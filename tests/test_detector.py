from __future__ import annotations

import hashlib
import io
import tempfile
import unittest
from pathlib import Path

from malware_archive.config import Config, EcosystemConfig, HttpConfig, RegistryConfig
from malware_archive.database import Database
from malware_archive.detector import Detector
from malware_archive.http import HttpResponse
from malware_archive.models import Artifact, Coordinate, PackageState, ProbeResult, ProbeStatus
from malware_archive.storage import ArchiveStore, ArtifactRejected


class FakeHttp:
    def __init__(self, body: bytes, final_url: str = "https://mirror.test/a.tgz"):
        self.config = HttpConfig(max_artifact_bytes=1024)
        self.body = body
        self.final_url = final_url

    def open(self, url: str, **_kwargs) -> HttpResponse:
        return HttpResponse(200, self.final_url, {"Content-Length": str(len(self.body))}, io.BytesIO(self.body))


class RegistryHttp(FakeHttp):
    def get_json(self, url: str, **_kwargs):
        if "official.test" in url:
            return 404, url, None
        return 200, url, {
            "versions": {
                "1.0.0": {
                    "dist": {
                        "tarball": "https://mirror.test/a.tgz",
                        "shasum": hashlib.sha1(self.body).hexdigest(),
                    }
                }
            }
        }


class DatabaseTests(unittest.TestCase):
    def test_archive_lookup_indexes_are_installed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "state.sqlite3")
            database.initialize()
            with database.connect() as connection:
                indexes = {row[1] for row in connection.execute("PRAGMA index_list(archives)")}
            self.assertIn("archives_sha256_idx", indexes)
            self.assertIn("archives_coordinate_time_idx", indexes)

    def test_absence_requires_spaced_confirmations_and_available_resets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "state.sqlite3")
            database.initialize()
            coordinate = Coordinate("npm", "pkg", "1.0.0")
            database.observe(coordinate, now=1)
            missing = ProbeResult(ProbeStatus.NOT_FOUND, "official")
            self.assertEqual(database.record_probe(coordinate, missing, 3, 60, now=100), PackageState.WATCHING)
            self.assertEqual(database.record_probe(coordinate, missing, 3, 60, now=120), PackageState.WATCHING)
            self.assertEqual(database.record_probe(coordinate, missing, 3, 60, now=160), PackageState.WATCHING)
            self.assertEqual(
                database.record_probe(coordinate, ProbeResult(ProbeStatus.UNKNOWN, "official"), 3, 60, now=220),
                PackageState.WATCHING,
            )
            self.assertEqual(database.record_probe(coordinate, missing, 3, 60, now=220), PackageState.SUSPECTED_TAKEDOWN)
            available = ProbeResult(ProbeStatus.AVAILABLE, "official")
            self.assertEqual(database.record_probe(coordinate, available, 3, 60, now=300), PackageState.WATCHING)
            row = database.packages()[0]
            self.assertEqual(row["absence_count"], 0)

    def test_detector_checks_official_then_archives_from_mirror(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            official = RegistryConfig("official", "https://official.test", ("official.test",))
            mirror = RegistryConfig("mirror", "https://mirror.test", ("mirror.test",))
            config = Config(
                database=root / "state.sqlite3",
                archive_dir=root / "archive",
                absence_threshold=2,
                min_absence_interval_seconds=0,
                lease_seconds=60,
                http=HttpConfig(max_artifact_bytes=1024),
                ecosystems={"npm": EcosystemConfig(official, (mirror,))},
            )
            database = Database(config.database)
            database.initialize()
            database.observe(Coordinate("npm", "a", "1.0.0"))
            detector = Detector(config, database, RegistryHttp(b"raw tgz bytes"))
            self.assertEqual(detector.scan().archived, 0)
            first = database.packages()[0]
            self.assertEqual(first["state"], PackageState.CAPTURED_PENDING_CONFIRMATION)
            self.assertIsNotNone(first["archived_sha256"])
            self.assertEqual(detector.scan().archived, 1)
            row = database.packages()[0]
            self.assertEqual(row["state"], PackageState.ARCHIVED_UNVERIFIED)
            digest = row["archived_sha256"]
            self.assertTrue((config.archive_dir / "objects" / "sha256" / digest[:2] / digest).exists())


class ArchiveStoreTests(unittest.TestCase):
    def test_download_is_raw_hash_verified_and_content_addressed(self) -> None:
        body = b"not really a tarball; it must never be parsed"
        digest = hashlib.sha256(body).hexdigest()
        registry = RegistryConfig("mirror", "https://mirror.test", ("mirror.test",))
        artifact = Artifact("https://mirror.test/a.tgz", "a.tgz", "mirror", sha256=digest, size=len(body))
        with tempfile.TemporaryDirectory() as directory:
            store = ArchiveStore(Path(directory), FakeHttp(body))
            result = store.download(Coordinate("npm", "a", "1.0.0"), artifact, registry)
            self.assertEqual(result.sha256, digest)
            self.assertEqual(result.path.read_bytes(), body)
            self.assertTrue(result.path.with_suffix(".json").exists())

    def test_redirect_to_non_allowlisted_host_is_rejected(self) -> None:
        registry = RegistryConfig("mirror", "https://mirror.test", ("mirror.test",))
        artifact = Artifact("https://mirror.test/a.tgz", "a.tgz", "mirror")
        with tempfile.TemporaryDirectory() as directory:
            store = ArchiveStore(Path(directory), FakeHttp(b"x", "https://evil.test/a.tgz"))
            with self.assertRaises(ArtifactRejected):
                store.download(Coordinate("npm", "a", "1"), artifact, registry)

    def test_cached_official_hash_rejects_mirror_substitution(self) -> None:
        registry = RegistryConfig("mirror", "https://mirror.test", ("mirror.test",))
        artifact = Artifact(
            "https://mirror.test/a.tgz",
            "a.tgz",
            "mirror",
            sha512=hashlib.sha512(b"expected").hexdigest(),
        )
        with tempfile.TemporaryDirectory() as directory:
            store = ArchiveStore(Path(directory), FakeHttp(b"substituted"))
            with self.assertRaisesRegex(ArtifactRejected, "SHA-512 mismatch"):
                store.download(Coordinate("npm", "a", "1"), artifact, registry)


if __name__ == "__main__":
    unittest.main()
