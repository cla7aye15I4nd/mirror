from __future__ import annotations

import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from malware_archive.config import Config, EcosystemConfig, HttpConfig, RegistryConfig, TrustedFeedsConfig
from malware_archive.database import Database
from malware_archive.http import HttpResponse
from malware_archive.intelligence import OpenSSFEnricher, OpenSSFFeedImporter
from malware_archive.models import Coordinate, ProbeResult, ProbeStatus
from malware_archive.trusted_feeds import DataDogFeedImporter


class FakeOSVHttp:
    def __init__(self) -> None:
        self.payload = None

    def open(self, _url: str, **kwargs) -> HttpResponse:
        self.payload = json.loads(kwargs["data"])
        body = json.dumps({"vulns": [{"id": "MAL-2026-123"}, {"id": "GHSA-not-malware"}]}).encode()
        return HttpResponse(200, "https://api.osv.dev/v1/query", {}, io.BytesIO(body))


class FakeFeedHttp:
    def open(self, _url: str, **_kwargs) -> HttpResponse:
        body = b"2026-09-03T01:00:00Z,MAL-2026-2\n2026-09-02T01:00:00Z,GHSA-ignore\n"
        return HttpResponse(200, "https://storage.googleapis.com/index.csv", {}, io.BytesIO(body))

    def get_json(self, url: str, **_kwargs):
        return 200, url, {
            "id": "MAL-2026-2",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "Bad-Package"},
                "versions": ["1.0.0", "1.0.1"],
            }],
        }


class FakeDataDogHttp:
    def __init__(self) -> None:
        self.config = HttpConfig()
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as bundle:
            bundle.writestr("package/index.js", "// static preview only\n")
        self.sample = payload.getvalue()

    def get_json(self, url: str, **_kwargs):
        if "/commits/" in url:
            return 200, url, {"files": [{
                "status": "added",
                "filename": "samples/npm/malicious_intent/@scope@bad/1.2.3/2026-09-03-bad.zip",
                "raw_url": "https://raw.githubusercontent.com/DataDog/dataset/sample.zip",
            }]}
        return 200, url, [{"sha": "a" * 40}]

    def open(self, url: str, **_kwargs) -> HttpResponse:
        return HttpResponse(200, url, {"Content-Length": str(len(self.sample))}, io.BytesIO(self.sample))


class IntelligenceTests(unittest.TestCase):
    def test_datadog_feed_preserves_secondary_sample_with_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = RegistryConfig("npmjs", "https://registry.test", ("registry.test",))
            config = Config(
                database=root / "state.sqlite3", archive_dir=root / "archive",
                absence_threshold=2, min_absence_interval_seconds=0, lease_seconds=60,
                http=HttpConfig(), ecosystems={"npm": EcosystemConfig(registry, ())},
                trusted_feeds=TrustedFeedsConfig(datadog_enabled=True),
            )
            database = Database(config.database); database.initialize()
            importer = DataDogFeedImporter(config, database, FakeDataDogHttp())  # type: ignore[arg-type]
            self.assertEqual(importer.sync().queued, 1)
            self.assertEqual(importer.recover().captured, 1)
            package = database.packages()[0]
            self.assertEqual((package["ecosystem"], package["name"], package["version"]), ("npm", "@scope/bad", "1.2.3"))
            self.assertTrue(package["malware"])
            archive = database.archive_rows()[0]
            self.assertEqual(archive["source"], "datadog-security-labs")
            self.assertFalse(archive["verified"])

    def test_official_mal_feed_backfills_exact_versions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = RegistryConfig("official", "https://registry.test", ("registry.test",))
            config = Config(
                database=root / "state.sqlite3", archive_dir=root / "archive",
                absence_threshold=2, min_absence_interval_seconds=0, lease_seconds=60,
                http=HttpConfig(), ecosystems={"npm": EcosystemConfig(registry, ())},
            )
            database = Database(config.database); database.initialize()
            captured = []
            importer = OpenSSFFeedImporter(
                config, database, capture=lambda item: not captured.append(item), http=FakeFeedHttp()
            )  # type: ignore[arg-type]
            self.assertEqual(importer.sync_index().indexed, 1)
            summary = importer.process_reports()
            self.assertEqual(summary.coordinates, 2)
            self.assertEqual({row["version"] for row in database.packages()}, {"1.0.0", "1.0.1"})
            self.assertTrue(all(row["malware"] for row in database.packages()))
            self.assertEqual(captured, [])
            recovery = importer.process_captures()
            self.assertEqual(recovery.captured, 2)
            self.assertEqual(len(captured), 2)

    def test_only_openssf_mal_ids_set_the_malware_classification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = RegistryConfig("official", "https://registry.test", ("registry.test",))
            config = Config(
                database=root / "state.sqlite3",
                archive_dir=root / "archive",
                absence_threshold=2,
                min_absence_interval_seconds=0,
                lease_seconds=60,
                http=HttpConfig(),
                ecosystems={"npm": EcosystemConfig(registry, ())},
            )
            database = Database(config.database)
            database.initialize()
            coordinate = Coordinate("npm", "sample", "1.0.0")
            database.observe(coordinate)
            database.record_archive(
                coordinate,
                sha256="1" * 64,
                source="mirror",
                source_url="https://mirror.test/sample.tgz",
                filename="sample.tgz",
                size=1,
                path=str(root / "archive/object"),
                verified=False,
            )
            http = FakeOSVHttp()
            enricher = OpenSSFEnricher(config, database, http)  # type: ignore[arg-type]
            self.assertEqual(enricher._query(coordinate), ["MAL-2026-123"])
            self.assertEqual(http.payload["package"], {"name": "sample", "ecosystem": "npm"})
            database.record_malware_intelligence(coordinate, ["MAL-2026-123"])
            row = database.packages()[0]
            self.assertEqual(row["malware"], 1)
            self.assertEqual(json.loads(row["malware_ids_json"]), ["MAL-2026-123"])

    def test_feed_maps_rubygems_and_crates_io_coordinates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ruby = RegistryConfig(
                "rubygems.org", "https://rubygems.org", ("rubygems.org",), "rubygems-api"
            )
            crates = RegistryConfig(
                "crates.io", "https://index.crates.io", ("static.crates.io",),
                "cargo-sparse", "global", "https://static.crates.io/crates/{name}/{filename}",
            )
            config = Config(
                database=root / "state.sqlite3", archive_dir=root / "archive",
                absence_threshold=2, min_absence_interval_seconds=0, lease_seconds=60,
                http=HttpConfig(), ecosystems={
                    "rubygems": EcosystemConfig(ruby, ()),
                    "crates.io": EcosystemConfig(crates, ()),
                },
            )
            database = Database(config.database); database.initialize()
            importer = OpenSSFFeedImporter(config, database, http=FakeFeedHttp())  # type: ignore[arg-type]
            coordinates = importer._coordinates({"affected": [
                {"package": {"ecosystem": "RubyGems", "name": "Bad_Gem"}, "versions": ["1.0.0"]},
                {"package": {"ecosystem": "crates.io", "name": "Bad_Crate"}, "versions": ["2.0.0"]},
            ]})
            self.assertEqual(coordinates, [
                Coordinate("rubygems", "bad_gem", "1.0.0"),
                Coordinate("crates.io", "bad_crate", "2.0.0"),
            ])

    def test_archived_package_is_checked_even_if_the_official_version_reappears(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = RegistryConfig("official", "https://registry.test", ("registry.test",))
            config = Config(
                database=root / "state.sqlite3", archive_dir=root / "archive",
                absence_threshold=2, min_absence_interval_seconds=0, lease_seconds=60,
                http=HttpConfig(), ecosystems={"npm": EcosystemConfig(registry, ())},
            )
            database = Database(config.database); database.initialize()
            coordinate = Coordinate("npm", "restored", "1.0.0")
            database.observe(coordinate)
            database.record_archive(
                coordinate, sha256="2" * 64, source="mirror",
                source_url="https://mirror.test/restored.tgz", filename="restored.tgz",
                size=1, path=str(root / "archive/object"), verified=False,
            )
            database.record_probe(coordinate, ProbeResult(ProbeStatus.AVAILABLE, "official"), 2, 0)
            self.assertEqual(database.intelligence_candidates(2**31, 10), [coordinate])


if __name__ == "__main__":
    unittest.main()
