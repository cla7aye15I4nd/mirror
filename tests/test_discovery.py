from __future__ import annotations

import base64
import hashlib
import tempfile
import unittest
from pathlib import Path

from malware_archive.config import Config, DiscoveryConfig, EcosystemConfig, HttpConfig, RegistryConfig
from malware_archive.database import Database
from malware_archive.discovery import NpmDiscoverer
from malware_archive.models import PackageState


class DiscoveryHttp:
    def __init__(self) -> None:
        self.feed_call = 0
        self.metadata_call = 0

    def get_json(self, url: str, **_kwargs):
        if "_changes" in url:
            self.feed_call += 1
            if self.feed_call == 1:
                return 200, url, {"results": [{"id": "seed"}], "last_seq": 100}
            return 200, url, {"results": [{"id": "sample"}], "last_seq": 100 + self.feed_call}
        self.metadata_call += 1
        if self.metadata_call == 1:
            digest = base64.b64encode(hashlib.sha512(b"original").digest()).decode()
            return 200, url, {
                "versions": {
                    "1.0.0": {
                        "dist": {
                            "tarball": "https://registry.npmjs.org/sample/-/sample-1.0.0.tgz",
                            "integrity": f"sha512-{digest}",
                        }
                    }
                }
            }
        return 200, url, {"versions": {}}


class DiscoveryTests(unittest.TestCase):
    def test_incremental_feed_detects_removed_version_and_keeps_strong_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            official = RegistryConfig("npmjs", "https://registry.npmjs.org", ("registry.npmjs.org",))
            config = Config(
                database=root / "state.sqlite3",
                archive_dir=root / "archive",
                absence_threshold=2,
                min_absence_interval_seconds=0,
                lease_seconds=60,
                http=HttpConfig(),
                ecosystems={"npm": EcosystemConfig(official, ())},
                discovery=DiscoveryConfig(concurrency=1),
            )
            database = Database(config.database)
            database.initialize()
            captures = []
            discoverer = NpmDiscoverer(
                config, database, DiscoveryHttp(), on_removed=lambda coordinate: not captures.append(coordinate)
            )
            self.assertTrue(discoverer.discover_once().initialized)
            self.assertEqual(discoverer.discover_once().removed_versions, 0)
            self.assertEqual(discoverer.discover_once().removed_versions, 1)
            package = database.packages()[0]
            self.assertEqual(package["state"], PackageState.WATCHING)
            self.assertIsNotNone(database.fingerprint_rows()[0]["sha512"])
            self.assertEqual([(item.name, item.version) for item in captures], [("sample", "1.0.0")])


if __name__ == "__main__":
    unittest.main()
