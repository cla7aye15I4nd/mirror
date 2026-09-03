from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from malware_archive.config import Config, DiscoveryConfig, EcosystemConfig, HttpConfig, RegistryConfig
from malware_archive.database import Database
from malware_archive.pypi_discovery import PyPIDiscoverer


class PyPIHttp:
    def __init__(self) -> None:
        self.metadata_calls = 0

    def get_json(self, url: str, **_kwargs):
        self.metadata_calls += 1
        if self.metadata_calls == 1:
            return 200, url, {
                "releases": {
                    "1.0": [
                        {
                            "packagetype": "sdist",
                            "filename": "sample-1.0.tar.gz",
                            "url": "https://files.pythonhosted.org/sample-1.0.tar.gz",
                            "digests": {"sha256": "a" * 64},
                            "size": 123,
                        }
                    ]
                }
            }
        return 200, url, {"releases": {}}


class FakePyPIDiscoverer(PyPIDiscoverer):
    def _xmlrpc(self, method: str, *parameters: object) -> object:
        if method == "changelog_last_serial":
            return 100
        since = int(parameters[0])
        if since == 100:
            return [["sample", "1.0", 1000, "new release", 101]]
        return [["sample", "1.0", 1001, "remove release", 102]]


class PyPIDiscoveryTests(unittest.TestCase):
    def test_journal_snapshot_detects_removal_and_triggers_capture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            official = RegistryConfig(
                "pypi", "https://pypi.org", ("files.pythonhosted.org",)
            )
            config = Config(
                database=root / "state.sqlite3",
                archive_dir=root / "archive",
                absence_threshold=2,
                min_absence_interval_seconds=0,
                lease_seconds=60,
                http=HttpConfig(),
                ecosystems={"pypi": EcosystemConfig(official, ())},
                discovery=DiscoveryConfig(concurrency=1),
            )
            database = Database(config.database)
            database.initialize()
            captures = []
            discoverer = FakePyPIDiscoverer(
                config,
                database,
                PyPIHttp(),
                on_removed=lambda coordinate: not captures.append(coordinate),
            )
            self.assertTrue(discoverer.discover_once().initialized)
            self.assertEqual(discoverer.discover_once().removed_versions, 0)
            self.assertEqual(discoverer.discover_once().removed_versions, 1)
            self.assertEqual([(item.name, item.version) for item in captures], [("sample", "1.0")])
            self.assertEqual(database.fingerprint_rows()[0]["sha256"], "a" * 64)


if __name__ == "__main__":
    unittest.main()
