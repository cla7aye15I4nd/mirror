from __future__ import annotations

import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

from malware_archive.config import Config, CoverageConfig, EcosystemConfig, HttpConfig, RegistryConfig
from malware_archive.coverage import NpmCoverageScanner
from malware_archive.database import Database


class CoverageHttp:
    def get_json(self, url: str, **_kwargs):
        if "descending=true" in url:
            return 200, url, {"results": [{"id": "newest", "seq": 100}], "last_seq": 100}
        if "_changes" in url:
            return 200, url, {
                "results": [
                    {"id": "older", "seq": 91},
                    {"id": "newer", "seq": 99},
                ],
                "last_seq": 100,
            }
        published = datetime.fromtimestamp(time.time() - 60, timezone.utc).isoformat()
        name = "newer" if "newer" in url else "older"
        return 200, url, {
            "versions": {
                "1.0.0": {"dist": {"tarball": f"https://registry.test/{name}-1.0.0.tgz"}}
            },
            "time": {"1.0.0": published},
        }


class CoverageTests(unittest.TestCase):
    def test_history_is_seeded_and_scanned_newest_first(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = RegistryConfig("official", "https://registry.test", ("registry.test",))
            config = Config(
                database=root / "state.sqlite3", archive_dir=root / "archive",
                absence_threshold=2, min_absence_interval_seconds=0, lease_seconds=60,
                http=HttpConfig(), ecosystems={"npm": EcosystemConfig(registry, ())},
                coverage=CoverageConfig(sequence_span=20, seed_chunk_size=10, scan_batch_size=1, concurrency=1),
            )
            database = Database(config.database); database.initialize()
            scanner = NpmCoverageScanner(config, database, CoverageHttp())  # type: ignore[arg-type]
            scanner.seed_once()
            summary = scanner.seed_once()
            self.assertEqual(summary.seeded_changes, 2)
            self.assertEqual(database.pending_npm_coverage(1)[0]["name"], "newer")
            scanned = scanner.scan_once()
            self.assertEqual(scanned.recent_packages, 1)
            self.assertEqual(database.npm_coverage_counts()["scanned"], 1)


if __name__ == "__main__":
    unittest.main()
