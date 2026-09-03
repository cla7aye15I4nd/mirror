from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from malware_archive.catalog_import import import_catalog
from malware_archive.config import Config, EcosystemConfig, HttpConfig, RegistryConfig
from malware_archive.database import Database
from malware_archive.models import Coordinate


class CatalogImportTests(unittest.TestCase):
    def test_import_marks_matching_trusted_sample_as_captured(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = Config(
                database=root / "state.sqlite3",
                archive_dir=root / "archive",
                absence_threshold=2,
                min_absence_interval_seconds=0,
                lease_seconds=60,
                http=HttpConfig(),
                ecosystems={
                    "npm": EcosystemConfig(
                        RegistryConfig("npmjs", "https://registry.test", ("registry.test",)), ()
                    )
                },
            )
            database = Database(config.database)
            database.initialize()
            payload = b"inert encrypted sample"
            digest = hashlib.sha256(payload).hexdigest()
            object_path = config.archive_dir / "objects" / "sha256" / digest[:2] / digest
            object_path.parent.mkdir(parents=True)
            object_path.write_bytes(payload)
            source_path = "samples/npm/malicious_intent/example/1.0.0/example.zip"
            source_url = f"https://raw.githubusercontent.com/DataDog/dataset/commit/{source_path}"
            database.enqueue_trusted_artifacts(
                "datadog-security-labs",
                [(source_path, Coordinate("npm", "example", "1.0.0"),
                  "https://github.com/DataDog/dataset/raw/commit/example.zip", "example.zip")],
            )
            catalog = root / "packages.jsonl"
            catalog.write_text(json.dumps({
                "ecosystem": "npm",
                "name": "example",
                "version": "1.0.0",
                "sha256": digest,
                "size": len(payload),
                "sourceUrl": source_url,
                "sourceFile": "example.zip",
                "evidenceRef": "datadog:npm/malicious_intent/example/1.0.0/example.zip",
            }) + "\n", encoding="utf-8")

            summary = import_catalog(config, database, catalog)

            self.assertEqual(summary.imported, 1)
            self.assertEqual(database.pending_trusted_artifacts("datadog-security-labs", 10), [])


if __name__ == "__main__":
    unittest.main()
