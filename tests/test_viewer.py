from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from artifact_viewer.worker import materialize


class ViewerMaterializerTests(unittest.TestCase):
    def test_tar_materialization_allows_regular_files_and_rejects_unsafe_members(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "sample.tgz"
            with tarfile.open(archive, "w:gz") as bundle:
                source = b"console.log('static only');\n"
                regular = tarfile.TarInfo("package/index.js")
                regular.size = len(source)
                bundle.addfile(regular, io.BytesIO(source))
                traversal = tarfile.TarInfo("../../escape.js")
                traversal.size = 4
                bundle.addfile(traversal, io.BytesIO(b"evil"))
                link = tarfile.TarInfo("package/link")
                link.type = tarfile.SYMTYPE
                link.linkname = "/etc/passwd"
                bundle.addfile(link)
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            manifest_path = materialize(archive, root / "views", digest)
            manifest = json.loads(manifest_path.read_text())
            self.assertEqual(manifest["status"], "ready", manifest.get("error"))
            self.assertEqual(manifest["files"], [{"path": "package/index.js", "size": len(source)}])
            self.assertEqual((manifest_path.parent / "files/package/index.js").read_bytes(), source)
            self.assertFalse((root / "escape.js").exists())
            self.assertGreaterEqual(len(manifest["skipped"]), 2)

    def test_zip_traversal_is_not_written(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "sample.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("src/main.py", "answer = 42\n")
                bundle.writestr("../outside.py", "bad = True\n")
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            manifest = json.loads(materialize(archive, root / "views", digest).read_text())
            self.assertEqual(manifest["status"], "ready", manifest.get("error"))
            self.assertEqual(manifest["archive_format"], "zip")
            self.assertEqual([item["path"] for item in manifest["files"]], ["src/main.py"])
            self.assertFalse((root / "views" / digest / "outside.py").exists())

    def test_rubygem_materialization_opens_the_nested_source_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "sample.gem"
            payload = io.BytesIO()
            source = b"module SafePreview\nend\n"
            with tarfile.open(fileobj=payload, mode="w:gz") as inner:
                member = tarfile.TarInfo("lib/safe_preview.rb")
                member.size = len(source)
                inner.addfile(member, io.BytesIO(source))
            compressed = payload.getvalue()
            with tarfile.open(archive, "w") as outer:
                member = tarfile.TarInfo("data.tar.gz")
                member.size = len(compressed)
                outer.addfile(member, io.BytesIO(compressed))
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            manifest_path = materialize(archive, root / "views", digest)
            manifest = json.loads(manifest_path.read_text())
            self.assertEqual(manifest["archive_format"], "rubygem")
            self.assertEqual([item["path"] for item in manifest["files"]], ["lib/safe_preview.rb"])
            self.assertEqual(
                (manifest_path.parent / "files/lib/safe_preview.rb").read_bytes(), source
            )

    def test_digest_mismatch_rejects_the_entire_preview(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "sample.tgz"
            with tarfile.open(archive, "w:gz") as bundle:
                data = b"hello"
                member = tarfile.TarInfo("package/readme.txt")
                member.size = len(data)
                bundle.addfile(member, io.BytesIO(data))
            expected = "0" * 64
            manifest = json.loads(materialize(archive, root / "views", expected).read_text())
            self.assertEqual(manifest["status"], "rejected")
            self.assertFalse((root / "views" / expected / "files").exists())


if __name__ == "__main__":
    unittest.main()
