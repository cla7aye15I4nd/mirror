from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from artifact_viewer.worker import materialize
from malware_archive.config import Config, EcosystemConfig, HttpConfig, RegistryConfig, WebConfig
from malware_archive.database import Database
from malware_archive.http import HttpClient, UnsafeUrl
from malware_archive.models import Coordinate
from malware_archive.web import create_server


class _RedirectResponse:
    status = 302
    headers = {"Location": "http://127.0.0.1/latest/meta-data"}

    def close(self) -> None:
        pass


class _CountingOpener:
    def __init__(self) -> None:
        self.calls = 0

    def open(self, request, timeout):  # noqa: ANN001
        self.calls += 1
        return _RedirectResponse()


class HttpPolicyTests(unittest.TestCase):
    def test_redirect_is_validated_before_second_request(self) -> None:
        opener = _CountingOpener()
        client = HttpClient(HttpConfig())
        with patch("urllib.request.build_opener", return_value=opener):
            with self.assertRaises(UnsafeUrl):
                client.open("https://registry.test/pkg", allowed_hosts=("registry.test",))
        self.assertEqual(opener.calls, 1)

    def test_private_literal_is_rejected(self) -> None:
        with self.assertRaises(UnsafeUrl):
            HttpClient.validate_url("https://127.0.0.1/x", ("127.0.0.1",))


class WebTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        registry = RegistryConfig("official", "https://registry.test", ("registry.test",))
        self.config = Config(
            database=root / "state.sqlite3",
            archive_dir=root / "archive",
            absence_threshold=2,
            min_absence_interval_seconds=0,
            lease_seconds=60,
            http=HttpConfig(),
            ecosystems={"npm": EcosystemConfig(registry, ())},
            view_dir=root / "views",
            web=WebConfig(host="127.0.0.1", port=0, require_access_headers=True),
        )
        self.database = Database(self.config.database)
        self.database.initialize()
        self.server = create_server(self.config, self.database)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def _request(self, path: str) -> urllib.response.addinfourl:
        request = urllib.request.Request(
            self.base + path,
            headers={
                "Cf-Access-Authenticated-User-Email": "operator@example.com",
                "Cf-Access-Jwt-Assertion": "test-assertion",
            },
        )
        return urllib.request.urlopen(request, timeout=2)

    def test_access_headers_are_required(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(self.base + "/api/status", timeout=2)
        self.assertEqual(raised.exception.code, 401)
        raised.exception.close()
        with self._request("/api/status") as response:
            self.assertEqual(json.load(response)["safety"]["execute"], False)
        with self._request("/archive") as response:
            page = response.read()
            self.assertIn(b"Ecosystem filter", page)
            self.assertIn(b"Malware classification filter", page)

    def test_artifact_is_forced_download_and_never_rendered_inline(self) -> None:
        body = b"opaque tgz bytes; never parse this"
        digest = hashlib.sha256(body).hexdigest()
        path = self.config.archive_dir / "objects" / "sha256" / digest[:2] / digest
        path.parent.mkdir(parents=True)
        path.write_bytes(body)
        coordinate = Coordinate("npm", "malicious-sample", "1.0.0")
        self.database.observe(coordinate)
        self.database.record_archive(
            coordinate,
            sha256=digest,
            source="mirror",
            source_url="https://mirror.test/sample.tgz",
            filename="sample.tgz",
            size=len(body),
            path=str(path),
            verified=False,
        )
        missing = Coordinate("npm", "known-but-unavailable", "9.9.9")
        self.database.observe(missing)
        self.database.record_malware_intelligence(missing, ["MAL-2026-9999"])
        with self._request("/api/archives") as response:
            listed = json.load(response)["packages"]
            self.assertEqual(len(listed), 1)
            self.assertEqual(listed[0]["archived_sha256"], digest)
        with self._request("/api/archives?include_unavailable=1") as response:
            catalog = json.load(response)["packages"]
            self.assertEqual(len(catalog), 2)
            unavailable = next(item for item in catalog if item["name"] == "known-but-unavailable")
            self.assertIsNone(unavailable["archived_sha256"])
            self.assertTrue(unavailable["malware"])
        with self._request("/api/archives?availability=unavailable") as response:
            unavailable_only = json.load(response)["packages"]
            self.assertEqual([item["name"] for item in unavailable_only], ["known-but-unavailable"])
            self.assertIsNone(unavailable_only[0]["archived_sha256"])
        with self._request("/api/archives?malware=suspicious") as response:
            suspicious_only = json.load(response)["packages"]
            self.assertEqual([item["name"] for item in suspicious_only], ["malicious-sample"])
        with self._request(f"/artifacts/{digest}/download") as response:
            self.assertEqual(response.headers["Content-Type"], "application/octet-stream")
            self.assertTrue(response.headers["Content-Disposition"].startswith("attachment;"))
            self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
            self.assertEqual(response.read(), body)

    def test_source_view_uses_manifest_allowlist_and_returns_text_as_json(self) -> None:
        archive = self.config.archive_dir / "sample.tgz"
        archive.parent.mkdir(parents=True, exist_ok=True)
        source = b"module.exports = 42;\n"
        with tarfile.open(archive, "w:gz") as bundle:
            member = tarfile.TarInfo("package/index.js")
            member.size = len(source)
            bundle.addfile(member, io.BytesIO(source))
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        object_path = self.config.archive_dir / "objects" / "sha256" / digest[:2] / digest
        object_path.parent.mkdir(parents=True)
        archive.replace(object_path)
        coordinate = Coordinate("npm", "malicious-sample", "2.0.0")
        self.database.observe(coordinate)
        self.database.record_archive(
            coordinate,
            sha256=digest,
            source="mirror",
            source_url="https://mirror.test/sample.tgz",
            filename="sample.tgz",
            size=object_path.stat().st_size,
            path=str(object_path),
            verified=False,
        )
        materialize(object_path, self.config.view_dir, digest)
        with self._request(f"/api/views/{digest}/tree") as response:
            manifest = json.load(response)
            self.assertEqual(manifest["files"][0]["path"], "package/index.js")
            self.assertEqual(response.headers["Cache-Control"], "private, max-age=3600, immutable")
        with self._request(f"/api/views/{digest}/file?path=package%2Findex.js") as response:
            body = json.load(response)
            self.assertEqual(body["content"], source.decode())
            self.assertEqual(response.headers["Content-Type"], "application/json; charset=utf-8")
            self.assertEqual(response.headers["Cache-Control"], "private, max-age=3600, immutable")
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self._request(f"/api/views/{digest}/file?path=..%2Fmanifest.json")
        self.assertEqual(raised.exception.code, 400)
        raised.exception.close()


if __name__ == "__main__":
    unittest.main()
