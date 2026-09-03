from __future__ import annotations

import io
import json
import unittest

from malware_archive.config import HttpConfig, RegistryConfig
from malware_archive.ecosystems import (
    CratesIOHook, GoModulesHook, MavenHook, NpmHook, NuGetHook, PyPIHook, RubyGemsHook,
)
from malware_archive.http import HttpResponse
from malware_archive.models import Coordinate, ProbeStatus


class MetadataHttp:
    def __init__(self, status: int, body: object):
        self.status = status
        self.body = body

    def get_json(self, url: str, **_kwargs):
        return self.status, url, self.body


class SimpleHttp:
    config = HttpConfig()

    def __init__(self, body: bytes):
        self.body = body

    def open(self, url: str, **_kwargs):
        return HttpResponse(200, url, {"Content-Length": str(len(self.body))}, io.BytesIO(self.body))


class MavenHttp:
    config = HttpConfig()

    def open(self, url: str, **_kwargs):
        body = b"a" * 40 if url.endswith(".sha1") else b"<project/>"
        return HttpResponse(200, url, {"Content-Length": str(len(body))}, io.BytesIO(body))


class HookTests(unittest.TestCase):
    def test_npm_exact_version_and_tarball(self) -> None:
        body = {"versions": {"1.2.3": {"dist": {"tarball": "https://r.test/a.tgz", "shasum": "ab"}}}}
        hook = NpmHook(RegistryConfig("r", "https://r.test", ("r.test",)), MetadataHttp(200, body))
        coordinate = Coordinate("npm", "A", "1.2.3")
        self.assertEqual(hook.probe(coordinate).status, ProbeStatus.AVAILABLE)
        self.assertEqual(hook.artifacts(coordinate)[0].filename, "a.tgz")

    def test_pypi_only_returns_sdist(self) -> None:
        body = {
            "urls": [
                {"packagetype": "bdist_wheel", "url": "https://f.test/a.whl", "filename": "a.whl"},
                {"packagetype": "sdist", "url": "https://f.test/a.tar.gz", "filename": "a.tar.gz", "digests": {}},
            ]
        }
        hook = PyPIHook(RegistryConfig("p", "https://p.test", ("f.test",)), MetadataHttp(200, body))
        artifacts = hook.artifacts(Coordinate("pypi", "A_B", "1.0"))
        self.assertEqual([artifact.filename for artifact in artifacts], ["a.tar.gz"])

    def test_pypi_simple_mirror_returns_exact_sdist_without_downloading_it(self) -> None:
        digest = "a" * 64
        page = (
            f'<a href="../../packages/a_b-1.0.tar.gz#sha256={digest}">a_b-1.0.tar.gz</a>'
            '<a href="../../packages/a_b-1.0-py3-none-any.whl">wheel</a>'
            '<a href="../../packages/a_b-2.0.tar.gz">other version</a>'
        ).encode()
        registry = RegistryConfig(
            "simple", "https://p.test/simple", ("p.test",), "pypi-simple", "test"
        )
        artifacts = PyPIHook(registry, SimpleHttp(page)).artifacts(Coordinate("pypi", "A_B", "1.0"))
        self.assertEqual([artifact.filename for artifact in artifacts], ["a_b-1.0.tar.gz"])
        self.assertEqual(artifacts[0].sha256, digest)

    def test_rubygems_uses_exact_version_sha_and_never_loads_the_gem(self) -> None:
        digest = "b" * 64
        body = [
            {"number": "1.0.0", "platform": "ruby", "sha": digest},
            {"number": "1.0.0", "platform": "java", "sha": "c" * 64},
            {"number": "2.0.0", "platform": "ruby", "sha": "d" * 64},
        ]
        registry = RegistryConfig(
            "rubygems.org", "https://rubygems.org", ("rubygems.org",), "rubygems-api"
        )
        hook = RubyGemsHook(registry, MetadataHttp(200, body))
        coordinate = Coordinate("rubygems", "Example_Gem", "1.0.0")
        self.assertEqual(hook.probe(coordinate).status, ProbeStatus.AVAILABLE)
        artifacts = hook.artifacts(coordinate)
        self.assertEqual([item.filename for item in artifacts], [
            "example_gem-1.0.0.gem", "example_gem-1.0.0-java.gem"
        ])
        self.assertEqual(artifacts[0].sha256, digest)

    def test_rubygems_artifact_only_mirror_builds_raw_gem_url(self) -> None:
        registry = RegistryConfig(
            "mirror", "https://mirror.test", ("mirror.test",), "artifact-template", "test",
            "https://mirror.test/gems/{filename}",
        )
        artifact = RubyGemsHook(registry, MetadataHttp(200, [])).artifacts(
            Coordinate("rubygems", "Example", "1.2.3")
        )[0]
        self.assertEqual(artifact.url, "https://mirror.test/gems/example-1.2.3.gem")

    def test_crates_io_reads_sparse_index_and_builds_raw_crate_url(self) -> None:
        digest = "e" * 64
        lines = b"\n".join([
            json.dumps({"name": "serde", "vers": "1.0.0", "cksum": "f" * 64, "yanked": False}).encode(),
            json.dumps({"name": "serde", "vers": "1.0.1", "cksum": digest, "yanked": False}).encode(),
        ])
        registry = RegistryConfig(
            "crates.io", "https://index.crates.io", ("static.crates.io",),
            "cargo-sparse", "global", "https://static.crates.io/crates/{name}/{filename}",
        )
        hook = CratesIOHook(registry, SimpleHttp(lines))
        coordinate = Coordinate("crates.io", "Serde", "1.0.1")
        self.assertEqual(hook.probe(coordinate).status, ProbeStatus.AVAILABLE)
        artifact = hook.artifacts(coordinate)[0]
        self.assertEqual(artifact.filename, "serde-1.0.1.crate")
        self.assertEqual(artifact.url, "https://static.crates.io/crates/serde/serde-1.0.1.crate")
        self.assertEqual(artifact.sha256, digest)

    def test_go_proxy_returns_source_zip_without_running_go(self) -> None:
        registry = RegistryConfig(
            "go", "https://proxy.golang.org", ("proxy.golang.org",), "go-proxy"
        )
        hook = GoModulesHook(registry, MetadataHttp(200, {"Version": "v1.2.3"}))
        coordinate = Coordinate("go", "github.com/Example/Module", "v1.2.3")
        self.assertEqual(hook.probe(coordinate).status, ProbeStatus.AVAILABLE)
        artifact = hook.artifacts(coordinate)[0]
        self.assertIn("github.com/!example/!module/@v/v1.2.3.zip", artifact.url)

    def test_maven_builds_repository_layout_and_reads_checksum_sidecar(self) -> None:
        registry = RegistryConfig(
            "central", "https://repo.maven.apache.org/maven2", ("repo.maven.apache.org",),
            "maven-repository",
        )
        hook = MavenHook(registry, MavenHttp())
        coordinate = Coordinate("maven", "com.example:sample", "1.0.0")
        self.assertEqual(hook.probe(coordinate).status, ProbeStatus.AVAILABLE)
        artifact = hook.artifacts(coordinate)[0]
        self.assertEqual(
            artifact.url,
            "https://repo.maven.apache.org/maven2/com/example/sample/1.0.0/sample-1.0.0.jar",
        )
        self.assertEqual(artifact.sha1, "a" * 40)

    def test_nuget_flat_container_returns_raw_nupkg(self) -> None:
        registry = RegistryConfig(
            "nuget", "https://api.nuget.org/v3-flatcontainer", ("api.nuget.org",), "nuget-flat"
        )
        hook = NuGetHook(registry, MetadataHttp(200, {"versions": ["1.2.3"]}))
        coordinate = Coordinate("nuget", "Example.Package", "1.2.3+build")
        self.assertEqual(hook.probe(coordinate).status, ProbeStatus.AVAILABLE)
        artifact = hook.artifacts(coordinate)[0]
        self.assertEqual(
            artifact.url,
            "https://api.nuget.org/v3-flatcontainer/example.package/1.2.3/example.package.1.2.3.nupkg",
        )


if __name__ == "__main__":
    unittest.main()
