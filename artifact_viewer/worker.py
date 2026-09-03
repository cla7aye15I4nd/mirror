from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import stat
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path, PurePosixPath


MAX_FILES = 10_000
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_PATH_BYTES = 512
MAX_COMPRESSION_RATIO = 200
TRUSTED_SAMPLE_PASSWORD = b"infected"


def _safe_parts(name: str) -> tuple[str, ...] | None:
    if not name or "\x00" in name or "\\" in name or len(name.encode("utf-8")) > MAX_PATH_BYTES:
        return None
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return None
    return tuple(path.parts)


def _destination(root: Path, name: str) -> Path | None:
    parts = _safe_parts(name)
    if parts is None:
        return None
    destination = root.joinpath(*parts)
    if not destination.is_relative_to(root):
        return None
    return destination


def _write_stream(source, destination: Path, expected: int, remaining: int) -> int:
    if expected < 0 or expected > MAX_FILE_BYTES or expected > remaining:
        raise ValueError("file exceeds preview limits")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    written = 0
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    try:
        with os.fdopen(fd, "wb") as output:
            while written < expected:
                block = source.read(min(64 * 1024, expected - written))
                if not block:
                    break
                written += len(block)
                if written > expected or written > remaining:
                    raise ValueError("archive member exceeded declared size")
                output.write(block)
            if written != expected:
                raise ValueError("archive member ended before declared size")
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return written


def _extract_tar_bundle(
    bundle: tarfile.TarFile, root: Path
) -> tuple[list[dict[str, object]], list[dict[str, str]]]:
    files: list[dict[str, object]] = []
    skipped: list[dict[str, str]] = []
    total = 0
    members_seen = 0
    for member in bundle:
        members_seen += 1
        if members_seen > MAX_FILES:
            skipped.append({"path": "*", "reason": "member count limit reached"})
            break
        destination = _destination(root, member.name)
        if destination is None:
            skipped.append({"path": member.name[:200], "reason": "unsafe path"})
            continue
        if member.isdir():
            destination.mkdir(parents=True, exist_ok=True, mode=0o750)
            continue
        if not member.isfile():
            skipped.append({"path": member.name[:200], "reason": "links and special files are forbidden"})
            continue
        if member.size > MAX_FILE_BYTES or total + member.size > MAX_TOTAL_BYTES:
            skipped.append({"path": member.name[:200], "reason": "preview size limit"})
            continue
        source = bundle.extractfile(member)
        if source is None:
            skipped.append({"path": member.name[:200], "reason": "member has no readable stream"})
            continue
        with source:
            total += _write_stream(source, destination, member.size, MAX_TOTAL_BYTES - total)
        files.append({"path": member.name, "size": member.size})
    return files, skipped


def _extract_tar(
    archive: Path, root: Path
) -> tuple[list[dict[str, object]], list[dict[str, str]], str]:
    with tarfile.open(archive, mode="r:*") as bundle:
        try:
            payload = bundle.getmember("data.tar.gz")
        except KeyError:
            payload = None
        if payload is not None:
            if not payload.isfile() or payload.size > MAX_TOTAL_BYTES:
                raise ValueError("RubyGems data payload is not a bounded regular file")
            source = bundle.extractfile(payload)
            if source is None:
                raise ValueError("RubyGems data payload is unreadable")
            with source, tarfile.open(fileobj=source, mode="r|gz") as inner:
                files, skipped = _extract_tar_bundle(inner, root)
            return files, skipped, "rubygem"
        files, skipped = _extract_tar_bundle(bundle, root)
        return files, skipped, "tar"


def _extract_zip(archive: Path, root: Path) -> tuple[list[dict[str, object]], list[dict[str, str]], bool]:
    files: list[dict[str, object]] = []
    skipped: list[dict[str, str]] = []
    total = 0
    encrypted = False
    with zipfile.ZipFile(archive) as bundle:
        for index, member in enumerate(bundle.infolist(), start=1):
            if index > MAX_FILES:
                skipped.append({"path": "*", "reason": "member count limit reached"})
                break
            destination = _destination(root, member.filename)
            if destination is None:
                skipped.append({"path": member.filename[:200], "reason": "unsafe path"})
                continue
            mode = member.external_attr >> 16
            if member.is_dir():
                destination.mkdir(parents=True, exist_ok=True, mode=0o750)
                continue
            if stat.S_ISLNK(mode):
                skipped.append({"path": member.filename[:200], "reason": "links are forbidden"})
                continue
            encrypted = encrypted or bool(member.flag_bits & 0x1)
            ratio = member.file_size / max(1, member.compress_size)
            if ratio > MAX_COMPRESSION_RATIO:
                skipped.append({"path": member.filename[:200], "reason": "compression ratio limit"})
                continue
            if member.file_size > MAX_FILE_BYTES or total + member.file_size > MAX_TOTAL_BYTES:
                skipped.append({"path": member.filename[:200], "reason": "preview size limit"})
                continue
            try:
                with bundle.open(
                    member, "r", pwd=TRUSTED_SAMPLE_PASSWORD if member.flag_bits & 0x1 else None
                ) as source:
                    total += _write_stream(source, destination, member.file_size, MAX_TOTAL_BYTES - total)
            except RuntimeError:
                skipped.append({"path": member.filename[:200], "reason": "encrypted member did not use the trusted dataset password"})
                continue
            files.append({"path": member.filename, "size": member.file_size})
    return files, skipped, encrypted


def _verify_digest(archive: Path, expected: str) -> None:
    digest = hashlib.sha256()
    with archive.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    if digest.hexdigest() != expected:
        raise ValueError("content-addressed artifact digest mismatch")


def _seal_directories(root: Path) -> None:
    directories = sorted((path for path in root.rglob("*") if path.is_dir()), reverse=True)
    for directory in directories:
        os.chmod(directory, 0o550)
    os.chmod(root, 0o550)


def materialize(archive: Path, output_root: Path, digest: str) -> Path:
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError("invalid SHA-256 digest")
    destination = output_root / digest
    manifest_path = destination / "manifest.json"
    if manifest_path.is_file():
        return manifest_path
    output_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    temp = Path(tempfile.mkdtemp(prefix=f".{digest[:12]}-", dir=output_root))
    try:
        _verify_digest(archive, digest)
        content = temp / "files"
        content.mkdir(mode=0o750)
        if zipfile.is_zipfile(archive):
            files, skipped, encrypted = _extract_zip(archive, content)
            archive_format = "zip-encrypted" if encrypted else "zip"
        else:
            files, skipped, archive_format = _extract_tar(archive, content)
        manifest = {
            "schema": 1,
            "sha256": digest,
            "status": "ready",
            "archive_format": archive_format,
            "created_at": int(time.time()),
            "files": sorted(files, key=lambda item: str(item["path"])),
            "skipped": skipped[:500],
            "limits": {
                "files": MAX_FILES,
                "file_bytes": MAX_FILE_BYTES,
                "total_bytes": MAX_TOTAL_BYTES,
            },
        }
        (temp / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        os.chmod(temp / "manifest.json", 0o440)
        try:
            os.replace(temp, destination)
        except OSError:
            if not manifest_path.is_file():
                raise
            shutil.rmtree(temp)
        _seal_directories(destination)
        return manifest_path
    except Exception as exc:
        shutil.rmtree(temp, ignore_errors=True)
        destination.mkdir(parents=True, exist_ok=True, mode=0o750)
        manifest = {
            "schema": 1,
            "sha256": digest,
            "status": "rejected",
            "error": f"{type(exc).__name__}: {exc}",
            "created_at": int(time.time()),
            "files": [],
            "skipped": [],
        }
        manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        os.chmod(manifest_path, 0o440)
        os.chmod(destination, 0o550)
        return manifest_path


def _objects(archive_root: Path, request_root: Path) -> list[tuple[str, Path]]:
    objects: list[tuple[str, Path]] = []
    root = archive_root / "objects" / "sha256"
    if not root.is_dir() or not request_root.is_dir():
        return objects
    for request in request_root.iterdir():
        digest = request.name
        if (
            request.is_symlink()
            or not request.is_file()
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            continue
        candidate = root / digest[:2] / digest
        if not candidate.is_symlink() and candidate.is_file():
            objects.append((digest, candidate))
    return objects


def run(archive_root: Path, output_root: Path, request_root: Path, poll_seconds: int) -> None:
    stopping = False

    def stop(_signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopping:
        for digest, archive in _objects(archive_root, request_root):
            if stopping:
                break
            manifest = output_root / digest / "manifest.json"
            if manifest.is_file():
                continue
            materialize(archive, output_root, digest)
        deadline = time.monotonic() + poll_seconds
        while not stopping and time.monotonic() < deadline:
            time.sleep(min(1.0, deadline - time.monotonic()))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Materialize inert source previews without network access")
    parser.add_argument("--archive-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--request-root", type=Path, required=True)
    parser.add_argument("--poll-seconds", type=int, default=5)
    args = parser.parse_args(argv)
    run(args.archive_root, args.output, args.request_root, max(1, args.poll_seconds))
    return 0
