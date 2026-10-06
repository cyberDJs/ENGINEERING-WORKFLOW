"""Race-aware, cross-platform filesystem primitives for EW CLI."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

MAX_CONTROL_FILE_BYTES = 16 * 1024 * 1024


class SafeFileError(RuntimeError):
    """A path could not be read without crossing a filesystem trust boundary."""


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stat_signature(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def same_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        stat.S_IFMT(first.st_mode) == stat.S_IFMT(second.st_mode)
        and int(first.st_dev) == int(second.st_dev)
        and int(first.st_ino) == int(second.st_ino)
    )


def read_stable_file(
    path: Path,
    *,
    expected: os.stat_result | None = None,
    max_bytes: int = MAX_CONTROL_FILE_BYTES,
) -> tuple[bytes, os.stat_result]:
    before = expected if expected is not None else path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise SafeFileError(f"unsafe non-regular file: {path}")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise SafeFileError(f"file changed before safe open: {path}")
        if os.name != "nt" and not same_identity(before, opened):
            raise SafeFileError(f"file changed before safe open: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise SafeFileError(f"file exceeds safe read limit {max_bytes}: {path}")
            chunks.append(chunk)
        after_descriptor = os.fstat(descriptor)
    except OSError as exc:
        raise SafeFileError(f"safe no-follow read failed for {path}: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)

    try:
        after_path = path.lstat()
    except OSError as exc:
        raise SafeFileError(f"file disappeared after read: {path}: {exc}") from exc
    if os.name == "nt":
        # Python 3.12 made Windows path stat identifiers more accurate (up to
        # 128-bit file indexes). Path and descriptor stat domains are not a
        # stable cross-domain equality contract, so verify each domain across
        # time: path before/after and descriptor open/after-read.
        stable = (
            same_identity(before, after_path)
            and same_identity(opened, after_descriptor)
            and stat_signature(before) == stat_signature(after_path)
            and stat_signature(opened) == stat_signature(after_descriptor)
        )
    else:
        stable = (
            same_identity(before, opened)
            and same_identity(opened, after_descriptor)
            and same_identity(after_descriptor, after_path)
            and stat_signature(before) == stat_signature(opened)
            and stat_signature(opened) == stat_signature(after_descriptor)
            and stat_signature(after_descriptor) == stat_signature(after_path)
        )
    if not stable:
        raise SafeFileError(f"file changed during verified read: {path}")
    return b"".join(chunks), opened


def sha_file(
    path: Path,
    *,
    expected: os.stat_result | None = None,
    max_bytes: int = MAX_CONTROL_FILE_BYTES,
) -> tuple[str, os.stat_result]:
    content, metadata = read_stable_file(path, expected=expected, max_bytes=max_bytes)
    return sha(content), metadata


def read_json_regular(path: Path) -> dict[str, object]:
    content, _ = read_stable_file(path)
    value = json.loads(content.decode("utf-8"))
    if not isinstance(value, dict):
        raise SafeFileError(f"JSON document must be an object: {path}")
    return value


def symlink_record(path: Path, relative: str) -> dict[str, str]:
    before = path.lstat()
    if not stat.S_ISLNK(before.st_mode):
        raise SafeFileError(f"path stopped being a symlink during audit: {relative}")
    try:
        target = os.readlink(path)
        after = path.lstat()
    except OSError as exc:
        raise SafeFileError(f"could not inspect symlink safely: {relative}: {exc}") from exc
    if stat_signature(before) != stat_signature(after):
        raise SafeFileError(f"symlink changed during audit: {relative}")
    return {"path": relative, "target_sha256": sha(os.fsencode(target))}
