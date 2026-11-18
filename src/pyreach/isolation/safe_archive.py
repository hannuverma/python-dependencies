"""Safe archive unpacker protecting against zip-slip path traversal, symlink escapes, and archive bombs."""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path


class SafeArchiveError(Exception):
    """Raised when an archive violates safety constraints (traversal, symlink escape, bomb)."""


DEFAULT_MAX_TOTAL_SIZE = 100 * 1024 * 1024  # 100 MB
DEFAULT_MAX_FILES = 10_000
DEFAULT_MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB


def _check_path_safety(target_dir: Path, rel_path: str) -> Path:
    """Ensure the relative path does not escape target_dir via traversal or absolute paths."""
    # Reject leading slashes or Windows drive letters
    if rel_path.startswith(("/", "\\")) or (len(rel_path) > 1 and rel_path[1] == ":"):
        raise SafeArchiveError(f"Security violation: Absolute path in archive: '{rel_path}'")

    dest = (target_dir / rel_path).resolve()
    resolved_target = target_dir.resolve()

    try:
        if not dest.is_relative_to(resolved_target):
            raise SafeArchiveError(
                f"Security violation: Zip-slip path traversal detected: '{rel_path}' escapes target directory"
            )
    except AttributeError:
        # Fallback for Python versions where is_relative_to might behave differently
        if not str(dest).startswith(str(resolved_target)):
            raise SafeArchiveError(f"Security violation: Path traversal detected: '{rel_path}'")

    return dest


def extract_zip_safely(
    zip_path: Path,
    target_dir: Path,
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
    max_files: int = DEFAULT_MAX_FILES,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
) -> Path:
    """Extract a .whl or .zip archive with path traversal and bomb protection."""
    target_dir.mkdir(parents=True, exist_ok=True)
    total_size = 0
    file_count = 0

    with zipfile.ZipFile(zip_path, "r") as zf:
        infolist = zf.infolist()
        if len(infolist) > max_files:
            raise SafeArchiveError(
                f"Archive bomb protection: File count {len(infolist)} exceeds maximum limit of {max_files}"
            )

        for info in infolist:
            file_count += 1
            if file_count > max_files:
                raise SafeArchiveError("Archive bomb protection: Too many files in archive")

            dest_path = _check_path_safety(target_dir, info.filename)

            if info.is_dir():
                dest_path.mkdir(parents=True, exist_ok=True)
                continue

            if info.file_size > max_file_size:
                raise SafeArchiveError(
                    f"Archive bomb protection: Single file '{info.filename}' size {info.file_size} exceeds limit {max_file_size}"
                )

            total_size += info.file_size
            if total_size > max_total_size:
                raise SafeArchiveError(
                    f"Archive bomb protection: Total uncompressed size {total_size} exceeds limit {max_total_size}"
                )

            # Ensure parent directories exist
            dest_path.parent.mkdir(parents=True, exist_ok=True)

            # Write file safely
            with zf.open(info, "r") as src, open(dest_path, "wb") as dst:
                bytes_written = 0
                while chunk := src.read(64 * 1024):
                    bytes_written += len(chunk)
                    if bytes_written > max_file_size:
                        raise SafeArchiveError("Archive bomb: File decompressed beyond declared size")
                    dst.write(chunk)

    return target_dir


def extract_tar_safely(
    tar_path: Path,
    target_dir: Path,
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
    max_files: int = DEFAULT_MAX_FILES,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
) -> Path:
    """Extract a tar sdist archive with path traversal, symlink, and bomb protection."""
    target_dir.mkdir(parents=True, exist_ok=True)
    total_size = 0
    file_count = 0

    with tarfile.open(tar_path, "r:*") as tf:
        members = tf.getmembers()
        if len(members) > max_files:
            raise SafeArchiveError(
                f"Archive bomb protection: Member count {len(members)} exceeds limit of {max_files}"
            )

        for member in members:
            file_count += 1
            if file_count > max_files:
                raise SafeArchiveError("Archive bomb protection: Too many files in archive")

            dest_path = _check_path_safety(target_dir, member.name)

            # Symlink / Hardlink safety check
            if member.issym() or member.islnk():
                link_target = member.linkname
                if link_target.startswith(("/", "\\")) or (len(link_target) > 1 and link_target[1] == ":"):
                    raise SafeArchiveError(
                        f"Security violation: Absolute symlink target detected: '{link_target}'"
                    )
                # Resolve relative symlink from dest_path's parent
                resolved_link = (dest_path.parent / link_target).resolve()
                if not resolved_link.is_relative_to(target_dir.resolve()):
                    raise SafeArchiveError(
                        f"Security violation: Symlink escapes target directory: '{member.name}' -> '{link_target}'"
                    )
                # For safety, avoid creating real symlinks on platforms that might mishandle them
                continue

            if member.isdir():
                dest_path.mkdir(parents=True, exist_ok=True)
                continue

            if member.size > max_file_size:
                raise SafeArchiveError(
                    f"Archive bomb protection: File '{member.name}' size {member.size} exceeds limit {max_file_size}"
                )

            total_size += member.size
            if total_size > max_total_size:
                raise SafeArchiveError(
                    f"Archive bomb protection: Total uncompressed size exceeds limit of {max_total_size}"
                )

            dest_path.parent.mkdir(parents=True, exist_ok=True)
            f_in = tf.extractfile(member)
            if f_in is not None:
                with f_in, open(dest_path, "wb") as f_out:
                    bytes_written = 0
                    while chunk := f_in.read(64 * 1024):
                        bytes_written += len(chunk)
                        if bytes_written > max_file_size:
                            raise SafeArchiveError("Archive bomb: File decompressed beyond declared size")
                        f_out.write(chunk)

    return target_dir


def extract_archive_safely(
    archive_path: Path,
    target_dir: Path,
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
    max_files: int = DEFAULT_MAX_FILES,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
) -> Path:
    """Extract an archive (.whl, .zip, .tar.gz, .tgz, .tar) safely with all protections enabled."""
    name_lower = archive_path.name.lower()
    if name_lower.endswith((".whl", ".zip")):
        return extract_zip_safely(
            archive_path, target_dir, max_total_size, max_files, max_file_size
        )
    elif name_lower.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar")):
        return extract_tar_safely(
            archive_path, target_dir, max_total_size, max_files, max_file_size
        )
    else:
        raise SafeArchiveError(f"Unsupported archive format: {archive_path.name}")
