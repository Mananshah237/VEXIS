"""Filesystem boundary checks for untrusted source trees."""

import os
import stat
from pathlib import Path


def validate_source_tree(root: str) -> None:
    """Reject links and special files before any scan pass reads a checkout."""
    base = Path(root)
    if base.is_symlink() or (hasattr(base, "is_junction") and base.is_junction()):
        raise ValueError("Source root must not be a link")
    def onerror(error):
        raise error
    for directory, dirs, files in os.walk(base, followlinks=False, onerror=onerror):
        for name in dirs + files:
            path = Path(directory) / name
            mode = path.lstat().st_mode
            if (stat.S_ISLNK(mode)
                    or (hasattr(path, "is_junction") and path.is_junction())
                    or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))):
                raise ValueError(f"Unsupported source filesystem entry: {path.relative_to(base)}")


def read_source_text(path: str, root: str | None = None) -> str:
    """Read a regular file without following links in its path.

    POSIX uses descriptor-relative traversal so component replacement cannot
    redirect a read. Windows checks reparse points; scans must own their tree
    exclusively there, as they do for freshly acquired scan directories.
    """
    source = Path(os.path.abspath(path))
    if root is not None:
        source.relative_to(Path(os.path.abspath(root)))
    if os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW"):
        fd = os.open(source.anchor, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in source.parts[1:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            file_fd = os.open(
                source.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd
            )
            with os.fdopen(file_fd, "r", encoding="utf-8", errors="replace") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ValueError("Source must be a regular file")
                return stream.read()
        finally:
            os.close(fd)
    for component in [*reversed(source.parents), source]:
        if component.is_symlink() or (
            hasattr(component, "is_junction") and component.is_junction()
        ):
            raise ValueError("Source path must not contain links")
    if not stat.S_ISREG(source.lstat().st_mode):
        raise ValueError("Source must be a regular file")
    return source.read_text(encoding="utf-8", errors="replace")
