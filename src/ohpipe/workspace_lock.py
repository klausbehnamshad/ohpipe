"""Die gemeinsame, fest geordnete WorkspaceWriteLock der sieben Writer."""

from __future__ import annotations

import fcntl
import os
import stat
from contextlib import contextmanager
from pathlib import Path
from collections.abc import Iterator

__all__ = ["WorkspaceLockError", "workspace_write_lock"]


class WorkspaceLockError(RuntimeError):
    pass


@contextmanager
def workspace_write_lock(root: Path, *, blocking: bool = True) -> Iterator[int]:
    governance = Path(root) / "_governance"
    fd_dir = os.open(governance, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            fd = os.open(
                ".b3b-workspace-write.lock",
                os.O_RDWR | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=fd_dir,
            )
            os.fsync(fd_dir)
        except FileExistsError:
            fd = os.open(
                ".b3b-workspace-write.lock",
                os.O_RDWR | os.O_NOFOLLOW,
                dir_fd=fd_dir,
            )
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise WorkspaceLockError("WorkspaceWriteLock ist keine regulaere Datei")
            fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
            yield fd
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
    finally:
        os.close(fd_dir)
