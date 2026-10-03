"""Allows only one copy of the app to run at a time for each user.

Copies running side by side would each keep their own unlocked data key, so after a PIN or
password change in one, the other would keep saving tokens with the replaced key.
"""
import os
import sys

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl

APP_DIR_NAME = "2FA App"
LOCK_FILE_NAME = "instance.lock"

# Kept so the OS lock isn't released if the caller discards the returned descriptor
_held_lock_fd: int | None = None

def _app_data_dir() -> str:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return os.path.join(base, APP_DIR_NAME)

def acquire(lock_path: str | None = None) -> int | None:
    """Locks the lock file (by default in the user's app data folder) and returns its file
    descriptor, or returns None if another copy of the app holds the lock. The OS releases the
    lock when the descriptor is closed or the process exits, even if it crashes.
    Errors creating the lock file are raised."""
    if lock_path is None:
        directory = _app_data_dir()
        os.makedirs(directory, mode=0o700, exist_ok=True)
        lock_path = os.path.join(directory, LOCK_FILE_NAME)
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        if os.lseek(fd, 0, os.SEEK_END) == 0:
            os.write(fd, b"\0")
        os.lseek(fd, 0, os.SEEK_SET)
        if sys.platform == "win32":
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    global _held_lock_fd
    _held_lock_fd = fd
    return fd
