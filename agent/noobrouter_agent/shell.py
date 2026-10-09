"""Subprocess helpers. Always argv lists, never shell strings built from input."""
import shutil
import subprocess


class CmdError(Exception):
    """status: HTTP status for the API layer (409 = state conflict, 500 = command failure)."""

    def __init__(self, msg, status=500):
        super().__init__(msg)
        self.status = status


def run(args, input=None, timeout=20, check=True):
    try:
        p = subprocess.run(args, input=input, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as e:
        raise CmdError(f"command not found: {args[0]}") from e
    except subprocess.TimeoutExpired as e:
        raise CmdError(f"timeout: {args[0]}") from e
    if check and p.returncode != 0:
        msg = (p.stderr or p.stdout).strip()[:800]
        raise CmdError(f"{args[0]} exit {p.returncode}: {msg}")
    return p.stdout


def try_run(args, **kw):
    """Run and return stdout, or '' on any failure (for read-only collectors)."""
    try:
        return run(args, check=False, **kw)
    except CmdError:
        return ""


def has(cmd):
    return shutil.which(cmd) is not None


def read(path, default=""):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return default
