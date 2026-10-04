"""Skip helpers for tests that cannot run on Windows.

Genuinely POSIX-only: Unix shell interpreter, chmod +x PATH stubs,
mkfifo / SIGALRM. Never weaken asserts — skip with a reason.
"""

from __future__ import annotations

import sys

import pytest

WIN32 = sys.platform == "win32"

requires_unix_shell = pytest.mark.skipif(
    WIN32,
    reason="POSIX-only: Unix shell interpreter and chmod +x PATH stubs",
)
