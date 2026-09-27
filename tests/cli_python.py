"""Windows-portable CLI interpreter and bash-wrapper skip.

Subprocess tests must use sys.executable, not the `python3` alias
(Microsoft Store stub on Windows). Bash `.sh` wrappers stay Linux/CI;
DESKTOP skips them with a reason instead of failing on missing WSL bash.
"""
from __future__ import annotations

import os
import sys

import pytest

PYTHON = sys.executable
skip_unless_bash = pytest.mark.skipif(
    os.name == "nt",
    reason="bash wrapper; WSL /bin/bash missing on this host",
)
