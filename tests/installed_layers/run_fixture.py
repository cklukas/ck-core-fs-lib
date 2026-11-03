"""Explicit native fixture for the installed C++ layer consumers."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile
binary, scratch = sys.argv[1:]
parent = Path(scratch)
if not parent.is_absolute() or not parent.is_dir():
    raise ValueError("an existing absolute fixture root is required")
with tempfile.TemporaryDirectory(prefix="installed-layer-", dir=parent) as work:
    source = Path(work) / "input"
    source.write_bytes(b"native layer source")
    subprocess.run([binary, work], check=True, timeout=60,
                   env=dict(os.environ, TMPDIR=work, TEMP=work, TMP=work))
    assert source.read_bytes() == b"native layer source"
