"""Explicit native fixture for the installed C++ layer consumers."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile
binary, scratch = sys.argv[1:]
parent = Path(scratch)
if not parent.is_absolute():
    raise ValueError("an existing absolute fixture root is required")
if os.name == "nt":
    native_parent = os.fspath(parent).replace("/", "\\")
    if not native_parent.startswith("\\\\?\\"):
        native_parent = ("\\\\?\\UNC\\" + native_parent[2:]
                         if native_parent.startswith("\\\\") else "\\\\?\\" + native_parent)
    parent = Path(native_parent)
if not parent.is_dir():
    raise ValueError("an existing absolute fixture root is required")
with tempfile.TemporaryDirectory(prefix="installed-layer-", dir=parent) as work:
    source = Path(work) / "input"
    source.write_bytes(b"native layer source")
    subprocess.run([binary, work], check=True, timeout=60,
                   env=dict(os.environ, TMPDIR=work, TEMP=work, TMP=work))
    assert source.read_bytes() == b"native layer source"
