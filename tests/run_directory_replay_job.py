"""Run the native directory executor under an explicit private fixture root."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile

binary, scratch = sys.argv[1:]
parent = Path(scratch)
if not parent.is_absolute():
    raise ValueError("an absolute native fixture root is required")
native_parent = os.fspath(parent)
if os.name == "nt":
    native_parent = native_parent.replace("/", "\\")
    if not native_parent.startswith("\\\\?\\"):
        native_parent = ("\\\\?\\UNC\\" + native_parent[2:]
                         if native_parent.startswith("\\\\") else "\\\\?\\" + native_parent)
with tempfile.TemporaryDirectory(prefix="directory-replay-", dir=native_parent) as work:
    subprocess.run([binary, work], check=True, timeout=170,
                   env=dict(os.environ, TMPDIR=work, TEMP=work, TMP=work))
