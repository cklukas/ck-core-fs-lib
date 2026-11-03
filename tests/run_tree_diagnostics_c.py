"""Exercise cached diagnostics of an actual failed native C Tree worker."""
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
with tempfile.TemporaryDirectory(prefix="tree-diagnostic-c-", dir=native_parent) as work:
    root = Path(work)
    source, target = root / "source", root / "target"
    source.mkdir(mode=0o700)
    target.mkdir(mode=0o700)
    sentinel = source / "sentinel"
    sentinel.write_bytes(b"source unchanged")
    subprocess.run([binary, work, str(source)], check=True, timeout=120,
                   env=dict(os.environ, TMPDIR=work, TEMP=work, TMP=work))
    assert sentinel.read_bytes() == b"source unchanged"
    assert list(target.iterdir()) == []
    assert {p.name for p in source.iterdir()} == {"sentinel", "private"}
    assert list((source / "private").iterdir()) == []
