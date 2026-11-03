"""Native name-side feedback without executing any copy/publication."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile

binary, scratch = sys.argv[1:]
parent = Path(scratch)
if not parent.is_absolute() or not parent.is_dir():
    raise ValueError("an existing absolute native fixture root is required")
with tempfile.TemporaryDirectory(prefix="tree-name-feedback-", dir=parent) as work:
    root = Path(work)
    source, target = root / "source", root / "target"
    source.mkdir(mode=0o700)
    target.mkdir(mode=0o700)
    incoming, existing = b"incoming data" * 100, b"old target data" * 100
    (source / "alpha").write_bytes(incoming)
    (target / "alpha").write_bytes(existing)
    subprocess.run([binary, work], check=True, timeout=60,
                   env=dict(os.environ, TMPDIR=work, TEMP=work, TMP=work))
    assert {p.name for p in source.iterdir()} == {"alpha"}
    assert {p.name for p in target.iterdir()} == {"alpha"}
    assert (source / "alpha").read_bytes() == incoming
    assert (target / "alpha").read_bytes() == existing
