#!/usr/bin/env python3
"""Actual C resolution ABI roundtrip in an explicitly selected Linux workspace."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary, parent = sys.argv[1:]
scratch = Path(parent)
if not scratch.is_absolute() or not scratch.is_dir():
    raise SystemExit("an existing absolute native test root is required")
with tempfile.TemporaryDirectory(prefix="sync-resolution-c-", dir=scratch) as work:
    root = Path(work)
    store, left, right = (root / name for name in ("store", "left", "right"))
    for directory in (store, left, right):
        directory.mkdir(mode=0o700)
    (left / "a").write_bytes(b"LEFT")
    (right / "a").write_bytes(b"RIGHT")
    subprocess.run([binary, str(store), str(left), str(right)], check=True, timeout=120,
                   env=dict(os.environ, TMPDIR=str(root), TEMP=str(root), TMP=str(root)))
    for directory, original in ((left, b"LEFT"), (right, b"RIGHT")):
        assert (directory / "a").read_bytes() == original
        assert (directory / "a.left").read_bytes() == b"LEFT"
        assert (directory / "a.right").read_bytes() == b"RIGHT"
        assert {item.name for item in directory.iterdir()} == {"a", "a.left", "a.right"}
