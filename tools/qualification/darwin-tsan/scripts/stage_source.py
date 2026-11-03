#!/usr/bin/env python3
"""Stage present tracked files from a clean sparse checkout, excluding caches."""
import os
from pathlib import Path
import subprocess
import sys

source, target = (Path(value).resolve(strict=True) for value in sys.argv[1:])
if any(target.iterdir()):
    raise SystemExit("staging directory must be empty")
entries = subprocess.check_output(
    ["git", "-C", str(source), "ls-files", "--stage", "-z"])
for record in entries.split(b"\0"):
    if not record:
        continue
    metadata, name = record.split(b"\t", 1)
    mode, _, stage = metadata.split()
    relative = Path(os.fsdecode(name))
    if relative.is_absolute() or ".." in relative.parts or stage != b"0":
        raise SystemExit("invalid tracked source entry")
    original, output = source / relative, target / relative
    if not original.exists() and not original.is_symlink():
        continue  # A sparse checkout deliberately omits unrelated projects.
    output.parent.mkdir(parents=True, exist_ok=True)
    if mode == b"120000":
        output.symlink_to(os.readlink(original))
    elif mode in (b"100644", b"100755") and original.is_file():
        output.write_bytes(original.read_bytes())
        output.chmod(0o755 if mode == b"100755" else 0o644)
    else:
        raise SystemExit(f"unsupported tracked source type: {relative}")
