#!/usr/bin/env python3
"""Stable SHA-256 over a source tree, excluding Git metadata."""

import hashlib
import os
import pathlib
import sys


def digest(path):
    state = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            state.update(block)
    return state.hexdigest()


def tree_digest(root):
    state = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file() or p.is_symlink()):
        relative = path.relative_to(root).as_posix()
        if relative == ".git" or relative.startswith(".git/"):
            continue
        content = ("link:" + os.readlink(path)) if path.is_symlink() else digest(path)
        state.update(relative.encode() + b"\0" + content.encode() + b"\n")
    return state.hexdigest()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: tree_hash.py DIRECTORY")
    root = pathlib.Path(sys.argv[1]).resolve(strict=True)
    print(tree_digest(root))
