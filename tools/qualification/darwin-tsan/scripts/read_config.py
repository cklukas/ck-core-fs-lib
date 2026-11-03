#!/usr/bin/env python3
"""Emit a trusted JSON config as shell assignments using shlex quoting."""

import json
import pathlib
import shlex
import sys


if len(sys.argv) != 2:
    raise SystemExit("usage: read_config.py CONFIG")
data = json.loads(pathlib.Path(sys.argv[1]).read_text())
source = data["source"]
toolchain = data["toolchain"]
build = data["build"]
values = {
    "SOURCE": source["staged_path"],
    "SOURCE_COMMIT": source["commit"],
    "BUILD": build["path"],
    "RUNTIME": build["runtime"],
    "RUNTIME_SHA256": build["runtime_sha256"] or "",
    "CC": toolchain["clang"],
    "CXX": toolchain["clangxx"],
    "RESOURCE_DIR": toolchain["resource_dir"],
}
for key, value in values.items():
    print(f"export {key}={shlex.quote(str(value))}")
