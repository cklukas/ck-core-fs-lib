#!/usr/bin/env python3
"""Write the JSON configure/build record without shell-quoting paths."""

import argparse
import hashlib
import json
import pathlib


def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    for name in ("config", "status", "start", "end", "duration", "source",
                 "source_commit", "source_before", "source_after", "staged",
                 "staged_hash", "cc", "cc_version", "cxx", "cxx_version",
                 "asm", "llvm_cmake", "resource", "build", "runtime",
                 "runtime_sha", "packet"):
        parser.add_argument("--" + name.replace("_", "-"), required=True)
    args = parser.parse_args()
    packet = pathlib.Path(args.packet)
    controls = [
        packet / "tests/compiler-rt/test/tsan/native_errno_tls.cpp",
        packet / "tests/compiler-rt/test/tsan/libdispatch/native_errno_gcd.cpp",
        packet / "tests/compiler-rt/lib/tsan/tests/unit/tsan_native_tls_test.cpp",
    ]
    patches = {
        str(packet / "patches/0001-darwin-arm64-native-errno-shadow-lifetime.patch"):
            digest(packet / "patches/0001-darwin-arm64-native-errno-shadow-lifetime.patch"),
        str(packet / "patches/0002-tests.patch"):
            digest(packet / "patches/0002-tests.patch"),
    }
    record = {
        "status": args.status,
        "source": {"path": args.source, "commit": args.source_commit,
                    "tree_sha256_before": args.source_before,
                    "tree_sha256_after": args.source_after,
                    "staged_snapshot_sha256": args.staged_hash,
                    "staged_path": args.staged},
        "patches": patches,
        "control_inputs": {str(path): digest(path) for path in controls},
        "toolchain": {
            "clang": args.cc, "clang_version": args.cc_version,
            "clang_sha256": digest(args.cc),
            "clangxx": args.cxx, "clangxx_version": args.cxx_version,
            "clangxx_sha256": digest(args.cxx),
            "assembler": args.asm, "assembler_sha256": digest(args.asm),
            "llvm_cmake": args.llvm_cmake,
            "llvm_cmake_sha256": digest(args.llvm_cmake),
            "resource_dir": args.resource,
        },
        "build": {"path": args.build, "runtime": args.runtime,
                  "runtime_sha256": args.runtime_sha or None,
                  "architecture": "arm64", "deployment_target": "13.0",
                  "parallel": 1},
        "timing": {"start": args.start, "end": args.end,
                   "duration_seconds": int(args.duration)},
    }
    pathlib.Path(args.config).write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
