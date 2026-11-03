#!/usr/bin/env python3
"""Run TSan unit objects with a fresh, normal LC_LOAD_DYLIB dependency."""

import argparse
import hashlib
import json
import os
import pathlib
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone


PIN = "7a941dfb2877a0b8cf30323fefa85ad019e0b0f5"
QUALIFIED_RUNTIME = "124e6acd2266a0526f9184c852ca6f3270997378bdbcedc22c72765b4d155890"
UNIT_V3_RECORD_SHA256 = "33ee71b6861ac5095ff42f86d54e972cc1b153a477614756d2e4a2c56e2db862"


def utc():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def choose_temp_root():
    for candidate in (pathlib.Path("/Volumes/S8T/tmp"),
                      pathlib.Path("/Volumes/PRO-BLADE/tmp")):
        if not candidate.is_dir():
            continue
        if os.path.ismount(candidate.parent):
            return candidate
    raise SystemExit("no mounted allowed Mac temporary volume")


def existing_under(path, root, label):
    path = pathlib.Path(path)
    if not path.is_absolute() or not path.exists():
        raise SystemExit(f"{label} is missing or not absolute: {path}")
    resolved = path.resolve(strict=True)
    if not any(candidate in resolved.parents and os.path.ismount(candidate.parent)
               for candidate in (pathlib.Path("/Volumes/S8T/tmp"), pathlib.Path("/Volumes/PRO-BLADE/tmp"))):
        raise SystemExit(f"{label} escapes allowed temporary root: {resolved}")
    return resolved


def fresh_under(path, root, label):
    path = pathlib.Path(path)
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise SystemExit(f"{label} is not a fresh absolute path: {path}")
    parent = path.parent.resolve(strict=True)
    resolved = parent / path.name
    if not any(candidate in resolved.parents and os.path.ismount(candidate.parent)
               for candidate in (pathlib.Path("/Volumes/S8T/tmp"), pathlib.Path("/Volumes/PRO-BLADE/tmp"))):
        raise SystemExit(f"{label} escapes allowed temporary root: {resolved}")
    return resolved


def executable(path, label):
    path = pathlib.Path(path)
    if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
        raise SystemExit(f"{label} is not an executable file: {path}")
    return path.resolve(strict=True)


def run(command, *, cwd=None, env=None, capture=False):
    print("+", shlex.join(map(str, command)), flush=True)
    return subprocess.run(command, cwd=cwd, env=env, check=True,
                          text=True, capture_output=capture)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", required=True, type=pathlib.Path)
    args = parser.parse_args()

    root = choose_temp_root()
    packet = pathlib.Path(__file__).resolve(strict=True).parent.parent
    work = existing_under(args.work, root, "work")
    config_file = existing_under(work / "configure-build.json", root,
                                  "configure-build.json")
    run_tmp = fresh_under(work / ".unit-tmp", root, "unit temp")
    image = fresh_under(work / "NativeTlsUnitRuntime.dylib", root, "unit image")
    loader = fresh_under(work / "NativeTlsUnitLoader", root, "unit loader")
    focused_log = fresh_under(work / "unit-focused.log", root, "focused log")
    full_log = fresh_under(work / "unit-full.log", root, "full log")
    record_path = fresh_under(work / "unit-mach-o-record.json", root,
                              "unit record")

    run_tmp.mkdir()
    os.environ["TMPDIR"] = str(run_tmp)
    os.environ["TMP"] = str(run_tmp)
    os.environ["TEMP"] = str(run_tmp)
    os.environ["CLANG_MODULE_CACHE_PATH"] = str(run_tmp / "clang-modules")
    started = time.monotonic()
    start_utc = utc()

    config = json.loads(config_file.read_text())
    source_data = config["source"]
    build_data = config["build"]
    toolchain = config["toolchain"]
    source = existing_under(source_data["staged_path"], root, "staged source")
    build = existing_under(build_data["path"], root, "build")
    runtime = existing_under(build_data["runtime"], root, "runtime")
    clang = executable(toolchain["clang"], "clang")
    cxx = executable(toolchain["clangxx"], "clang++")
    if source_data.get("commit") != PIN:
        raise SystemExit("configure record is not pinned to LLVM 23.1.4 commit")
    if not build_data.get("runtime_sha256"):
        raise SystemExit("configure record has no runtime digest")
    if digest(runtime) != build_data["runtime_sha256"]:
        raise SystemExit("runtime changed after configure/build")
    if digest(runtime) != QUALIFIED_RUNTIME:
        print("notice: rebuilt runtime differs from the recorded qualified artifact",
              file=sys.stderr)

    clang_version = subprocess.run([str(clang), "--version"], check=True,
                                   text=True, capture_output=True).stdout
    cxx_version = subprocess.run([str(cxx), "--version"], check=True,
                                 text=True, capture_output=True).stdout
    if "23.1.4" not in clang_version or "23.1.4" not in cxx_version:
        raise SystemExit("unit compiler is not LLVM 23.1.4")
    resource = subprocess.run([str(clang), "-print-resource-dir"], check=True,
                              text=True, capture_output=True).stdout.strip()
    if "/clang/23" not in resource:
        raise SystemExit("unit compiler resource directory is not clang 23")

    unit_dir = existing_under(build / "lib/tsan/tests/unit", root,
                              "unit object directory")
    source_loader = (packet / "tests/unit-loader.c").resolve(strict=True)
    unit_record = (packet / "records/unit-dynamic-v3-record.json").resolve(strict=True)
    if digest(unit_record) != UNIT_V3_RECORD_SHA256:
        raise SystemExit("the pinned v3 unit qualification record changed")

    commands = run(["ninja", "-C", str(build), "-t", "commands",
                    "TsanUnitTests"], capture=True).stdout.splitlines()
    candidates = [line for line in commands
                  if "TsanUnitTestsObjects.tsan_dense_alloc_test" in line
                  and " -o " in line and "-c" not in shlex.split(line)]
    if len(candidates) != 1:
        raise SystemExit(f"expected one official unit linker line, found {len(candidates)}")
    link_line = candidates[0]
    prefix, separator, command_text = link_line.partition(" && ")
    if not separator:
        raise SystemExit("official unit linker line lacks an explicit cd prefix")
    prefix_parts = shlex.split(prefix)
    if prefix_parts != ["cd", str(unit_dir)]:
        raise SystemExit(f"unit linker cwd differs from generated build: {prefix_parts}")
    link = shlex.split(command_text)
    if "-o" not in link or not any("TsanUnitTestsObjects.tsan_dense_alloc_test" in arg for arg in link):
        raise SystemExit("unit linker command does not match the qualified v3 recipe")
    output_index = link.index("-o") + 1
    link[output_index] = str(image)
    link[1:1] = ["-dynamiclib", f"-Wl,-install_name,{image}"]
    run(link, cwd=unit_dir)
    if not image.is_file():
        raise SystemExit("unit image was not produced")

    # Passing the dylib as a normal linker input creates LC_LOAD_DYLIB.
    run([str(clang), "-std=c11", "-O1", "-g", str(source_loader), str(image),
         "-o", str(loader)])
    load_commands = subprocess.run(["otool", "-L", str(loader)], check=True,
                                   text=True, capture_output=True).stdout
    if image.name not in load_commands:
        raise SystemExit("loader has no normal LC_LOAD_DYLIB dependency")
    if "DYLD_INSERT_LIBRARIES" in load_commands:
        raise SystemExit("unit loader unexpectedly uses DYLD preload")

    env = os.environ.copy()
    env["CK_TSAN_UNIT_IMAGE"] = str(image)
    env["DYLD_PRINT_LIBRARIES"] = "1"
    env["TSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=0:exitcode=66"
    runtime_before = digest(runtime)
    image_before = digest(image)
    log_paths = (("focused", focused_log, ["--gtest_filter=NativeTlsShadow.*"]),
                 ("full", full_log, []))
    for suffix, log, extra in log_paths:
        with log.open("w") as stream:
            subprocess.run([str(loader), *extra], env=env, stdout=stream,
                           stderr=subprocess.STDOUT, check=True)
        text = log.read_text()
        if f"runtime_test_image={image}" not in text:
            raise SystemExit(f"{suffix}: loader did not resolve the expected image")
        if str(image) not in text or "libclang_rt.tsan_osx_dynamic.dylib" in text:
            raise SystemExit(f"{suffix}: expected one combined unit/runtime image")
        if "DYLD_INSERT_LIBRARIES" in text:
            raise SystemExit(f"{suffix}: preload workaround appeared in log")
        if digest(image) != image_before:
            raise SystemExit(f"{suffix}: unit image changed during execution")
        if digest(runtime) != runtime_before:
            raise SystemExit(f"{suffix}: runtime changed during execution")
        print(f"{suffix}: PASS ({log})")

    end_utc = utc()
    record = {
        "source_commit": source_data["commit"],
        "source_tree": str(source),
        "unit_v3_record_sha256": digest(unit_record),
        "toolchain": {
            "clang": str(clang), "clang_sha256": digest(clang),
            "clangxx": str(cxx), "clangxx_sha256": digest(cxx),
            "resource_dir": resource,
        },
        "runtime": {"path": str(runtime), "before_sha256": runtime_before,
                     "after_sha256": digest(runtime)},
        "unit_image": {"path": str(image), "sha256": digest(image)},
        "loader": {"path": str(loader), "sha256": digest(loader),
                   "lc_load_dylib": image.name},
        "control_inputs": {
            str(packet / "tests/unit-loader.c"): digest(source_loader),
            str(packet / "tests/compiler-rt/lib/tsan/tests/unit/tsan_native_tls_test.cpp"):
                digest(packet / "tests/compiler-rt/lib/tsan/tests/unit/tsan_native_tls_test.cpp"),
        },
        "logs": {str(path): digest(path) for _, path, _ in log_paths},
        "tsan_options": env["TSAN_OPTIONS"],
        "start": start_utc, "end": end_utc,
        "duration_seconds": round(time.monotonic() - started, 3),
        "result": "focused and full unit tests passed with normal LC_LOAD_DYLIB",
    }
    record_path.write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    sys.exit(main())
