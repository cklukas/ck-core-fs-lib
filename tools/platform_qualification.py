#!/usr/bin/env python3
"""Build the independent tests against a verified *installed* pinned baseline.

First archive the exact commit with `git archive <full-sha> -o baseline.tar`,
extract it into an isolated task directory, and run its tools/qualification.cmake
with --parallel 1 (the script enforces that cap). Then invoke this harness with
--archive baseline.tar --revision <full-sha> --prefix <baseline>/install
--baseline-record <baseline>/qualification.log --output <fresh-task-directory>.
On Windows enter the x64 VS developer environment first. No source-tree CMake
changes are needed. Exit 2 means incomplete platform coverage, never a pass.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import time


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--baseline-record", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--test-source", type=Path, default=Path(__file__).resolve().parent.parent / "tests/platform_qualification.cpp")
    parser.add_argument("--unc-root", help="actual UNC alias of output/fixtures, not a fabricated namespace")
    parser.add_argument("--cmake", default="cmake")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.revision):
        parser.error("revision must be the full pinned commit SHA")
    output = args.output
    if not output.is_absolute() or output.exists():
        parser.error("output must be a fresh absolute directory")
    output = output.resolve()
    system = platform.system()
    if system == "Windows":
        if not Path("V:/").is_dir() or not output.is_relative_to(Path("V:/tmp").resolve()):
            parser.error("Windows output must be beneath available V:/tmp")
        if not args.prefix.resolve().is_relative_to(Path("V:/").resolve()):
            parser.error("Windows installed prefix must be on V:")
    elif system == "Darwin":
        roots = [Path("/Volumes") / vol / "tmp" for vol in ("S8T", "PRO-BLADE")
                 if os.path.ismount(Path("/Volumes") / vol)]
        if not any(output.is_relative_to(root) for root in roots):
            parser.error("Mac output must be beneath mounted S8T/tmp or PRO-BLADE/tmp")
    baseline_record = args.baseline_record.read_text()
    if "qualification PASS" not in baseline_record:
        parser.error("baseline record must contain a completed successful qualification")
    # git archive writes the full commit ID into its global pax header. Verify
    # every installed public/native header byte against that pinned archive.
    source_manifest = []
    with tarfile.open(args.archive) as archive:
        if archive.pax_headers.get("comment") != args.revision:
            parser.error("git archive commit does not match requested revision")
        for member in archive.getmembers():
            if not member.isfile():
                continue
            contents = archive.extractfile(member).read()
            source_manifest.append((member.name, hashlib.sha256(contents).hexdigest()))
            installed = None
            if member.name.startswith("include/"):
                installed = args.prefix / member.name
            elif member.name.startswith("src/files/") and member.name.endswith(".hpp"):
                installed = args.prefix / "include/ck-core-fs" / member.name.removeprefix("src/files/")
            if installed and (not installed.is_file() or installed.read_bytes() != contents):
                parser.error(f"installed header mismatch: {installed}")
    baseline_inputs = [(name, sha) for name, sha in source_manifest if
                       name == "CMakeLists.txt" or name.startswith(("src/", "include/", "tests/", "cmake/", "tools/", ".github/workflows/"))]
    baseline_fingerprint = hashlib.sha256("".join(f"{sha}  {name}\n" for name, sha in sorted(baseline_inputs)).encode()).hexdigest()
    if not re.search(r"qualification PASS .*source_sha256=" + baseline_fingerprint + r"\b", baseline_record):
        parser.error("baseline source fingerprint does not match pinned archive")
    if args.prefix.resolve() != (args.baseline_record.parent / "install").resolve():
        parser.error("installed prefix must belong to the recorded baseline qualification")
    output.mkdir(parents=True)
    temporary = output / "tmp"
    temporary.mkdir()
    os.environ.update(TMPDIR=str(temporary), TMP=str(temporary), TEMP=str(temporary),
                      CMAKE_BUILD_PARALLEL_LEVEL="1", CTEST_PARALLEL_LEVEL="1",
                      PYTHONDONTWRITEBYTECODE="1")
    manifest = output / "source.sha256"
    manifest.write_text("".join(f"{sha}  {name}\n" for name, sha in sorted(source_manifest)))
    shutil.copyfile(args.baseline_record, output / "baseline-qualification.log")
    # Also retain the baseline per-input hash record so its timing and identity
    # remain reviewable even if the baseline build tree is later retired.
    for record in args.baseline_record.parent.glob("source-*.sha256"):
        shutil.copyfile(record, output / ("baseline-" + record.name))
    prefix = args.prefix.resolve()
    installed_manifest = [(str(p.relative_to(prefix)), digest(p))
                          for p in sorted(prefix.rglob("*")) if p.is_file()]
    (output / "installed.sha256").write_text("".join(f"{sha}  {name}\n" for name, sha in installed_manifest))
    source = output / "driver"
    source.mkdir()
    test = source / "platform_qualification.cpp"
    shutil.copyfile(args.test_source, test)
    # Generated driver only; the library and repository CMake files stay intact.
    (source / "CMakeLists.txt").write_text('''cmake_minimum_required(VERSION 3.25)
project(independent_platform_qualification LANGUAGES CXX)
find_package(ck-core-fs CONFIG REQUIRED)
add_executable(platform_qualification platform_qualification.cpp)
target_compile_features(platform_qualification PRIVATE cxx_std_20)
target_link_libraries(platform_qualification PRIVATE ck::ck_files_platform ck::ck_file_engine_c)
''')
    report = dict(revision=args.revision, archive=str(args.archive.resolve()), archive_sha256=digest(args.archive),
                  baseline_source_sha256=baseline_fingerprint,
                  source_manifest_sha256=digest(manifest), test_sha256=digest(test),
                  installed_manifest_sha256=digest(output / "installed.sha256"),
                  baseline_record=str(args.baseline_record.resolve()), baseline_record_sha256=digest(args.baseline_record),
                  prefix=str(prefix), output=str(output), config="RelWithDebInfo", compile_slots=1,
                  started=utc(), platform=platform.platform(), python=sys.version, stages=[],
                  duration_baseline="No comparable local clean qualification-test build recorded. Inspect verbose compile/link inputs; CI host timings are not a local duration baseline.",
                  assets="No separate bundled assets; all installed headers and binaries fingerprinted.")
    report_file = output / "record.json"

    def save():
        report_file.write_text(json.dumps(report, indent=2) + "\n")

    def run(label, command, env=None):
        stage = dict(stage=label, command=list(map(str, command)), started=utc())
        start = time.monotonic()
        with (output / (label + ".log")).open("wb") as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, env=env)
        stage.update(ended=utc(), elapsed_seconds=round(time.monotonic() - start, 3), result=result.returncode)
        report["stages"].append(stage)
        save()
        print(json.dumps(stage), flush=True)
        return result.returncode

    save()
    build = output / "build"
    result = run("configure", [args.cmake, "-S", str(source), "-B", str(build),
                 "-DCMAKE_BUILD_TYPE=RelWithDebInfo", "-DCMAKE_PREFIX_PATH=" + str(prefix)])
    if not result:
        result = run("build", [args.cmake, "--build", str(build), "--config", "RelWithDebInfo", "--parallel", "1", "--verbose"])
    if not result:
        executable = build / ("RelWithDebInfo/platform_qualification.exe" if system == "Windows" else "platform_qualification")
        if not executable.is_file():
            executable = build / "platform_qualification.exe"
        report["executable"] = str(executable)
        report["executable_sha256"] = digest(executable)
        report["executable_mtime_ns"] = executable.stat().st_mtime_ns
        if executable.stat().st_mtime_ns < max(test.stat().st_mtime_ns, (source / "CMakeLists.txt").stat().st_mtime_ns):
            report.update(result=1, freshness_error="Executable predates staged test inputs; refusing launch")
            save()
            return 1
        env = os.environ.copy()
        if system == "Windows":
            env["PATH"] = str(prefix / "bin") + os.pathsep + env["PATH"]
        command = [str(executable), str(output / "fixtures")]
        if args.unc_root:
            command.append(args.unc_root)
        result = run("test", command, env)
        print((output / "test.log").read_text(errors="replace"), end="", flush=True)
    report.update(ended=utc(), result=result)
    # Detect unexpected install changes or test-source edits during this run.
    current = [(str(p.relative_to(prefix)), digest(p)) for p in sorted(prefix.rglob("*")) if p.is_file()]
    if current != installed_manifest or digest(test) != report["test_sha256"]:
        report.update(result=1, stability_error="Installed inputs or staged tests changed during qualification")
        result = 1
    save()
    return result


if __name__ == "__main__":
    sys.exit(main())
