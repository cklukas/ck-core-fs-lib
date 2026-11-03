#!/usr/bin/env bash
set -euo pipefail

script_dir="${BASH_SOURCE[0]%/*}"
[[ "$script_dir" != "${BASH_SOURCE[0]}" ]] || script_dir="."
packet_root="$(cd "$script_dir/.." && pwd -P)"
# shellcheck disable=SC1091
source "$packet_root/scripts/mac-temp-preflight.sh"

usage() {
  echo "usage: $0 --work QUALIFIED_WORK_DIR" >&2
  exit 2
}
work_arg=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --work) [[ $# -ge 2 ]] || usage; work_arg="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[[ -n "$work_arg" ]] || usage
[[ "${OSTYPE:-}" == darwin* ]] || { echo "Darwin is required" >&2; exit 1; }
ck_select_temp_root
# The read-only toolkit may live in the permanent project checkout.
work_dir="$(ck_require_existing_under_root "$work_arg" work)"
work_tmp="$(ck_require_fresh_under_root "$work_dir/.controls-tmp" controls-temp)"
mkdir -p "$work_tmp"
export TMPDIR="$work_tmp" TMP="$work_tmp" TEMP="$work_tmp"
export CLANG_MODULE_CACHE_PATH="$work_tmp/clang-modules"
start_epoch="$(date +%s)"
start_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

config="$work_dir/configure-build.json"
[[ -f "$config" ]] || { echo "run configure-build.sh first" >&2; exit 1; }
eval "$(python3 "$packet_root/scripts/read_config.py" "$config")"
source_root="$SOURCE/compiler-rt"
runtime="$RUNTIME"
clang="${CC:?configure-build.json has no CC}"
cxx="${CXX:?configure-build.json has no CXX}"
resource="$work_dir/resource"
out="$work_dir/controls"
record="$work_dir/controls-record.json"
for output in "$resource" "$out" "$record"; do
  [[ ! -e "$output" ]] || { echo "control output already exists: $output" >&2; exit 1; }
done
ck_require_existing_under_root "$source_root" staged-source >/dev/null
ck_require_existing_under_root "$runtime" runtime >/dev/null
[[ -x "$clang" && -x "$cxx" ]] || { echo "configured compilers are not executable" >&2; exit 1; }
[[ "$("$clang" --version 2>&1)" == *23.1.4* ]] || { echo "clang is not LLVM 23.1.4" >&2; exit 1; }
[[ "$("$cxx" --version 2>&1)" == *23.1.4* ]] || { echo "clang++ is not LLVM 23.1.4" >&2; exit 1; }
resource_dir="$("$clang" -print-resource-dir)"
[[ "$resource_dir" == */clang/23* ]] || { echo "resource directory is not clang 23" >&2; exit 1; }
runtime_hash_before="$(shasum -a 256 "$runtime" | awk '{print $1}')"
[[ "$runtime_hash_before" == "${RUNTIME_SHA256:?missing runtime hash}" ]] || {
  echo "runtime changed after configure/build" >&2
  exit 1
}
mkdir -p "$out/tmp" "$resource/lib"
ln -s "$resource_dir/include" "$resource/include"
ln -s "$(dirname "$runtime")" "$resource/lib/darwin"

export TSAN_OPTIONS='halt_on_error=1:abort_on_error=0:exitcode=66'
export DYLD_PRINT_LIBRARIES=1

compile() {
  local name="$1" compiler="$2"; shift 2
  "$compiler" -resource-dir="$resource" -pthread -O1 -g -fsanitize=thread \
    -fno-omit-frame-pointer -I "$source_root/test" "$@" -o "$out/$name"
  otool -L "$out/$name" | grep -q libclang_rt.tsan_osx_dynamic.dylib
}

verify_runtime_image_log() {
  local log="$1"
  grep -q libclang_rt.tsan_osx_dynamic.dylib "$log"
  if ! grep -Fq "$runtime" "$log" &&
     ! grep -Fq "$resource/lib/darwin/libclang_rt.tsan_osx_dynamic.dylib" "$log"; then
    echo "DYLD_PRINT_LIBRARIES did not show the configured runtime image: $log" >&2
    return 1
  fi
  [[ "$(shasum -a 256 "$runtime" | awk '{print $1}')" == "$RUNTIME_SHA256" ]]
}

expect_clean() {
  local name="$1"; shift
  set +e
  "$@" >"$out/$name.log" 2>&1
  local rc=$?
  set -e
  [[ $rc -eq 0 ]] || { cat "$out/$name.log" >&2; return 1; }
  ! grep -q 'WARNING: ThreadSanitizer' "$out/$name.log"
  verify_runtime_image_log "$out/$name.log"
}

expect_race() {
  local name="$1" needle="$2"; shift 2
  set +e
  "$@" >"$out/$name.log" 2>&1
  local rc=$?
  set -e
  [[ $rc -eq 66 ]] || { cat "$out/$name.log" >&2; return 1; }
  grep -q "$needle" "$out/$name.log"
  verify_runtime_image_log "$out/$name.log"
}

native="$packet_root/tests/compiler-rt/test/tsan/native_errno_tls.cpp"
gcd="$packet_root/tests/compiler-rt/test/tsan/libdispatch/native_errno_gcd.cpp"
compile native_errno_tls "$cxx" -std=c++17 "$native"
expect_clean native_errno_detached "$out/native_errno_tls" detached
expect_clean native_errno_joined "$out/native_errno_tls" joined
expect_race native_errno_shared 'ThreadSanitizer: data race' "$out/native_errno_tls" shared

compile native_errno_gcd "$cxx" -std=c++17 -fblocks "$gcd"
expect_clean gcd "$out/native_errno_gcd" gcd
expect_race main_foreign 'ThreadSanitizer: data race' "$out/native_errno_gcd" main-foreign

compile tls_race "$cxx" "$source_root/test/tsan/tls_race.cpp"
expect_race tls_race 'ThreadSanitizer: data race' "$out/tls_race"
compile tls_race2 "$cxx" "$source_root/test/tsan/tls_race2.cpp"
expect_race tls_race2 'ThreadSanitizer: data race' "$out/tls_race2"
compile finished_thread "$cxx" "$source_root/test/tsan/race_with_finished_thread.cpp"
expect_race finished_thread 'ThreadSanitizer: data race' "$out/finished_thread"
compile thread_detach "$clang" "$source_root/test/tsan/thread_detach.c"
expect_clean thread_detach "$out/thread_detach"
compile signal_errno "$cxx" "$source_root/test/tsan/signal_errno.cpp"
expect_race signal_errno 'signal handler spoils errno' "$out/signal_errno"
compile dtls "$clang" "$source_root/test/tsan/dtls.c"
compile dtls-so.so "$clang" -DBUILD_SO -fPIC -shared "$source_root/test/tsan/dtls.c"
expect_clean dtls "$out/dtls"

runtime_hash_after="$(shasum -a 256 "$runtime" | awk '{print $1}')"
[[ "$runtime_hash_after" == "$runtime_hash_before" ]] || {
  echo "runtime changed during controls" >&2
  exit 1
}
end_epoch="$(date +%s)"
end_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
python3 - "$record" "$source_root" "$runtime" "$clang" "$cxx" \
  "$SOURCE_COMMIT" "$runtime_hash_before" "$runtime_hash_after" "$start_utc" "$end_utc" \
  "$((end_epoch - start_epoch))" "$out" "$packet_root" <<'PY'
import hashlib
import json
import pathlib
import sys

record, source_root, runtime, clang, cxx = map(pathlib.Path, sys.argv[1:6])
source_commit, before, after, start, end, duration, out, packet = sys.argv[6:14]
packet = pathlib.Path(packet)
out = pathlib.Path(out)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

inputs = [
    packet / "tests/compiler-rt/test/tsan/native_errno_tls.cpp",
    packet / "tests/compiler-rt/test/tsan/libdispatch/native_errno_gcd.cpp",
    packet / "tests/compiler-rt/lib/tsan/tests/unit/tsan_native_tls_test.cpp",
    source_root / "test/tsan/tls_race.cpp",
    source_root / "test/tsan/tls_race2.cpp",
    source_root / "test/tsan/race_with_finished_thread.cpp",
    source_root / "test/tsan/thread_detach.c",
    source_root / "test/tsan/signal_errno.cpp",
    source_root / "test/tsan/dtls.c",
]
data = {
    "source_commit": source_commit,
    "source_tree": str(source_root),
    "start": start, "end": end, "duration_seconds": int(duration),
    "tsan_options": "halt_on_error=1:abort_on_error=0:exitcode=66",
    "runtime": {"path": str(runtime), "before_sha256": before, "after_sha256": after},
    "toolchain": {
        "clang": str(clang), "clang_sha256": digest(clang),
        "clangxx": str(cxx), "clangxx_sha256": digest(cxx),
    },
    "control_inputs": {str(path): digest(path) for path in inputs},
    "logs": {str(path): digest(path) for path in sorted(out.glob("*.log"))},
    "result": "expected clean controls passed and intentional races returned exit 66",
}
record.write_text(json.dumps(data, indent=2) + "\n")
PY
echo "all native errno, GCD, and upstream control expectations passed"
