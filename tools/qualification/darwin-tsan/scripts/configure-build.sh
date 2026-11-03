#!/usr/bin/env bash
set -euo pipefail

readonly PIN="7a941dfb2877a0b8cf30323fefa85ad019e0b0f5"
script_dir="${BASH_SOURCE[0]%/*}"
[[ "$script_dir" != "${BASH_SOURCE[0]}" ]] || script_dir="."
packet_root="$(cd "$script_dir/.." && pwd -P)"
# shellcheck disable=SC1091
source "$packet_root/scripts/mac-temp-preflight.sh"

usage() {
  echo "usage: $0 --source CLEAN_LLVM_CHECKOUT --work FRESH_WORK_DIR [--prepare-only]" >&2
  exit 2
}

source_arg=""
work_arg=""
prepare_only=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --source) [[ $# -ge 2 ]] || usage; source_arg="$2"; shift 2 ;;
    --work) [[ $# -ge 2 ]] || usage; work_arg="$2"; shift 2 ;;
    --prepare-only) prepare_only=1; shift ;;
    *) usage ;;
  esac
done
[[ -n "$source_arg" && -n "$work_arg" ]] || usage
[[ "$work_arg" != *';'* ]] || { echo "CMake build directories cannot contain semicolons" >&2; exit 1; }
[[ "${OSTYPE:-}" == darwin* ]] || { echo "Darwin is required" >&2; exit 1; }

ck_select_temp_root
# The read-only toolkit may live in the permanent project checkout.
source_dir="$(ck_require_existing_under_root "$source_arg" source)"
work_dir="$(ck_require_fresh_under_root "$work_arg" work)"
mkdir -p "$work_dir"
work_tmp="$(ck_require_fresh_under_root "$work_dir/tmp" work-temp)"
mkdir -p "$work_tmp"
export TMPDIR="$work_tmp" TMP="$work_tmp" TEMP="$work_tmp"
export CLANG_MODULE_CACHE_PATH="$work_tmp/clang-modules"

[[ -e "$source_dir/.git" ]] || { echo "source must be a Git checkout" >&2; exit 1; }
start_epoch="$(date +%s)"
start_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
source_pin="$(git -C "$source_dir" rev-parse HEAD)"
[[ "$source_pin" == "$PIN" ]] || {
  echo "source is $source_pin, expected $PIN" >&2
  exit 1
}
git -C "$source_dir" diff --quiet
git -C "$source_dir" diff --cached --quiet
[[ -z "$(git -C "$source_dir" status --porcelain=v1 --untracked-files=all)" ]] || {
  echo "source checkout has tracked or untracked changes" >&2
  exit 1
}
source_hash_before="$(python3 "$packet_root/scripts/tree_hash.py" "$source_dir")"

staged="$work_dir/llvm-source"
mkdir -p "$staged"
python3 "$packet_root/scripts/stage_source.py" "$source_dir" "$staged"
patch_log="$work_dir/patch-check.log"
git -C "$staged" apply --no-index --check \
  "$packet_root/patches/0001-darwin-arm64-native-errno-shadow-lifetime.patch" \
  >"$patch_log" 2>&1
git -C "$staged" apply --no-index --check \
  "$packet_root/patches/0002-tests.patch" >>"$patch_log" 2>&1
git -C "$staged" apply --no-index \
  "$packet_root/patches/0001-darwin-arm64-native-errno-shadow-lifetime.patch" \
  >>"$patch_log" 2>&1
git -C "$staged" apply --no-index \
  "$packet_root/patches/0002-tests.patch" >>"$patch_log" 2>&1
staged_hash="$(python3 "$packet_root/scripts/tree_hash.py" "$staged")"
source_hash_after="$(python3 "$packet_root/scripts/tree_hash.py" "$source_dir")"
[[ "$source_hash_before" == "$source_hash_after" ]] || {
  echo "source changed while staging patches" >&2
  exit 1
}

if [[ -n "${CC+x}" ]]; then
  cc="$CC"
else
  cc=""
  for candidate in /opt/homebrew/opt/llvm/23.1.4/bin/clang /opt/homebrew/opt/llvm/bin/clang; do
    if [[ -x "$candidate" ]]; then cc="$candidate"; break; fi
  done
fi
if [[ -n "${CXX+x}" ]]; then
  cxx="$CXX"
else
  cxx=""
  for candidate in /opt/homebrew/opt/llvm/23.1.4/bin/clang++ /opt/homebrew/opt/llvm/bin/clang++; do
    if [[ -x "$candidate" ]]; then cxx="$candidate"; break; fi
  done
fi
asm="${ASM:-$cc}"
[[ -x "$cc" && -x "$cxx" && -x "$asm" ]] || {
  echo "LLVM 23.1.4 clang/clang++/assembler paths are not executable" >&2
  exit 1
}
cc_version="$("$cc" --version 2>&1)"
cxx_version="$("$cxx" --version 2>&1)"
[[ "$cc_version" == *23.1.4* && "$cxx_version" == *23.1.4* ]] || {
  echo "compiler version is not LLVM 23.1.4" >&2
  exit 1
}
resource_dir="$("$cc" -print-resource-dir)"
[[ "$resource_dir" == */clang/23* ]] || {
  echo "compiler resource directory is not clang 23: $resource_dir" >&2
  exit 1
}
if [[ -n "${LLVM_CMAKE_DIR+x}" ]]; then
  llvm_cmake_dir="$LLVM_CMAKE_DIR"
elif [[ -d /opt/homebrew/opt/llvm/lib/cmake/llvm ]]; then
  llvm_cmake_dir=/opt/homebrew/opt/llvm/lib/cmake/llvm
else
  llvm_cmake_dir=/opt/homebrew/Cellar/llvm/23.1.4/lib/cmake/llvm
fi
llvm_config="$llvm_cmake_dir/LLVMConfig.cmake"
[[ -f "$llvm_config" ]] || { echo "LLVMConfig.cmake is missing" >&2; exit 1; }
grep -q 23.1.4 "$llvm_config" || {
  echo "LLVM CMake package is not version 23.1.4: $llvm_cmake_dir" >&2
  exit 1
}
lit="$staged/llvm/utils/lit/lit.py"
[[ -f "$lit" ]] || { echo "pinned llvm-lit source is missing: $lit" >&2; exit 1; }

build="$work_dir/build"
runtime="$build/lib/darwin/libclang_rt.tsan_osx_dynamic.dylib"
config="$work_dir/configure-build.json"
for output in "$build" "$work_dir/configure.log" "$work_dir/build-tsan.log" \
              "$work_dir/build-unit.log" "$config"; do
  [[ ! -e "$output" ]] || { echo "output already exists: $output" >&2; exit 1; }
done

finish_record() {
  local status="$1" runtime_sha="${2:-}"
  local end_epoch end_utc
  end_epoch="$(date +%s)"
  end_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  python3 "$packet_root/scripts/write_config.py" \
    --config "$config" --status "$status" --start "$start_utc" --end "$end_utc" \
    --duration "$((end_epoch - start_epoch))" --source "$source_dir" \
    --source-commit "$source_pin" --source-before "$source_hash_before" \
    --source-after "$source_hash_after" --staged "$staged" \
    --staged-hash "$staged_hash" --cc "$cc" --cc-version "$cc_version" \
    --cxx "$cxx" --cxx-version "$cxx_version" --asm "$asm" \
    --llvm-cmake "$llvm_config" --resource "$resource_dir" \
    --build "$build" --runtime "$runtime" --runtime-sha "$runtime_sha" \
    --packet "$packet_root"
}

if [[ $prepare_only -eq 1 ]]; then
  finish_record PREPARED
  echo "PREPARED: patches, source hashes, toolchain pin, and JSON config recorded; no CMake or compilation invoked (toolchain identity probes completed)"
  exit 0
fi

cmake -G Ninja -S "$staged/compiler-rt" -B "$build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER="$cc" \
  -DCMAKE_CXX_COMPILER="$cxx" \
  -DCMAKE_ASM_COMPILER="$asm" \
  -DCMAKE_C_COMPILER_TARGET=arm64-apple-darwin27.2.0 \
  -DCMAKE_CXX_COMPILER_TARGET=arm64-apple-darwin27.2.0 \
  -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0 \
  -DLLVM_CMAKE_DIR="$llvm_cmake_dir" \
  -DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON \
  -DCOMPILER_RT_BUILD_BUILTINS=OFF \
  -DCOMPILER_RT_BUILD_SANITIZERS=ON \
  -DCOMPILER_RT_SANITIZERS_TO_BUILD=tsan \
  -DCOMPILER_RT_BUILD_LIBFUZZER=OFF \
  -DCOMPILER_RT_BUILD_PROFILE=OFF \
  -DCOMPILER_RT_BUILD_CRT=OFF \
  -DCOMPILER_RT_BUILD_XRAY=OFF \
  -DCOMPILER_RT_BUILD_MEMPROF=OFF \
  -DCOMPILER_RT_BUILD_ORC=OFF \
  -DCOMPILER_RT_INCLUDE_TESTS=ON \
  -DCOMPILER_RT_ENABLE_IOS=OFF \
  -DCOMPILER_RT_ENABLE_WATCHOS=OFF \
  -DCOMPILER_RT_ENABLE_TVOS=OFF \
  -DCOMPILER_RT_ENABLE_VISIONOS=OFF \
  -DCOMPILER_RT_ENABLE_MACCATALYST=OFF \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_INSTALL_PREFIX="$work_dir/install" \
  -DDARWIN_osx_ARCHS=arm64 \
  -DLLVM_EXTERNAL_LIT="$lit" \
  -DCOMPILER_RT_ENABLE_TEST_SUITES=tsan \
  2>&1 | tee "$work_dir/configure.log"
cmake --build "$build" --target tsan --parallel 1 2>&1 | tee "$work_dir/build-tsan.log"
cmake --build "$build" --target TsanUnitTests --parallel 1 2>&1 | tee "$work_dir/build-unit.log"
[[ -f "$runtime" ]] || { echo "TSan runtime was not produced" >&2; exit 1; }
[[ "$(lipo -archs "$runtime")" == arm64 ]] || { echo "runtime is not arm64-only" >&2; exit 1; }
runtime_sha256="$(shasum -a 256 "$runtime" | awk '{print $1}')"
source_hash_after="$(python3 "$packet_root/scripts/tree_hash.py" "$source_dir")"
[[ "$source_hash_before" == "$source_hash_after" ]] || { echo "source changed during build" >&2; exit 1; }
finish_record BUILT "$runtime_sha256"
echo "BUILT: pinned arm64 TSan runtime at $runtime"
