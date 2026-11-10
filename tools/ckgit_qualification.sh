#!/bin/sh
# ck-git Linux runner entry point; every lane keeps one build/test process.
set -eu
case "$(uname -s)" in Linux) ;; *) echo 'ck-git backend qualification requires a Linux runner' >&2; exit 1 ;; esac
lane=${1:?select normal-on, normal-off, asan-ubsan or tsan}
case "$lane" in normal-on|normal-off|asan-ubsan|tsan) ;; *) echo 'Unknown qualification lane' >&2; exit 1 ;; esac
: "${TMPDIR:?runner must provide an explicit temporary directory}"
case "$TMPDIR" in /*) ;; *) echo 'Runner temporary directory must be absolute' >&2; exit 1 ;; esac
: "${CKGIT_COMMIT:?runner must provide the source commit}"
test "$(git rev-parse HEAD)" = "$CKGIT_COMMIT"
task=$(mktemp -d "$TMPDIR/ckfs-$lane.XXXXXXXX")
mkdir "$task/tmp" "$task/native"
export TMPDIR="$task/tmp" TMP="$task/tmp" TEMP="$task/tmp"
export CMAKE_BUILD_PARALLEL_LEVEL=1 CTEST_PARALLEL_LEVEL=1 MAKEFLAGS=-j1 PYTHONDONTWRITEBYTECODE=1
# A pathname on ext4 is a prerequisite, not native capability authority.
# The fixtures independently qualify their held root, mount and ownership.
test "$(findmnt -T "$task/native" -no FSTYPE)" = ext4
python3 tests/run_private_scope_mounts.py --probe "$task/native"
browser=ON
sanitizer=none
shared=OFF
case "$lane" in
  normal-off) browser=OFF ;;
  asan-ubsan)
    sanitizer=address-undefined
    export ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
    ;;
  tsan)
    sanitizer=thread
    shared=ON
    export TSAN_OPTIONS=halt_on_error=1
    selected=false
    for version in 23 22 21 20 19; do
      if command -v "clang-$version" >/dev/null && command -v "clang++-$version" >/dev/null; then
        CC="clang-$version" CXX="clang++-$version"
        export CC CXX
        selected=true
        break
      fi
    done
    test "$selected" = true
    "$CXX" --version
    ;;
esac
artifacts="$PWD/ci-$lane"
test ! -e "$artifacts"
mkdir "$artifacts"
# Deliberately bounded diagnostics, not a build-tree archive. The runner
# currently packs artifacts only after a successful job; on failure the
# bounded console excerpts below are best-effort (subject to its log cap).
retention_errors=0
retention_bytes=0
retention_error() {
  retention_errors=$((retention_errors + 1))
  printf 'DIAGNOSTIC_RETENTION_ERROR: %s\n' "$1" >&2
}
retain_one() {
  retain_source=$1
  retain_destination=$2
  test -f "$retain_source" || return 0
  retain_size=$(wc -c < "$retain_source") || {
    retention_error "cannot size $retain_source"
    return 0
  }
  # 16 MiB/file and 64 MiB in total; never silently truncate retained files.
  if test "$retain_size" -gt 16777216 || test $((retention_bytes + retain_size)) -gt 67108864; then
    retention_error "bounded retention refused $retain_source ($retain_size bytes)"
    return 0
  fi
  if ! mkdir -p "$(dirname "$retain_destination")"; then
    retention_error "cannot create diagnostic destination for $retain_source"
    return 0
  fi
  if ! cp -- "$retain_source" "$retain_destination"; then
    retention_error "cannot retain $retain_source"
    return 0
  fi
  retention_bytes=$((retention_bytes + retain_size))
}
retain_records() {
  if ! printf 'lane=%s\nbrowser=%s\nsanitizer=%s\nshared_thread_runtime=%s\nCC_environment=%s\nCXX_environment=%s\n' \
      "$lane" "$browser" "$sanitizer" "$shared" "${CC-<CMake default>}" "${CXX-<CMake default>}" \
      > "$artifacts/compiler-selection.txt"; then
    retention_error 'cannot record compiler selection; actual configured identities are in CMake compiler records'
  fi
  if test -d "$task/qualification"; then
    for record in "$task/qualification/qualification.log" "$task/qualification"/source-*.sha256; do
      retain_one "$record" "$artifacts/$(basename "$record")"
    done
    for tree in build consumer layer-consumers; do
      tree_root="$task/qualification/$tree"
      for record in CMakeCache.txt compile_commands.json CTestTestfile.cmake \
          CMakeFiles/CMakeConfigureLog.yaml CMakeFiles/CMakeOutput.log CMakeFiles/CMakeError.log \
          Testing/Temporary/LastTest.log Testing/Temporary/LastTestsFailed.log \
          Testing/Temporary/CTestCostData.txt; do
        retain_one "$tree_root/$record" "$artifacts/diagnostics/$tree/$record"
      done
      compiler_directories=0
      for compiler_directory in "$tree_root"/CMakeFiles/[0-9]*; do
        test -d "$compiler_directory" || continue
        compiler_directories=$((compiler_directories + 1))
        if test "$compiler_directories" -gt 4; then
          retention_error "too many compiler-identity directories under $tree_root"
          break
        fi
        for record in CMakeCCompiler.cmake CMakeCXXCompiler.cmake CMakeSystem.cmake; do
          retain_one "$compiler_directory/$record" \
            "$artifacts/diagnostics/$tree/CMakeFiles/$(basename "$compiler_directory")/$record"
        done
      done
    done
  fi
}
finish_qualification() {
  qualification_status=$?
  trap - EXIT
  set +e
  retain_records
  printf 'qualification_exit=%s retention_errors=%s retained_bytes=%s\n' \
      "$qualification_status" "$retention_errors" "$retention_bytes" >&2
  if test "$qualification_status" -ne 0; then
    # At most 128 KiB plus short headings. Preserve original failing status;
    # printing/staging diagnostics never turns failed qualification green.
    if test -f "$task/qualification/qualification.log"; then
      printf '\n--- failing qualification stages (last 16 KiB) ---\n' >&2
      tail -c 16384 "$task/qualification/qualification.log" >&2
    fi
    for tree in build consumer layer-consumers; do
      tree_root="$task/qualification/$tree/Testing/Temporary"
      if test -f "$tree_root/LastTestsFailed.log"; then
        printf '\n--- %s failed tests (last 4 KiB) ---\n' "$tree" >&2
        tail -c 4096 "$tree_root/LastTestsFailed.log" >&2
      fi
      if test -f "$tree_root/LastTest.log"; then
        printf '\n--- %s test log (last 32 KiB) ---\n' "$tree" >&2
        tail -c 32768 "$tree_root/LastTest.log" >&2
      fi
    done
  elif test "$retention_errors" -ne 0; then
    qualification_status=1
  fi
  exit "$qualification_status"
}
trap finish_qualification EXIT
cmake "-DQUALIFICATION_OUTPUT=$task/qualification"   "-DQUALIFICATION_BROWSER=$browser"   "-DQUALIFICATION_SANITIZER=$sanitizer"   "-DQUALIFICATION_SHARED_THREAD_RUNTIME=$shared"   "-DQUALIFICATION_NATIVE_TEST_ROOT=$task/native"   -P tools/qualification.cmake
case "$lane" in
  normal-*)
    git archive --format=tar --output="$task/baseline.tar" "$CKGIT_COMMIT"
    python3 tools/platform_qualification.py       --archive "$task/baseline.tar" --revision "$CKGIT_COMMIT"       --prefix "$task/qualification/install"       --baseline-record "$task/qualification/qualification.log"       --output "$artifacts/platform"
    ;;
esac
