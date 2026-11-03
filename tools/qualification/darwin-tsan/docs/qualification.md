# Technical and qualification notes

## Bug and correction

On Darwin arm64 in LLVM 23.1.4, the generic TSan stack/TLS discovery path can
report a zero-sized TLS range while Darwin's native `errno` object returned by
`__error()` remains a live four-byte object outside that range. Thread start
and finish consequently do not establish or retire shadow lifetime for that
object. A worker that only writes its own errno can then reuse native storage
without a corresponding TSan lifetime record.

The correction tracks the exact `__error()` address and four-byte lifetime at
Darwin thread start/finish. The private shadow helpers operate on exact byte
masks, split ranges at shadow-cell boundaries, use the existing slot lock, and
use compare/exchange when clearing or claiming a shadow slot. They fail closed
for rodata, freed markers, the reserved `0x81` free-access encoding,
non-contiguous masks, malformed records, and unavailable shadow capacity.
They do not reset unrelated byte history, alter clocks, or add a public ABI.
Fibers are excluded because they share the operating-system thread's native
errno storage.

The lifecycle hooks are deliberately platform/lifecycle-owned and are kept in
the five-file production patch. The tests remain separate so reviewers can
apply the runtime correction independently.

## Reproducible build recipe

Use a fresh work directory under mounted `/Volumes/S8T/tmp` or
`/Volumes/PRO-BLADE/tmp` and a clean checkout at the exact source
pin. The packet script first confirms that one of those volumes is actually
mounted, sets `TMPDIR`, `TMP`, `TEMP`, and the Clang module cache under the
selected volume, then accepts canonical source/work paths on either mounted
permitted volume. It checks index, tracked, and untracked state, stages present
tracked files while excluding caches (so a shallow
or sparse source checkout does not trigger an external Git fetch), applies
both patches with `git apply --no-index`, and refuses to reuse an existing
work directory or output.

```sh
packet=/absolute/path/to/ck-core-fs-lib/tools/qualification/darwin-tsan
source=/path/to/llvm-source-at-7a941dfb2877a0b8cf30323fefa85ad019e0b0f5
work=/Volumes/S8T/tmp/ck-core-fs-tsan-errno-rebuild-v1
"$packet/scripts/configure-build.sh" --source "$source" --work "$work"
```

For a no-compile preparation check, add `--prepare-only`. It stages and
patches the pinned source, verifies the toolchain pin, captures source hashes,
and writes `configure-build.json` with status `PREPARED`; it does not invoke
CMake or compile anything. It does query the selected compiler for its
version and resource directory so a preparation record cannot silently pin an
unverified toolchain.

The configure is arm64-only and matches the qualified settings:

- LLVM/Clang 23.1.4, verified from both driver versions and the Clang 23
  resource directory;
- LLVM CMake package version 23.1.4, verified from `LLVMConfig.cmake`;
- `CMAKE_OSX_ARCHITECTURES=arm64` and `DARWIN_osx_ARCHS=arm64`;
- deployment target 13.0;
- compiler-rt sanitizers limited to TSan;
- Release build, one build job;
- compiler-rt unit tests enabled and the TSan unit target built.

The build script does not run tests. It records start/end/duration, source commit and
tree identity, patch and control-input hashes, compiler/CMake/resource hashes,
and the produced runtime hash in `configure-build.json`. Set
`LLVM_CMAKE_DIR`, `CC`, and `CXX` explicitly if the pinned toolchain is staged
elsewhere; every override is still version-checked before CMake runs.

## Focused controls

After a successful build, run:

```sh
"$packet/scripts/run-controls.sh" --work "$work"
```

The runner uses the built matching runtime through the compiler's resource
directory. It creates fresh control/resource/log directories, sets explicit
`TSAN_OPTIONS=halt_on_error=1:abort_on_error=0:exitcode=66`, checks the runtime
hash before and after, and requires `DYLD_PRINT_LIBRARIES` to name the actual
configured TSan image. It checks both positive and negative controls:

- detached and joined workers: exit 0, no race report;
- native worker foreign-pointer race: exit 66 with a TSan data-race report;
- GCD worker startup/reuse: exit 0;
- foreign main-thread errno-pointer race: exit 66 with a TSan data-race report;
- upstream TLS, finished-thread, signal-errno, DTLS, and detach controls.

No ignorelist, `no_sanitize`, suppression, or `DYLD_INSERT_LIBRARIES` path is
used. Expected race exit 66 is asserted explicitly.

## Unit packaging: normal Mach-O dependency

The official TSan unit objects are linked into one temporary dynamic image.
The thin C loader is then linked with the image path as a normal input:

```sh
clang -std=c11 -O1 -g tests/unit-loader.c \
  "$work/NativeTlsUnitRuntime.dylib" \
  -o "$work/NativeTlsUnitLoader"
otool -L "$work/NativeTlsUnitLoader" | grep NativeTlsUnitRuntime.dylib
```

That link creates an `LC_LOAD_DYLIB` dependency, so dyld loads the matching
runtime before `main` and gtest death-test re-exec inherits the same dependency.
The runner sets `CK_TSAN_UNIT_IMAGE` only so the loader can resolve and verify
the image with `dlopen`; it does not use `DYLD_INSERT_LIBRARIES` or a preload
workaround. Run the recipe with:

```sh
"$packet/scripts/run-unit-mach-o.py" --work "$work"
```

The script verifies the generated Ninja linker line has the exact unit-object
working directory, refuses ambiguous commands, verifies the loader's
`LC_LOAD_DYLIB`, creates only fresh image/loader/log outputs, and runs with
explicit `TSAN_OPTIONS` and no preload variable. It records source,
toolchain, runtime, unit-image, loader, control-input, log, start/end, and
duration data. It then runs the focused `NativeTlsShadow.*` tests and the
complete built unit executable. The qualified v3 record reports focused
exact-shadow controls and 45 complete unit tests passing; eight
upstream-disabled tests are explicitly excluded from the pass count.

## Qualification boundary

The evidence qualifies the pinned Darwin arm64 runtime and the focused
native-errno behavior under the matching LLVM 23.1.4 toolchain. It is not a
claim that an uninstrumented or mismatched runtime is safe, nor a stock LLVM
23.1.4 full-suite pass. A future upstream submission still needs current
LLVM review, current Darwin coverage, and a fresh full-suite result.
