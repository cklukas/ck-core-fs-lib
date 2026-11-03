# Provenance and licensing

## Source pin

- Upstream project: LLVM compiler-rt / LLVM Project
- Release/tag: `llvmorg-23.1.4`
- Exact source commit: `7a941dfb2877a0b8cf30323fefa85ad019e0b0f5`
- Audited checkout: `/Volumes/S8T/tmp/ck-core-fs-hardening.6j2hcco1/tsan-runtime-qualification-v1/llvm-source`
- Source checkout was inspected at the exact commit; the working-tree
  changes are represented by the two packet patches rather than by a source
  checkout copy.

The production patch changes exactly these five files:

1. `compiler-rt/lib/tsan/rtl/tsan_platform.h`
2. `compiler-rt/lib/tsan/rtl/tsan_platform_mac.cpp`
3. `compiler-rt/lib/tsan/rtl/tsan_rtl_thread.cpp`
4. `compiler-rt/lib/tsan/rtl/tsan_rtl.h`
5. `compiler-rt/lib/tsan/rtl/tsan_rtl_access.cpp`

The test patch adds the exact-shadow unit test, registers it in the existing
TSan unit target, and adds Darwin native-errno and libdispatch controls.
There is no public runtime ABI, `ThreadState` layout, clock, shadow encoding,
ignorelist, suppression, or safety-check weakening change.

Packet patch digests:

- `patches/0001-darwin-arm64-native-errno-shadow-lifetime.patch`:
  `f43f79b92c0aae3bf5321fc81379253565923d5ba9336132c3e7c9095ee89d12`
- `patches/0002-tests.patch`:
  `0a4cacaeba378a6000343062f3259e84becf5bac1a6e54afbfa4d55bd5fbb894`

## Qualification provenance

The source records were captured under:

`/Volumes/S8T/tmp/ck-core-fs-hardening.6j2hcco1/tsan-runtime-qualification-v1`

The matching patched arm64 runtime was built with the pinned source and
the exact toolchain settings recorded in `records/patched-record.json`: the
Homebrew LLVM 23.1.4 `clang`/`clang++` drivers, CMake package
`/opt/homebrew/Cellar/llvm/23.1.4/lib/cmake/llvm`, target
`arm64-apple-darwin27.2.0`, `CMAKE_OSX_ARCHITECTURES=arm64`, deployment target
13.0, compiler-rt Release, and one build worker. The durable runner verifies
the compiler version, resource directory, and LLVM CMake package contents at
runtime instead of trusting these paths.
The verified runtime digest is:

`124e6acd2266a0526f9184c852ca6f3270997378bdbcedc22c72765b4d155890`

The normal Mach-O unit packaging was qualified by
`records/unit-dynamic-v3-record.json`; its status records focused exact-shadow
controls and the complete 45-test unit executable passing, with eight upstream
unit tests disabled by the existing platform/test configuration and therefore
not counted as a stock-suite pass.

The controls records cover detached and joined native errno reuse, TLS race
controls, finished-thread and signal-errno controls, DTLS, GCD worker startup
and reuse, and the deliberate foreign errno-pointer races. A deliberate race
must still report TSan status 66; this is an invariant, not a failure.

## License

The upstream license is preserved verbatim in
`licenses/LLVM-LICENSE.TXT`. The new test sources carry the LLVM Apache 2.0
with LLVM exceptions headers. This packet does not relicense LLVM or claim
upstream acceptance.
