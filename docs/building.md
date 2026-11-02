# Building and testing

The library is a standalone CMake project:

```sh
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build --parallel 6
ctest --test-dir build --output-on-failure
cmake --install build --prefix install
```

The C ABI smoke test is compiled as a C translation unit and verifies that the
installed-facing header remains C-compatible. Platform CI builds and tests the
same project on Linux, macOS, and Windows. Add path, identity, cancellation,
and reparse/security regression tests before changing a native boundary.

## Independent installed-C capability gates

`tests/contract-consumer` is a separate C-only project that consumes the
installed package. It keeps fourteen behavioral contracts, including preservation
success gates that currently fail on unsupported scopes/providers. It is not
part of the default passing core CTest set, and its failures must not be
converted to expected passes. See its README for an explicit build/fixture
directory invocation. Use approved temporary volumes on macOS and the mandatory
V: development drive on the Windows workstation.

The Complete-metadata success gates remain unresolved. Ordinary local-file
success is independently established on Linux ARM64; the current macOS fixture
is refused for opaque `com.apple.provenance` metadata. Cancellation tests using
small files qualify only their observed cancellation/completion outcomes, not
latency during blocked native I/O.
