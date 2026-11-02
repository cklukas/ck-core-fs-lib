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
