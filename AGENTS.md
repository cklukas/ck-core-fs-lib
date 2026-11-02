# ck-core-fs-lib agent instructions

This repository is the headless filesystem backend shared by ckUtilities,
CDE, and other frontends. Keep the public boundary independent of ckVision,
Turbo Vision, Motif, STL types, and UI-thread callbacks.

Windows filesystem code must use modern wide-character/native handle APIs and
must not rely on legacy `MAX_PATH`-limited path handling. Convert validated
absolute DOS and UNC addresses to extended-length form (`\\?\\` /
`\\?\\UNC\\`) at the Win32 boundary, or use a handle-relative native API.
Do not add narrow Win32 final I/O, `std::fstream`, or `std::filesystem` final
I/O for long or adversarial paths. Preserve identity, reparse, sharing,
access, cancellation, and error-state checks. Every replacement needs tests
for ordinary and long paths, UNC namespaces, exact UTF-16 names, and relevant
reparse/security behavior.

The C ABI is exception-free. Ownership and callback/job lifetimes must be
explicit in `include/ck_file_engine.h`; never expose C++ or UI types there.
