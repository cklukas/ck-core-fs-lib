# C++ API

The build exports `ck::ck_core_fs_engine` and `ck::ck_files_platform` as the
implementation targets, with compatibility aliases `ck_file_engine` and
`ck_files_core` for the ckUtilities frontend during the extraction period.

Native headers live under `src/files` in the source checkout and are installed
under `include/ck-core-fs`. They expose the identity-aware cursor and operation
types used by the existing ckUtilities file frontend. The C ABI is implemented
on top of these same targets, so there is one filesystem implementation and
one set of platform safety behavior.

Prefer the C ABI for a language or process boundary. Use the C++ targets only
when the consumer can follow the library's C++ toolchain and ABI policy.
