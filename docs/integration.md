# Integration

## ckUtilities

The ckUtilities root CMake project adds this checkout as a sibling:

```sh
cmake -S /path/to/ckUtilities -B build \
  -DCK_CORE_FS_LIB_SOURCE_DIR=/path/to/ck-core-fs-lib
```

The default is `../ck-core-fs-lib` relative to the ckUtilities checkout. The
ckVision-based frontend remains in ckUtilities; it links the `ck_files_core`
and `ck_files_platform` targets from this project.

## CDE

CDE should consume the installed C ABI or a CMake-built shared library. Its
adapter owns Motif/UI integration, Trash policy, metadata presentation,
conflict dialogs, and Autotools packaging. It must not duplicate native path
reopening or operation safety logic.

The ABI deliberately keeps allocation and lifetime rules explicit so a CDE
adapter can translate snapshots and structured errors into its own status
bar/event loop without crossing a C++ exception or callback boundary.

CDE currently keeps qualified SDK 0.3/`3972516` frozen and FS Apply disabled.
dtfile's legacy worker-owned conflict/Replace path is a compatibility contract;
its best-effort backup does not claim durable publication, retention or restart
safety. Migrating it requires the proposed [held entry and durable replacement
contract](native-contracts.md#proposed-cde-entry-and-replacement-contract), a
coherent qualified installed SDK, and an explicit downstream admission. Do not
borrow newer API headers or treat local SAME_ENTRY flags as backend authority.
