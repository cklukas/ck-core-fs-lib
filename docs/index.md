# ck-core-fs-lib

`ck-core-fs-lib` is the headless filesystem engine shared by the ckUtilities
ckVision frontend, CDE, and future clients. It owns native file identity,
byte-native names, safe directory access, journaled mutation, recovery
evidence, and cross-platform path handling. It does not own a UI, terminal,
event loop, or frontend policy.

The project exposes two layers over the same implementation:

- a C++ target for native clients that already use the backend types; and
- an exception-free opaque-handle C ABI for CDE, other languages, and stable
  frontend adapters.

The current consumable revision includes held-handle directory and entry
inspection plus journaled regular-file copy and move jobs with polling and
cooperative cancellation. The lower-level backend already contains the
identity, recovery, recursive inventory, and deletion primitives needed for
the next ABI slices.

See [architecture](architecture.md) for the ownership boundary, [safety](safety.md)
for the non-negotiable filesystem rules, and [the C API](c-api.md) for the
public integration surface.
