# Architecture

The library is intentionally split into three layers.

| Layer | Responsibility | Consumers |
| --- | --- | --- |
| Native core | Handles, identities, names, metadata, directory cursors, copy/move jobs, journals, recovery, and platform adapters | C++ clients and the C ABI |
| C ABI | Opaque handles, explicit allocation, structured errors, snapshots, and cancellation | CDE and non-C++ clients |
| Frontend adapter | UI commands, panes, dialogs, policy, trash UX, and status text | ckUtilities or CDE |

`ck-core-fs-lib` owns the first two layers. The ckUtilities checkout keeps the
ckVision frontend and links the exported C++ backend targets from the sibling
checkout selected by `CK_CORE_FS_LIB_SOURCE_DIR`.

No backend callback runs on a UI thread. A client starts a job, polls a
snapshot, and decides when it is safe to release the opaque job handle. This
keeps callback lifetimes out of the ABI and lets each frontend integrate with
its own event loop.

The backend uses held parent/entry identities rather than reopening a path
from display text. On Windows the native boundary is wide-character and
extended-length aware; on POSIX it preserves byte-native names.
