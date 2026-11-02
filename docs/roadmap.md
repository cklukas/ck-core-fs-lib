# Roadmap

The extraction is intentionally incremental:

1. Publish the headless C++ implementation and the exception-free C ABI with
   copy/move/inspection, packaging, and independent CI.
2. Add typed progress events, conflict decisions, recursive copy, rename, and
   delete adapters without changing the held-identity contract.
3. Add recovery inspection/reconciliation and capability/Trash adapters for
   CDE and other frontends.
4. Add ABI compatibility policy, versioned packages, sanitizer/race jobs, and
   Windows long-path/UNC/UTF-16/reparse conformance suites.

The project name and install namespace are fixed as `ck-core-fs-lib` so the
future GitHub repository and downstream references remain stable.
