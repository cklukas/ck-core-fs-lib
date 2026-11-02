# Roadmap

The extraction is intentionally incremental. The order is a contract with CDE
and dtfile:

1. **Foundation:** publish the headless C++ implementation and exception-free C
   ABI with held inspection, journaled regular copy/move, packaging, and
   independent CI.
2. **Preservation gate:** add the versioned metadata policy and provider
   capability inventory. Qualify ordinary permissions/timestamps first, then
   ownership semantics, ACL/security xattrs/labels, and provider metadata with
   held-identity apply and post-publication verification. Strict copy must
   refuse unsupported classes with typed review-needed diagnostics.
3. **Planning:** add bounded recursive inventory and a non-mutating declarative
   planner for Copy, Safe Move, Update, Copy-missing-only, One-way Sync,
   Compare-only, and Dry-run. Add explicit comparison modes, filters, link and
   filesystem-boundary policies, stable decision tokens, and typed reasons.
4. **Reviewed mutation:** add conflict receipts, batch rename preview, mkdir,
   journaled recursive execution, verification, retry/backoff, cancellation,
   and partial/recovery terminal summaries.
5. **Destructive and recovery adapters:** add Mirror with separately reviewed
   destination deletion, Trash/restore, permanent delete, durable recovery
   inspection, bounded events, and provider capability adapters. Two-way sync
   requires a persistent baseline and conflict model.
6. **Qualification:** add ABI compatibility policy, versioned packages,
   sanitizer/race jobs, and Windows long-path/UNC/UTF-16/reparse conformance
   suites for every new boundary.

The project name and install namespace are fixed as `ck-core-fs-lib` so the
future GitHub repository and downstream references remain stable.
