# Safety contract

The following rules are part of the API contract:

- Preserve exact names and identities; do not reopen an operation from a path
  reconstructed from display text.
- Hold and revalidate parents and entries across mutation phases.
- Do not delete an existing destination before a verified replacement is ready.
- For cross-filesystem moves, retain the source if completion is not proven and
  make recovery evidence actionable.
- Treat concurrent changes, denied access, unsupported metadata, and recovery
  requirements as structured outcomes, never as silent success.
- Use bounded I/O and handle short reads, short writes, EINTR-equivalent
  retries, cancellation, synchronization, and close failures.
- On Windows, use wide/native handles and extended-length paths for ordinary,
  UNC, long, and adversarial names. No legacy narrow API is a final I/O path.
- Keep all callbacks out of UI threads; polling and event draining are the
  frontend integration mechanisms.

These constraints apply equally to future delete, rename, Trash, archive, and
volume operations.
