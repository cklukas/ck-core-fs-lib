# Cached Tree name-side feedback

`ckfet_name_feedback_get_v1(job, generation, row_id, choice, &feedback)` returns
an additive output record. Existing v1 option, row, snapshot and receipt layouts
are unchanged. `choice` accepts `CKFET_KEEP_BOTH_INCOMING`,
`CKFET_KEEP_BOTH_TARGET`, `CKFET_RENAME`, or
`CKFET_NAME_CHOICE_SELECTED` for the actual last assessed decision.

Incoming KeepBoth and Rename require `CKFET_NAME_INCOMING`; Target KeepBoth
requires `CKFET_NAME_TARGET`, genuine worker-qualified retention, and qualified
source preservation. Source preservation follows the existing native assessment
predicate: required metadata is known under the selected ownership contract or
the caller explicitly consented to metadata loss. A legacy `allowed_choices`
Target bit or retention bit alone does not establish this eligibility.

`required_side` describes the named choice. `allowed_sides` is zero when the
worker could not qualify that choice; `capability_reason` explains why.
`selection_reason` separately explains the submitted selection, such as
`WRONG_SIDE`, `AWAITING_NAME`, or `NAME_NOT_ALLOWED`. Both reasons may apply:
a Target choice can have the wrong submitted Incoming side while retention is
unavailable. `decision_state` and `decision_reason` retain the core rule result.
The frontend must not recompute policy or reinterpret a display path.

Read `assessment_command_id` after the corresponding worker command outcome.
Zero identifies initial assessment. While a command is queued, the previous
assessment remains visible. Generation mismatch returns `CKFE_API_STALE_PLAN`;
other failures also clear the full output object. Pass a complete
`ckfet_name_feedback_v1` output object.

The getter copies a fixed worker cache under its existing mutex. It performs no
native I/O, name probing, rule evaluation or allocation. AVAILABLE describes
proposal eligibility in that assessment. It grants no execution authority and
makes no claim that the requested variant name is absent or acceptable. Native
review, frozen receipt binding and fresh execution checks remain mandatory.
Compare assessments report `REPORT_ONLY` for named mutation capabilities.

The isolated development qualification covers pure core policy, actual Linux native C
worker review/cached polling, strict C11 linkage and the ELF export. The native
test inventories and reviews real files, then cancels and drains without
publication. Allocation rejection and wrapped filesystem calls are armed only
on the polling thread. The strict-unknown-source plus genuine-retention case
is a core policy test; it is not a Windows native execution qualification.
Windows, Darwin and sanitizer qualification remain outstanding.

The private `ReviewedTreeFacts` and item layouts changed. Rebuild every affected
translation unit from coherent headers; do not combine the new headers with an
older SDK. The existing export map exports the new `ckfet_*` symbol. See the
[development validation record](validation-2026-11-03-development.md) for the
qualified source cohort and remaining combined-platform gates.
