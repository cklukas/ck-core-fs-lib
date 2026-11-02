# Conflict resolution and reusable choices

Status: required backend/frontend contract. This page distinguishes desired
controls from currently qualified execution capabilities. A normal planned
copy/update is covered by the selected profile and one plan confirmation;
users do not need to approve every changed file.

## Reference behavior

[Robocopy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
offers job-wide selection switches for older/newer, changed, extra and missing
files; explicit metadata selections; retry limits; and preview logging. Mirror
adds destination removal. These are command-line policies rather than an
interactive per-file conflict dialog.

[rsync](https://rsync.samba.org/ftp/rsync/rsync.1) separates quick comparison
from checksum comparison. Update protects newer receiver files; ignore-existing
implements missing-only transfers. It also offers backup directories, dry-run,
itemized changes, filters and deletion limits. Its update rule copies equal-time
files whose sizes differ; this is a distinct choice from strictly-newer-only.

[Midnight Commander](https://source.midnight-commander.org/man/mc.html)
provides overwrite/skip, overwrite-all/none, newer-source, size-based rules,
zero-length protection, and retry/abort controls. Its append/reget controls need
stronger identity/content qualification than a general overwrite rule.

[Total Commander](https://www.ghisler.com/advanced.htm) shows comparison results
and proposed directions before synchronization, including equal-date differences.
Its author also documents an
[overwrite-all-older choice](https://www.ghisler.ch/board/viewtopic.php?t=52754).
Commander-style overwrite/skip/all controls are the interaction reference;
the precise historical Norton Commander version-specific menu has not been
verified against an original vendor manual.

## Required resolution choices

| User choice | Core meaning | Important boundary |
| --- | --- | --- |
| Ask / leave unresolved | Retain both versions and defer the affected row | Independent reviewed rows can continue |
| Use source / replace target | Prefer the incoming object | One-way direction is explicit; replacement retention is selectable |
| Keep target / skip existing | Preserve the existing target; copy missing objects | A skipped move retains its source |
| Use newest | Prefer the later qualified modification time | Ties, missing times and precision ambiguity use a visible fallback |
| Use source if newer | Strict source-newer update | Target-newer objects are protected |
| Source newer or size differs at equal time | rsync-style update variant | Different from strictly-newer-only |
| Replace if size differs | Replace known unequal sizes | Same size makes no content-equality claim |
| Prefer larger / prefer smaller | Select by known logical size | Advanced heuristic; not a quality/content guarantee |
| Keep both: rename incoming | Preserve target and add a unique incoming name | Preview exact names and recheck native alias/collision rules |
| Keep both: rename existing | Retain old target under a unique name, publish incoming | Journal and verify both resulting objects |
| Rename manually | Supply a reviewed new destination name | Revalidate before no-replace publication |
| Skip / skip matching | Leave affected objects unchanged | Remains skipped/pending in results and two-way baseline |
| Compare / merge | Inspect content; optionally stage a merged result | Merged output must pass fresh identity and metadata verification |
| Merge folders | Combine child plans | Does not decide child file conflicts |
| Retry / retry matching failures | Reattempt a qualified recoverable failure | Bounded attempts/backoff; no blind replay after ambiguous publication |
| Cancel | Stop at safe boundaries and retain recovery evidence | Partial completed work is reported |

Provide **Do not replace nonempty files with empty files** independently of
the winning rule. Let users require **preserve replaced versions**, choose
retention storage, and preview retained names. Missing retention capability,
disk-full and retention failures must block a rule that requires a backup.

In two-way mode use **Keep Left**, **Keep Right**, **Use newest**, **Keep Both**
and **Skip**; source/target labels would conceal the direction. Edit/delete
conflicts offer **Restore deleted version**, **Keep edited version**, or
**Delete edited version** with explicit version retention. Required metadata
differences remain relevant even when content is equal.

## Conflict classes

The backend classifies existing same-name regular files (newer/older/equal-time,
size difference and verified content difference), independently changed versions,
edit/delete, directory-delete/changed-descendant, file/directory mismatch,
link/reparse mismatch, case/normalization aliases, rename collisions, hard-link
effects, required metadata/security differences, stale identities/plans,
unavailable providers, access/read-only/locked objects, disk space/quota,
and interrupted or ambiguous publication. Those last operational failures are
reported separately from content choices.

Use-source, keep-target, time and size rules apply only to compatible,
qualified object classes. A folder merge cannot silently authorize deleting a
different object type. Destructive type replacement, deletion propagation,
security loss and privilege changes each need their own explicit policy.
Unknown/unreadable/offline is never absence; a bulk content rule cannot override
identity uncertainty, mount escapes, stale plans, failed inventory or an
ambiguous commit. Such rows retain a typed reason and permitted retry/review
actions. Arbitrary append/reget is not part of ordinary conflict resolution;
resume requires identity-verified journal/content evidence.

## Scope, preview and persistence

Each choice supports **this item**, **selected rows**, **all matching conflicts
in this folder/subtree**, and **all matching conflicts in this job**. Matching
means a named conflict class and applicable object kind/direction, with optional
path/type filters. The UI states the affected count, overwritten bytes, retained
versions, deletions and unresolved rows before applying the rule. A job-wide
choice is allowed, but applies only to its declared eligible classes.

After one representative review, a user can select a rule and apply it to the
remaining matching conflicts. Precedence is explicit: item decision, selected
scope override, then job/profile rule. Equal-time/size ties have an explicit
fallback: Ask, Keep target/side, or Keep Both. Contradictory same-priority rules
require correction rather than depending on incidental traversal order.

The plan records the chosen rule, matched rows, consequences and review receipt.
Execution revalidates each row against that receipt. Newly discovered or changed
objects require an updated plan; a previously scoped rule can propose the same
decision, but cannot reuse stale mutation authority. Saved profiles store user
preferences and scopes; they do not store permission to delete or overwrite
objects from future scans. A rule editor supports inspecting and removing
active rules, and a results page explains automatic choices per row.

The frontend must expose every supported choice above through setup, preview
and in-progress conflict controls. Unsupported provider operations are disabled
with the backend's reason. The shared core evaluates rules and issues receipts;
frontends supply choices and render results.
