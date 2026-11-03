#!/usr/bin/env bash

# Shared Mac temporary-root policy. Call ck_select_temp_root before invoking
# git, cmake, clang, shasum, or any other external tool.

ck_select_temp_root() {
  local candidate mount_root mounts
  for candidate in /Volumes/S8T/tmp /Volumes/PRO-BLADE/tmp; do
    [[ -d "$candidate" ]] || continue
    mount_root="${candidate%/tmp}"
    # The directory is deliberately only a candidate until mount(8) confirms
    # the volume. It is safe as TMPDIR for this read-only mount probe.
    export TMPDIR="$candidate/.ck-tsan-errno-preflight-$$-$RANDOM"
    export TMP="$TMPDIR" TEMP="$TMPDIR"
    mounts="$(/sbin/mount 2>/dev/null || true)"
    case "$mounts" in
      *" on $mount_root ("*)
        CK_ALLOWED_TEMP_ROOT="$candidate"
        CK_MOUNTED_VOLUMES="$mounts"
        export CK_ALLOWED_TEMP_ROOT
        CK_PREFLIGHT_TMP="$(mktemp -d "$candidate/ck-tsan-preflight.XXXXXXXX")"
        export TMPDIR="$CK_PREFLIGHT_TMP" TMP="$CK_PREFLIGHT_TMP" TEMP="$CK_PREFLIGHT_TMP"
        trap 'rmdir "$CK_PREFLIGHT_TMP" 2>/dev/null || true' EXIT
        return 0
        ;;
    esac
  done
  echo "neither /Volumes/S8T nor /Volumes/PRO-BLADE is a mounted allowed volume" >&2
  return 1
}

ck_path_is_allowed() {
  local candidate mount_root
  for candidate in /Volumes/S8T/tmp /Volumes/PRO-BLADE/tmp; do
    mount_root="${candidate%/tmp}"
    case "$CK_MOUNTED_VOLUMES" in
      *" on $mount_root ("*)
        case "$1" in "$candidate"/*) return 0 ;; esac
        ;;
    esac
  done
  return 1
}

ck_require_existing_under_root() {
  local path="$1" label="${2:-path}" canonical
  [[ -n "$path" && "$path" = /* ]] || { echo "$label must be absolute" >&2; return 1; }
  [[ -e "$path" ]] || { echo "$label does not exist: $path" >&2; return 1; }
  canonical="$(python3 -I -c 'import os,sys; print(os.path.realpath(sys.argv[1], strict=True))' "$path")"
  ck_path_is_allowed "$canonical" || { echo "$label escapes mounted temporary roots: $canonical" >&2; return 1; }
  printf '%s\n' "$canonical"
}

ck_require_fresh_under_root() {
  local path="$1" label="${2:-path}" parent name canonical_parent canonical
  [[ -n "$path" && "$path" = /* ]] || { echo "$label must be absolute" >&2; return 1; }
  [[ ! -e "$path" && ! -L "$path" ]] || { echo "$label already exists: $path" >&2; return 1; }
  parent="${path%/*}"
  name="${path##*/}"
  [[ -n "$parent" && -d "$parent" ]] || { echo "$label parent missing: $parent" >&2; return 1; }
  canonical_parent="$(cd "$parent" && pwd -P)"
  canonical="$canonical_parent/$name"
  ck_path_is_allowed "$canonical" || { echo "$label escapes mounted temporary roots: $canonical" >&2; return 1; }
  printf '%s\n' "$canonical"
}
