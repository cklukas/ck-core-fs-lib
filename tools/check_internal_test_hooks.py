"""Internal hook guard regression / supplementary actual OFF-artifact audit.

Source mode is NOT a compiler or native qualification. Artifact mode consumes
real MSVC-preprocessed and dumpbin output from the reviewed whole OFF cohort;
the producer must independently bind commands, tool/image/object/source hashes
and complete TU coverage. This tool never invokes a compiler or native test.
"""
import argparse
import os
from pathlib import Path
import re

MACRO = 'CK_FS_INTERNAL_TEST_HOOKS'
GUARD = '#if defined(CK_FS_INTERNAL_TEST_HOOKS) && CK_FS_INTERNAL_TEST_HOOKS'
FAMILIES = {
 'src/files/platform/journal_root_test_faults.hpp': [
  'JournalRootFault', 'journal_root_test_fault', 'journal_root_test_worker_fault',
  'journal_root_test_worker_exception', 'JournalRootPublicationPause', 'journal_root_test_publication_pause'],
 'src/files/private_journal_membership.hpp': ['PrivateMembershipFault', 'private_membership_test_fault'],
 'src/files/verified_copy_retry.hpp': ['VerifiedCopyRetryAfterDrain', 'verified_copy_retry_test_after_drain'],
 'src/files/platform/native_sync_session_lease.hpp': ['session_epoch_before_construct_test'],
}
HELPERS = ['journal_root_fault', 'take_journal_root_worker_test_exception',
 'journal_root_failure_publication_checkpoint', 'private_membership_fault',
 'verified_copy_retry_after_drain_checkpoint', 'session_epoch_before_construct_checkpoint']
OTHER_STORAGE = ['native_test_io_observer', 'native_file_test_before', 'native_file_test_after',
 'native_close_test_before', 'native_close_test_after', 'native_close_test_role',
 'NativeIoObserver', 'NativeFileIoBefore', 'NativeFileIoAfter', 'NativeCloseBefore', 'NativeCloseAfter',
 'action_final_drain_test_observe', 'action_final_drain_test_hold',
 'NativeReadAfter', 'native_read_test_after',
 'NativeMetadataFlushBefore', 'NativeMetadataFlushAfter', 'NativeMetadataTimesAfter',
 'native_metadata_flush_before', 'native_metadata_flush_after', 'native_metadata_times_after',
 'LegacyNativeObserver', 'legacy_native_test_observer', 'legacy_native_observer_active',
 'probe_native_capture_read', 'probe_native_capture_read_completion', 'probe_native_capture_close']


def require(value, message):
    if not value:
        raise RuntimeError(message)


def native(path):
    text = os.fspath(path)
    if os.name == 'nt' and not text.startswith('\\\\?\\'):
        text = text.replace('/', '\\')
        require(Path(text).is_absolute(), 'absolute native audit input required')
        text = '\\\\?\\UNC\\' + text[2:] if text.startswith('\\\\') else '\\\\?\\' + text
    return Path(text)


def selected(text, enabled):
    """Current four guard blocks only; deliberately not a C++ preprocessor."""
    result, inside, active = [], False, True
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == GUARD:
            require(not inside, 'nested internal guard needs review')
            inside, active = True, enabled
        elif inside and stripped == '#else':
            active = not enabled
        elif inside and stripped == '#endif':
            inside, active = False, True
        else:
            require(not (inside and re.match(r'#\s*(if|ifdef|ifndef)\b', stripped)),
                    'new nested condition needs review')
            if active:
                result.append(line)
    require(not inside, 'unterminated internal guard')
    return '\n'.join(result)


def directory_profile_guard(cmake):
    # One directory-scope definition for all existing/later SDK and fixture
    # targets, without an OS branch. Recognize the reviewed two-macro union;
    # do not mistake a second, equally guarded definition for an unguarded one.
    # This is a deliberately narrow source-shape check, not a CMake interpreter.
    legacy = 'CK_FS_LEGACY_NATIVE_TEST_OBSERVERS'
    definitions = ('CK_FS_INTERNAL_TEST_HOOKS=1', legacy)
    whitespace = r'(?:\s|#[^\n]*(?:\n|$))*'
    command = r'add_compile_definitions\((?:' + '|'.join(map(re.escape, definitions)) + r')\)'
    pattern = r'if\(BUILD_TESTING\)' + whitespace + r'(?P<body>(?:' + command + whitespace + r')+)endif\(\)'
    blocks = [m.group('body') for m in re.finditer(pattern, cmake)
              if 'add_compile_definitions(' + definitions[0] + ')' in m.group('body')]
    require(len(blocks) == 1, 'uniform BUILD_TESTING directory guard missing')
    for definition in definitions:
        token = 'add_compile_definitions(' + definition + ')'
        count = cmake.count(token)
        required = 1 if definition == definitions[0] or count else 0
        require(count == required and blocks[0].count(token) == required,
                'duplicate/unguarded profile definition: ' + definition)
    for macro in (MACRO, legacy):
        require(not re.search(r'target_compile_definitions\([^)]*(PUBLIC|INTERFACE)[^)]*\b' + macro + r'\b', cmake, re.S),
                'test macro must not be an installed/public capability: ' + macro)


def source_guard(source):
    cmake = native(source / 'CMakeLists.txt').read_text(encoding='utf-8')
    directory_profile_guard(cmake)
    for relative, names in FAMILIES.items():
        text = native(source / relative).read_text(encoding='utf-8')
        require(text.count(GUARD) == 1, 'one explicit family guard required: ' + relative)
        on, off = selected(text, True), selected(text, False)
        for name in names:
            word = r'\b' + re.escape(name) + r'\b'
            require(re.search(word, on) is not None, 'ON test seam lost: ' + name)
            require(re.search(word, off) is None, 'OFF test seam survives: ' + name)
    all_headers = '\n'.join(native(source / name).read_text(encoding='utf-8') for name in FAMILIES)
    for helper in HELPERS:
        require(len(re.findall(r'\b' + helper + r'\s*\(', all_headers)) >= 2,
                'typed ON/OFF checkpoint missing: ' + helper)
    # No direct storage accesses remain at production call sites. Header
    # checkpoints retain their native error/cancellation/publication ordering.
    names = [n for values in FAMILIES.values() for n in values]
    for path in native(source / 'src').rglob('*.cpp'):
        text = path.read_text(encoding='utf-8')
        for name in names:
            require(re.search(r'\b' + re.escape(name) + r'\b', text) is None,
                    'unguarded direct production test storage access: ' + str(path) + ':' + name)


def artifact_guard(preprocessed, symbols):
    require(preprocessed and symbols, 'both actual preprocessed and symbol outputs required')
    pp = []
    for path in preprocessed:
        data = native(path).read_bytes()
        require(data and b'\0' not in data and re.search(rb'#\s*(?:line\s+)?\d+', data),
                'missing/unrecognized actual preprocessor output')
        pp.append(data)
    merged = b'\n'.join(pp)
    for helper in HELPERS:
        require(re.search(rb'\b' + helper.encode() + rb'\b', merged), 'incomplete seam-header PP coverage: ' + helper)
    for path in symbols:
        data = native(path).read_bytes()
        require(data and b'\0' not in data and b'COFF SYMBOL TABLE' in data,
                'missing/unrecognized actual COFF symbol output; no empty/LTCG absence proof')
    forbidden = [n for values in FAMILIES.values() for n in values] + OTHER_STORAGE
    for path in [*preprocessed, *symbols]:
        data = native(path).read_bytes()
        for name in forbidden:
            require(not re.search(rb'\b' + name.encode() + rb'\b', data),
                    'test callback state/type survives in actual OFF artifact: ' + str(path) + ':' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--preprocessed', action='append', default=[], type=Path)
    parser.add_argument('--symbols', action='append', default=[], type=Path)
    args = parser.parse_args()
    source_guard(args.source)
    if args.preprocessed or args.symbols:
        artifact_guard(args.preprocessed, args.symbols)
        print('OFF_ARTIFACT_CONTENT_CHECK_PASS_REQUIRES_REVIEWED_PRODUCER_AND_COHORT_COVERAGE')
    else:
        print('SOURCE_GUARD_PASS_NOT_COMPILER_OR_NATIVE_QUALIFICATION')


if __name__ == '__main__':
    main()
