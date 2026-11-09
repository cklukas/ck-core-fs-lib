"""Ordinary-user isolated bind aliases; exit 77 is unqualified, never PASS."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    if len(sys.argv) != 3:
        return 1
    if sys.platform != 'linux' or os.getuid() == 0 or os.getuid() != os.geteuid():
        print('UNQUALIFIED: ordinary Linux host identity required')
        return 77
    binary, scratch = Path(sys.argv[1]).absolute(), Path(sys.argv[2])
    if not scratch.is_absolute() or not binary.is_file():
        return 1
    unshare = shutil.which('unshare')
    if not unshare:
        return 77
    scratch.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CK_RETRY_SCOPE_HOST_UID=str(os.getuid()),
               CK_RETRY_SCOPE_HOST_USER_NS=str(os.stat('/proc/self/ns/user').st_ino),
               CK_RETRY_SCOPE_HOST_MOUNT_NS=str(os.stat('/proc/self/ns/mnt').st_ino))
    isolation = [unshare, '--user', '--map-root-user', '--mount', '--propagation', 'private']
    probe = subprocess.run(isolation + ['/bin/true'], capture_output=True, text=True)
    if probe.returncode:
        print('UNQUALIFIED: ' + probe.stderr.strip())
        return 77
    for mode in ('source-bind-alias', 'candidate-bind-alias', 'destination-bind-alias',
                 'source-bind-alias-second', 'candidate-bind-alias-second', 'destination-bind-alias-second'):
        with tempfile.TemporaryDirectory(prefix='retry-scope-' + mode + '-', dir=scratch) as fixture:
            env.update(TMPDIR=fixture, TMP=fixture, TEMP=fixture)
            result = subprocess.run(isolation + [str(binary), fixture, mode], env=env, timeout=60)
            if result.returncode:
                return 1
    print('PASS: six actual native retry bind aliases refused before attempt creation')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
