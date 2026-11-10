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
    if (sys.platform != 'linux' or os.getuid() == 0 or os.getuid() != os.geteuid()
            or os.getgid() != os.getegid()):
        print('UNQUALIFIED: ordinary Linux host identity required')
        return 77
    binary, scratch = Path(sys.argv[1]).absolute(), Path(sys.argv[2])
    if not scratch.is_absolute() or not binary.is_file() or not os.access(binary, os.X_OK):
        return 1
    mode = os.environ.get('CK_FS_NAMESPACE_BOOTSTRAP', 'unprivileged')
    if mode not in ('unprivileged', 'privileged-id-map'):
        print('FAIL: unknown explicit namespace bootstrap mode')
        return 1
    unshare = shutil.which('unshare')
    if not unshare or not Path('/bin/true').is_file():
        print('UNQUALIFIED: unshare or /bin/true is unavailable')
        return 77
    user_ns = os.stat('/proc/self/ns/user')
    mount_ns = os.stat('/proc/self/ns/mnt')
    env = dict(os.environ, CK_RETRY_SCOPE_HOST_UID=str(os.getuid()),
               CK_RETRY_SCOPE_HOST_USER_NS=str(user_ns.st_ino),
               CK_RETRY_SCOPE_HOST_MOUNT_NS=str(mount_ns.st_ino))
    if mode == 'unprivileged':
        isolation = [unshare, '--user', '--map-root-user', '--mount', '--propagation', 'private']
    else:
        sudo = shutil.which('sudo')
        helper = Path(__file__).resolve().with_name('bootstrap_private_scope_namespace.py')
        if not sudo or not helper.is_file() or not Path('/usr/bin/python3').is_file():
            print('UNQUALIFIED: explicit identity-map bootstrap prerequisites are unavailable')
            return 77
        # The shared helper maps only its own child to this ordinary host
        # caller. The native fixture still checks the UID map and both fresh
        # namespace identities before any bind mount.
        preserve = ('TMPDIR,TEMP,TMP,ASAN_OPTIONS,UBSAN_OPTIONS,TSAN_OPTIONS,'
                    'CK_RETRY_SCOPE_HOST_UID,CK_RETRY_SCOPE_HOST_USER_NS,'
                    'CK_RETRY_SCOPE_HOST_MOUNT_NS')
        isolation = [sudo, '-n', '--preserve-env=' + preserve,
                     '/usr/bin/python3', '-I', str(helper), str(os.getuid()), str(os.getgid()),
                     f'{user_ns.st_dev}:{user_ns.st_ino}',
                     f'{mount_ns.st_dev}:{mount_ns.st_ino}', str(os.getpid())]
    scratch.mkdir(parents=True, exist_ok=True)
    try:
        probe = subprocess.run(isolation + ['/bin/true'], env=env,
                               capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f'FAIL: namespace probe: {error}')
        return 1
    if probe.returncode:
        print('UNQUALIFIED: ' + probe.stderr.strip())
        return 77
    for mode in ('source-bind-alias', 'candidate-bind-alias', 'destination-bind-alias',
                 'source-bind-alias-second', 'candidate-bind-alias-second', 'destination-bind-alias-second'):
        with tempfile.TemporaryDirectory(prefix='retry-scope-' + mode + '-', dir=scratch) as fixture:
            env.update(TMPDIR=fixture, TMP=fixture, TEMP=fixture)
            try:
                result = subprocess.run(isolation + [str(binary), fixture, mode], env=env, timeout=60)
            except (OSError, subprocess.TimeoutExpired) as error:
                print(f'FAIL: native retry scope: {error}')
                return 1
            if result.returncode:
                return 1
    print('PASS: six actual native retry bind aliases refused before attempt creation')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
