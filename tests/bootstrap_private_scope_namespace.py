"""Explicit CI fixture bootstrap; the native test runs as the caller's host UID.

Run only through sudo from run_private_scope_mounts.py. The privileged parent
maps its own waiting child, then waits. The child drops the host identity,
creates a private mount namespace, sets no-new-privileges, and execs the test.
No host mounts, security policy, persistent helpers, or library code are changed.
"""
import ctypes
import os
import select
import signal
import sys


CLONE_NEWNS = 0x00020000
CLONE_NEWUSER = 0x10000000
MS_REC, MS_PRIVATE = 16384, 1 << 18
PR_SET_PDEATHSIG, PR_SET_NO_NEW_PRIVS = 1, 38


def main():
    if sys.platform != "linux" or len(sys.argv) < 7 or os.getuid() or os.geteuid():
        raise RuntimeError("explicit sudo Linux fixture bootstrap is required")
    uid, gid = int(sys.argv[1]), int(sys.argv[2])
    if not (0 < uid < 2**32 - 1 and 0 < gid < 2**32 - 1):
        raise RuntimeError("ordinary nonzero host UID/GID required")
    if int(os.environ.get("SUDO_UID", "-1")) != uid or int(os.environ.get("SUDO_GID", "-1")) != gid:
        raise RuntimeError("mapping must match the actual sudo caller")
    for name, expected in [("user",sys.argv[3]),("mnt",sys.argv[4])]:
        observed=os.stat(f"/proc/self/ns/{name}")
        if f"{observed.st_dev}:{observed.st_ino}" != expected:
            raise RuntimeError("bootstrap must start in the actual caller's namespaces")
    caller_pid=int(sys.argv[5])
    if caller_pid<=1:
        raise RuntimeError("live ordinary caller PID required")
    command = sys.argv[6:]
    if not os.path.isabs(command[0]):
        raise RuntimeError("absolute fixture executable required")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.unshare.argtypes, libc.unshare.restype = [ctypes.c_int], ctypes.c_int
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                          ctypes.c_ulong, ctypes.c_void_p]
    libc.mount.restype = ctypes.c_int
    libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
    libc.prctl.restype = ctypes.c_int

    def checked(result):
        if result:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))

    # Keep a dead child as our zombie until all /proc accesses are finished.
    # Its PID therefore cannot be reused for an unrelated process.
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    child, child_handle, caller_handle = None, None, None
    bootstrap_pid = os.getpid()

    def terminate(_signum, _frame):
        raise InterruptedError("namespace fixture bootstrap cancelled")

    for number in [signal.SIGTERM, signal.SIGHUP, signal.SIGINT]:
        signal.signal(number, terminate)
    parent = os.getppid()
    checked(libc.prctl(PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0))
    if os.getppid() != parent:
        raise RuntimeError("fixture launcher parent changed")
    ready_r, ready_w = os.pipe2(os.O_CLOEXEC)
    gate_r, gate_w = os.pipe2(os.O_CLOEXEC)
    descriptors = {ready_r, ready_w, gate_r, gate_w}

    def close(descriptor):
        if descriptor in descriptors:
            descriptors.remove(descriptor)
            os.close(descriptor)

    try:
        child = os.fork()
        if child == 0:
            try:
                for number in [signal.SIGTERM, signal.SIGHUP, signal.SIGINT]:
                    signal.signal(number, signal.SIG_DFL)
                close(ready_r)
                close(gate_w)
                checked(libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0))
                if os.getppid() != bootstrap_pid:
                    raise RuntimeError("namespace bootstrap parent changed")
                os.setgroups([])
                checked(libc.unshare(CLONE_NEWUSER))
                if os.write(ready_w, b"R") != 1 or os.read(gate_r, 1) != b"G":
                    raise RuntimeError("namespace identity mapping was not completed")
                close(ready_w)
                close(gate_r)
                os.setresgid(0, 0, 0)
                os.setresuid(0, 0, 0)
                if os.getuid() or os.geteuid() or os.getgid() or os.getegid() or os.getgroups():
                    raise RuntimeError("fixture identity did not drop to the mapped caller")
                # Credential changes clear PDEATHSIG; establish it again.
                checked(libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0))
                if os.getppid() != bootstrap_pid:
                    raise RuntimeError("namespace bootstrap parent changed")
                checked(libc.unshare(CLONE_NEWNS))
                checked(libc.mount(None, b"/", None, MS_REC | MS_PRIVATE, None))
                checked(libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
                os.execve(command[0], command, dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
            except BaseException as error:
                print(f"FAIL namespace child: {error}", file=sys.stderr, flush=True)
                os._exit(1)
        child_handle = os.pidfd_open(child, 0)
        caller_handle = os.pidfd_open(caller_pid, 0)
        if select.select([caller_handle],[],[],0)[0] or os.stat(f"/proc/{caller_pid}").st_uid!=uid:
            raise RuntimeError("ordinary fixture caller is no longer live")
        ancestor=os.getppid()
        for _ in range(16):
            if ancestor==caller_pid:
                break
            with open(f"/proc/{ancestor}/status",encoding="ascii") as status:
                ancestor=next(int(line.split()[1])for line in status if line.startswith("PPid:"))
            if ancestor<=1:
                raise RuntimeError("fixture caller is not an ancestor")
        else:
            raise RuntimeError("fixture caller ancestry exceeds bound")
        close(ready_w)
        close(gate_r)
        if not select.select([ready_r], [], [], 10)[0] or os.read(ready_r, 1) != b"R":
            raise RuntimeError("namespace child did not enter its new user namespace")
        # Hold this exact child's proc directory throughout mapping. No final
        # operation follows a replaceable pathname after this directory open.
        proc = os.open(f"/proc/{child}", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            for name, data in [("setgroups", b"deny\n"),
                               ("uid_map", f"0 {uid} 1\n".encode()),
                               ("gid_map", f"0 {gid} 1\n".encode())]:
                descriptor = os.open(name, os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=proc)
                try:
                    if os.write(descriptor, data) != len(data):
                        raise RuntimeError("short namespace mapping write")
                finally:
                    os.close(descriptor)
        finally:
            os.close(proc)
        if os.write(gate_w, b"G") != 1:
            raise RuntimeError("short namespace startup grant")
        close(gate_w)
        close(ready_r)
        ready=select.select([child_handle,caller_handle],[],[],140)[0]
        if caller_handle in ready:
            raise InterruptedError("ordinary fixture caller terminated")
        if child_handle not in ready:
            raise TimeoutError("isolated native fixture exceeded its bounded lifetime")
        _, status = os.waitpid(child, 0)
        child = None
        result = os.waitstatus_to_exitcode(status)
        return result if result >= 0 else 128 - result
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK,[signal.SIGTERM,signal.SIGHUP,signal.SIGINT])
        if child:
            try:
                if child_handle is not None:
                    signal.pidfd_send_signal(child_handle, signal.SIGKILL)
                else:
                    # pidfd acquisition failed before any wait/reap; our own
                    # child (including a zombie) still reserves this PID.
                    os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(child, 0)
            except ChildProcessError:
                pass
        if child_handle is not None:
            os.close(child_handle)
        if caller_handle is not None:
            os.close(caller_handle)
        for descriptor in list(descriptors):
            close(descriptor)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"FAIL namespace bootstrap: {error}", file=sys.stderr, flush=True)
        sys.exit(1)
