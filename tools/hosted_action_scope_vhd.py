# SPDX-License-Identifier: LGPL-2.0-or-later
"""Own one disposable GitHub-hosted Windows action-scope VHD through qualification."""
from contextlib import ExitStack
import ctypes as c
from ctypes import wintypes as w
import json
import ntpath
import os
from pathlib import Path
import subprocess
import sys
import uuid

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent.parent / "tests"))
from run_action_scope_fixture_windows import (LABEL, VOLUME_GUID, NativeCommandIndeterminate,
                                              ScopeWindows, below, checked_process, dos_path,
                                              extended, hosted_temp)


# The Windows SDK Version1 parameter arm is used with the Microsoft VHD
# provider (device 2), default dynamic allocation and no parent/source image.
class Guid(c.Structure):
    _fields_ = [("data1", w.DWORD), ("data2", w.WORD), ("data3", w.WORD), ("data4", c.c_ubyte * 8)]


class StorageType(c.Structure):
    _fields_ = [("device", w.ULONG), ("vendor", Guid)]


class CreateVhdV1(c.Structure):
    _fields_ = [("id", Guid), ("size", c.c_uint64), ("block", w.ULONG), ("sector", w.ULONG),
                ("parent", w.LPCWSTR), ("source", w.LPCWSTR)]


class CreateVhdV4(c.Structure):
    # Allocate the full SDK union even though the selected Version1 arm
    # only consumes its own fields.
    _fields_ = [("id", Guid), ("size", c.c_uint64), ("block", w.ULONG), ("sector", w.ULONG),
                ("physical_sector", w.ULONG), ("parent", w.LPCWSTR), ("source", w.LPCWSTR),
                ("open_flags", w.ULONG), ("parent_type", StorageType), ("source_type", StorageType),
                ("resiliency", Guid), ("source_limit", w.LPCWSTR), ("backing_type", StorageType),
                ("pmem_type", Guid), ("data_alignment", c.c_uint64)]


class CreateVhdData(c.Union):
    _fields_ = [("v1", CreateVhdV1), ("v4", CreateVhdV4)]


class CreateParameters(c.Structure):
    _fields_ = [("version", w.ULONG), ("data", CreateVhdData)]


def create_vhd(native, image):
    if (c.sizeof(c.c_void_p), c.sizeof(StorageType), CreateParameters.data.offset,
            CreateVhdV1.size.offset, CreateVhdV1.parent.offset, CreateVhdV4.data_alignment.offset,
            c.sizeof(CreateParameters)) != (8, 20, 8, 16, 32, 168, 184):
        raise RuntimeError("unexpected Windows x64 virtdisk.h layout")
    provider = c.WinDLL(ntpath.join(native.system, "virtdisk.dll"))
    create = provider.CreateVirtualDisk
    create.argtypes = [c.POINTER(StorageType), w.LPCWSTR, w.DWORD, c.c_void_p, w.DWORD,
                       w.ULONG, c.POINTER(CreateParameters), c.c_void_p, c.POINTER(w.HANDLE)]
    create.restype = w.DWORD
    storage_type = StorageType(2, Guid.from_buffer_copy(uuid.UUID("ec984aec-a0f9-47e9-901f-71415a66345b").bytes_le))
    parameters = CreateParameters(1, CreateVhdData(v1=CreateVhdV1(size=4 * 1024**3)))
    handle = w.HANDLE()
    status = create(c.byref(storage_type), extended(image), 0x00100000, None, 0, 0,
                    c.byref(parameters), None, c.byref(handle))
    if status:
        raise OSError(f"CreateVirtualDisk returned Win32 {status}")
    if not native.kernel.CloseHandle(handle):
        raise c.WinError(c.get_last_error())


STORAGE_PREFLIGHT = r"""
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'VHD provisioning requires the active administrator token' }
foreach ($name in 'Mount-DiskImage','Dismount-DiskImage','Get-DiskImage','Get-Disk','Initialize-Disk','New-Partition','Get-Partition','Format-Volume') {
    Get-Command ('Storage\' + $name) -ErrorAction Stop | Out-Null
}
[ordered]@{PowerShell=$PSVersionTable.PSVersion.ToString(); module=(Get-Module Storage).Path; admin=$true} | ConvertTo-Json -Compress
"""

ASSOCIATION = r"""
function OwnedDisk($image) {
    if (-not $image.Attached -or $image.ImagePath -ine $env:CKFS_SCOPE_IMAGE) {
        throw 'exact attached action VHD is required'
    }
    $disks = @($image | Storage\Get-Disk)
    if ($disks.Count -ne 1) { throw 'owned VHD must resolve to one disk' }
    $disk = $disks[0]
    if ($disk.IsBoot -or $disk.IsSystem -or
        $disk.BusType -ne 'File Backed Virtual' -or $disk.Location -ine $env:CKFS_SCOPE_IMAGE -or
        $image.DevicePath -ine ('\\.\PhysicalDrive' + $disk.Number)) { throw 'disk is not the exact file-backed image' }
    return $disk
}
"""

PROVISION = ASSOCIATION + r"""
$path = $env:CKFS_SCOPE_IMAGE
$image = Storage\Get-DiskImage -ImagePath $path
if ($image.Attached -or $image.ImagePath -ine $path) { throw 'fresh detached image required' }
$image = Storage\Mount-DiskImage -ImagePath $path -Access ReadWrite -NoDriveLetter -PassThru
$disk = OwnedDisk $image
if ($disk.IsReadOnly -or $disk.IsOffline -or $disk.PartitionStyle -ne 'RAW') { throw 'fresh VHD must be online, writable and RAW' }
$initialized = Storage\Initialize-Disk -InputObject $disk -PartitionStyle GPT -PassThru
$disk = OwnedDisk (Storage\Get-DiskImage -ImagePath $path)
if ($disk.ObjectId -cne $initialized.ObjectId -or $disk.PartitionStyle -ne 'GPT') { throw 'initialized VHD identity changed' }
$partition = Storage\New-Partition -InputObject $disk -UseMaximumSize
$verify = OwnedDisk (Storage\Get-DiskImage -ImagePath $path)
if ($verify.ObjectId -cne $disk.ObjectId -or $partition.DiskNumber -ne $verify.Number -or
    [string]$partition.DriveLetter -match '^[A-Za-z]$' -or -not $partition.Guid) { throw 'exact unaliased partition required' }
Storage\Format-Volume -Partition $partition -FileSystem NTFS -NewFileSystemLabel $env:CKFS_SCOPE_LABEL -Confirm:$false | Out-Null
$disk = OwnedDisk (Storage\Get-DiskImage -ImagePath $path)
$parts = @($disk | Storage\Get-Partition | Where-Object { $_.PartitionNumber -eq $partition.PartitionNumber -and $_.Guid -eq $partition.Guid })
if ($parts.Count -ne 1 -or $parts[0].AccessPaths.Count -ne 1) { throw 'formatted partition must have exactly one volume GUID address' }
[ordered]@{image=$path; disk=$disk.Number; partition=$parts[0].PartitionNumber; volume=$parts[0].AccessPaths[0]} | ConvertTo-Json -Compress
"""

DETACH = ASSOCIATION + r"""
$image = Storage\Get-DiskImage -ImagePath $env:CKFS_SCOPE_IMAGE
if ($image.ImagePath -ine $env:CKFS_SCOPE_IMAGE) { throw 'image address changed before teardown' }
if ($image.Attached) {
    $disk = OwnedDisk $image
    Storage\Dismount-DiskImage -InputObject $image
}
if ((Storage\Get-DiskImage -ImagePath $env:CKFS_SCOPE_IMAGE).Attached) { throw 'owned action VHD still attached' }
"""


def exact(native, handle, drive_guid, path, expected=None):
    if native.path(handle)[1] != drive_guid + path[3:]:
        raise RuntimeError(f"native object redirected: {path}")
    identity = native.identity(handle)
    if expected is not None and identity != expected:
        raise RuntimeError(f"native object identity changed: {path}")
    return identity


def check_owner(owner, temp):
    if (not below(owner, temp)
            or not ntpath.basename(owner).startswith("ckfs-action-vhd-")):
        raise ValueError("hosted action image requires an exclusively created task owner")


def release(native, owner, owner_handle, image_handle, lease_handle):
    image = ntpath.join(owner, "scope.vhd")
    lease = ntpath.join(owner, "scope.lease")
    with native.open("D:\\", follow_mount=True) as drive:
        guid = native.path(drive)[0]
        # These are inherited references to the supervisor's original file
        # objects, not persisted IDs that could be replayed after a replacement.
        exact(native, owner_handle, guid, owner)
        image_id = exact(native, image_handle, guid, image)
        lease_id = exact(native, lease_handle, guid, lease)
        # A still-running fixture or its wrapper retains the exclusive read
        # open, so DELETE cannot be acquired and no detach is attempted.
        with native.open(lease, directory=False, access=0x80010000, share=0) as exclusive:
            exact(native, exclusive, guid, lease, lease_id)
            with native.open(image, directory=False) as pinned:
                exact(native, pinned, guid, image, image_id)
                native.storage(DETACH, dict(os.environ, CKFS_SCOPE_IMAGE=image), 25)
            with native.open(image, directory=False, access=0x10080, share=7) as removal:
                exact(native, removal, guid, image, image_id)
                native.remove(removal)
            native.remove(exclusive)
    print("Owned action-scope VHD detached; exact image and lease marked for removal.", flush=True)


def absent(native, path, *, directory=False):
    try:
        with native.open(path, directory=directory):
            raise RuntimeError(f"owned object survived teardown: {path}")
    except OSError as failure:
        if failure.winerror != 2:  # ERROR_FILE_NOT_FOUND, not denied or another lookup failure
            raise


def provision_and_run(native, temp, data, qualification):
    caller = dos_path(os.environ.get("TEMP", ""), "D")
    if (not below(caller, temp) or not below(data, temp)
            or any(dos_path(os.environ.get(key, ""), "D") != caller for key in ("TMPDIR", "TMP"))):
        raise ValueError("explicit hosted caller temporary storage and ordinary data root required")
    owner = ntpath.join(caller, "ckfs-action-vhd-" + uuid.uuid4().hex)
    image = ntpath.join(owner, "scope.vhd")
    lease = ntpath.join(owner, "scope.lease")
    helper = [sys.executable, "-B", os.path.abspath(__file__)]

    with ExitStack() as anchors:
        drive = anchors.enter_context(native.open("D:\\", follow_mount=True))
        host_guid = native.path(drive)[0]
        # Open every parent from the drive root without following reparses and
        # pin it against delete/rename throughout the supervisor lifetime.
        ancestor = "D:\\"
        for component in caller[3:].split("\\"):
            ancestor = ntpath.join(ancestor, component)
            handle = anchors.enter_context(native.open(ancestor))
            exact(native, handle, host_guid, ancestor)
        ordinary = anchors.enter_context(native.open(data, follow_mount=True))
        ordinary_guid = native.path(ordinary)[0]
        print(native.storage(STORAGE_PREFLIGHT, os.environ, 12), flush=True)
        os.mkdir(extended(owner))
        owner_handle = anchors.enter_context(native.open(owner, access=0x10080, share=3))
        exact(native, owner_handle, host_guid, owner)
        print(f"Creating hosted action-scope VHD at {image}", flush=True)
        # CREATE_NEW for the lease, and CreateVirtualDisk refuses an existing image.
        with ExitStack() as file_anchors:
            lease_handle = file_anchors.enter_context(native.open(lease, directory=False, share=7, creation=1))
            exact(native, lease_handle, host_guid, lease)
            checked_process([*helper, "--create", owner, str(owner_handle)], 30, inherit=(owner_handle,))
            image_handle = file_anchors.enter_context(native.open(image, directory=False, share=7))
            image_id = exact(native, image_handle, host_guid, image)
            safe_to_release, work_failure = True, None
            try:
                with native.open(image, directory=False) as pinned_image:
                    exact(native, pinned_image, host_guid, image, image_id)
                    try:
                        proof = json.loads(native.storage(
                            PROVISION, dict(os.environ, CKFS_SCOPE_IMAGE=image, CKFS_SCOPE_LABEL=LABEL), 60))
                    except (NativeCommandIndeterminate, KeyboardInterrupt):
                        # The Storage broker may still be mutating the disk.
                        safe_to_release = False
                        raise
                    match = VOLUME_GUID.fullmatch(proof["volume"])
                    if not match or proof["image"] != image:
                        raise RuntimeError("provisioning did not report the exact owned volume")
                    with native.open(proof["volume"]) as root:
                        if (native.path(root)[1].lower() != proof["volume"].lower()
                                or native.volume(root) != ("NTFS", LABEL)
                                or native.path(root)[0].lower() in (ordinary_guid.lower(), host_guid.lower())):
                            raise RuntimeError("native hosted action volume failed isolation admission")
                        print(json.dumps(dict(proof, image_file_id=image_id, data_volume=ordinary_guid,
                                              runner_image=os.environ.get("ImageVersion"))), flush=True)
                    arguments = [*qualification[:-2], f"-DQUALIFICATION_ACTION_SCOPE_ROOT=hosted-guid:{match[1]}",
                                 f"-DQUALIFICATION_ACTION_SCOPE_VHD={image}", *qualification[-2:]]
                    # An inherited lease rules out an orphan after CTest.
                    safe_to_release = False
                    code = subprocess.run(arguments, executable=arguments[0], check=False).returncode
                    safe_to_release = True
                    print(f"Hosted Windows qualification exited {code}", flush=True)
            except (Exception, KeyboardInterrupt) as failure:
                work_failure = failure
            if not safe_to_release:
                print(f"Ownership retained after an indeterminate operation: {owner}", flush=True)
                raise work_failure
            try:
                release_handles = (owner_handle, image_handle, lease_handle)
                print(checked_process([*helper, "--release", owner, *map(str, release_handles)], 45,
                                      inherit=release_handles), flush=True)
            except (Exception, KeyboardInterrupt) as release_failure:
                if work_failure is not None:
                    raise release_failure from work_failure
                raise
        # Original image and lease references were retained through disposition.
        absent(native, image)
        absent(native, lease)
        native.remove(owner_handle)  # Empty directory, through its original native owner.
    absent(native, owner, directory=True)
    print(f"Verified hosted action-scope image and owner removed: {owner}", flush=True)
    if work_failure is not None:
        raise work_failure
    return code


def main():
    if os.name != "nt":
        raise ValueError("Windows GitHub-hosted action-scope provisioning only")
    temp = hosted_temp()
    native = ScopeWindows()
    if len(sys.argv) == 4 and sys.argv[1] == "--create":
        owner = dos_path(sys.argv[2], "D")
        check_owner(owner, temp)
        with native.open("D:\\", follow_mount=True) as drive:
            exact(native, int(sys.argv[3]), native.path(drive)[0], owner)
            create_vhd(native, ntpath.join(owner, "scope.vhd"))
        return 0
    if len(sys.argv) == 6 and sys.argv[1] == "--release":
        owner = dos_path(sys.argv[2], "D")
        check_owner(owner, temp)
        release(native, owner, *map(int, sys.argv[3:]))
        return 0
    if len(sys.argv) < 7 or sys.argv[2] != "--cmake" or sys.argv[-2:] != ["-P", "tools/qualification.cmake"]:
        raise ValueError("usage: hosted_action_scope_vhd.py ordinary-root --cmake absolute-cmake options -P tools/qualification.cmake")
    qualification = sys.argv[3:]
    if not ntpath.isabs(qualification[0]) or ntpath.basename(qualification[0]).lower() != "cmake.exe":
        raise ValueError("explicit installed cmake.exe required")
    return provision_and_run(native, temp, dos_path(sys.argv[1], "D"), qualification)


if __name__ == "__main__":
    sys.exit(main())
