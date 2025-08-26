# cython: language_level=3

cimport _statfs
cimport libc.string
cimport libc.errno
from cpython.exc cimport PyErr_SetFromErrnoWithFilenameObject

import os
import pathlib
import dataclasses
import enum


FSType = enum.IntEnum("FSType", {"UNKNOWN": -1, **{
    k: v for k, v in [
        ("ADFS",        _statfs.ADFS_SUPER_MAGIC),
        ("AFFS",        _statfs.AFFS_SUPER_MAGIC),
        ("AFS",         _statfs.AFS_SUPER_MAGIC),
        ("ANON_INODE",  _statfs.ANON_INODE_FS_MAGIC),
        ("AUTOFS",      _statfs.AUTOFS_SUPER_MAGIC),
        ("BDEVFS",      _statfs.BDEVFS_MAGIC),
        ("BEFS",        _statfs.BEFS_SUPER_MAGIC),
        ("BFS",         _statfs.BFS_MAGIC),
        ("BINFMTFS",    _statfs.BINFMTFS_MAGIC),
        ("BPF",         _statfs.BPF_FS_MAGIC),
        ("BTRFS",       _statfs.BTRFS_SUPER_MAGIC),
        ("BTRFS_TEST",  _statfs.BTRFS_TEST_MAGIC),
        ("CGROUP2",     _statfs.CGROUP2_SUPER_MAGIC),
        ("CGROUP",      _statfs.CGROUP_SUPER_MAGIC),
        ("CIFS",        _statfs.CIFS_MAGIC_NUMBER),
        ("CODA",        _statfs.CODA_SUPER_MAGIC),
        ("COH",         _statfs.COH_SUPER_MAGIC),
        ("CRAMFS",      _statfs.CRAMFS_MAGIC),
        ("DEBUGFS",     _statfs.DEBUGFS_MAGIC),
        ("DEVFS",       _statfs.DEVFS_SUPER_MAGIC),
        ("DEVPTS",      _statfs.DEVPTS_SUPER_MAGIC),
        ("ECRYPTFS",    _statfs.ECRYPTFS_SUPER_MAGIC),
        ("EFIVARFS",    _statfs.EFIVARFS_MAGIC),
        ("EFS",         _statfs.EFS_SUPER_MAGIC),
        ("EXT",         _statfs.EXT_SUPER_MAGIC),
        ("EXT2_OLD",    _statfs.EXT2_OLD_SUPER_MAGIC),
        ("EXT2",        _statfs.EXT2_SUPER_MAGIC),
        ("EXT3",        _statfs.EXT3_SUPER_MAGIC),
        ("EXT4",        _statfs.EXT4_SUPER_MAGIC),
        ("F2FS",        _statfs.F2FS_SUPER_MAGIC),
        ("FUSE",        _statfs.FUSE_SUPER_MAGIC),
        ("FUTEXFS",     _statfs.FUTEXFS_SUPER_MAGIC),
        ("HFS",         _statfs.HFS_SUPER_MAGIC),
        ("HOSTFS",      _statfs.HOSTFS_SUPER_MAGIC),
        ("HPFS",        _statfs.HPFS_SUPER_MAGIC),
        ("HUGETLBFS",   _statfs.HUGETLBFS_MAGIC),
        ("ISOFS",       _statfs.ISOFS_SUPER_MAGIC),
        ("JFFS2",       _statfs.JFFS2_SUPER_MAGIC),
        ("JFS",         _statfs.JFS_SUPER_MAGIC),
        ("MINIX",       _statfs.MINIX_SUPER_MAGIC),
        ("MINIX_2",     _statfs.MINIX_SUPER_MAGIC2),
        ("MINIX2",      _statfs.MINIX2_SUPER_MAGIC),
        ("MINIX2_2",    _statfs.MINIX2_SUPER_MAGIC2),
        ("MINIX3",      _statfs.MINIX3_SUPER_MAGIC),
        ("MQUEUE",      _statfs.MQUEUE_MAGIC),
        ("MSDOS",       _statfs.MSDOS_SUPER_MAGIC),
        ("MTD_INODE",   _statfs.MTD_INODE_FS_MAGIC),
        ("NCP",         _statfs.NCP_SUPER_MAGIC),
        ("NFS",         _statfs.NFS_SUPER_MAGIC),
        ("NILFS",       _statfs.NILFS_SUPER_MAGIC),
        ("NSFS",        _statfs.NSFS_MAGIC),
        ("NTFS",        _statfs.NTFS_SB_MAGIC),
        ("OCFS2",       _statfs.OCFS2_SUPER_MAGIC),
        ("OPENPROM",    _statfs.OPENPROM_SUPER_MAGIC),
        ("OVERLAYFS",   _statfs.OVERLAYFS_SUPER_MAGIC),
        ("PIPEFS",      _statfs.PIPEFS_MAGIC),
        ("PROC",        _statfs.PROC_SUPER_MAGIC),
        ("PSTOREFS",    _statfs.PSTOREFS_MAGIC),
        ("QNX4",        _statfs.QNX4_SUPER_MAGIC),
        ("QNX6",        _statfs.QNX6_SUPER_MAGIC),
        ("RAMFS",       _statfs.RAMFS_MAGIC),
        ("REISERFS",    _statfs.REISERFS_SUPER_MAGIC),
        ("ROMFS",       _statfs.ROMFS_MAGIC),
        ("SECURITYFS",  _statfs.SECURITYFS_MAGIC),
        ("SELINUX",     _statfs.SELINUX_MAGIC),
        ("SMACK",       _statfs.SMACK_MAGIC),
        ("SMB",         _statfs.SMB_SUPER_MAGIC),
        ("SMB2",        _statfs.SMB2_MAGIC_NUMBER),
        ("SOCKFS",      _statfs.SOCKFS_MAGIC),
        ("SQUASHFS",    _statfs.SQUASHFS_MAGIC),
        ("SYSFS",       _statfs.SYSFS_MAGIC),
        ("SYSV2",       _statfs.SYSV2_SUPER_MAGIC),
        ("SYSV4",       _statfs.SYSV4_SUPER_MAGIC),
        ("TMPFS",       _statfs.TMPFS_MAGIC),
        ("TRACEFS",     _statfs.TRACEFS_MAGIC),
        ("UDF",         _statfs.UDF_SUPER_MAGIC),
        ("UFS",         _statfs.UFS_MAGIC),
        ("USBDEVICE",   _statfs.USBDEVICE_SUPER_MAGIC),
        ("V9FS",        _statfs.V9FS_MAGIC),
        ("VXFS",        _statfs.VXFS_SUPER_MAGIC),
        ("XENFS",       _statfs.XENFS_SUPER_MAGIC),
        ("XENIX",       _statfs.XENIX_SUPER_MAGIC),
        ("XFS",         _statfs.XFS_SUPER_MAGIC),
        ("XIAFS",       _statfs.XIAFS_SUPER_MAGIC),
    ]
    if v > 0
}})


FSFlag = enum.IntFlag("FSFlag", {
    k: v for k, v in [
        ("MANDLOCK",    _statfs.ST_MANDLOCK),
        ("NOATIME",     _statfs.ST_NOATIME),
        ("NODEV",       _statfs.ST_NODEV),
        ("NODIRATIME",  _statfs.ST_NODIRATIME),
        ("NOEXEC",      _statfs.ST_NOEXEC),
        ("NOSUID",      _statfs.ST_NOSUID),
        ("RDONLY",      _statfs.ST_RDONLY),
        ("RELATIME",    _statfs.ST_RELATIME),
        ("SYNCHRONOUS", _statfs.ST_SYNCHRONOUS),
        ("NOSYMFOLLOW", _statfs.ST_NOSYMFOLLOW),
    ]
    if v > 0
})


@dataclasses.dataclass(frozen=True)
class StatFS:
    type: FSType
    type_value: int
    bsize: int
    blocks: int
    bfree: int
    bavail: int
    files: int
    ffree: int
    namelen: int
    frsize: int
    flags: FSFlag
    flags_value: int


def __get_fstype(f_type: int) -> FSType:
    try:
        return FSType(f_type)
    except ValueError:
        return FSType.UNKNOWN


def statfs(path: str | os.PathLike) -> None:
    cdef _statfs.statfs_t fsinfo
    cpath = os.fspath(path).encode("utf-8")
    libc.string.memset(&fsinfo, 0, sizeof(fsinfo))
    if _statfs.statfs(cpath, &fsinfo) != 0:
        PyErr_SetFromErrnoWithFilenameObject(OSError, os.fspath(path))
    return StatFS(
        type = __get_fstype(fsinfo.f_type),
        type_value = fsinfo.f_type,
        bsize = fsinfo.f_bsize,
        blocks = fsinfo.f_blocks,
        bfree = fsinfo.f_bfree,
        bavail = fsinfo.f_bavail,
        files = fsinfo.f_files,
        ffree = fsinfo.f_ffree,
        namelen = fsinfo.f_namelen,
        frsize = fsinfo.f_frsize,
        flags = FSFlag(fsinfo.f_flags),
        flags_value = fsinfo.f_flags,
    )

