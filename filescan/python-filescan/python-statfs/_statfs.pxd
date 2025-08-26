# cython: language_level=3

cdef extern from "<sys/vfs.h>":
    # doing it this way is hacky, but the types aren't guaranteed to be anything
    # in particular, especially cross-platform... there may be an easier way of
    # doing this (and in the end, I don't know that it matters), but this is at
    # least a "reasonably sane" way of making it -correct-, if -ugly-...
    """
    #define STATFS_TYPE(f) typeof ( ((struct statfs*)0)->f )
    """
    ctypedef signed long    __f_type    "STATFS_TYPE(f_type)"
    ctypedef signed long    __f_bsize   "STATFS_TYPE(f_bsize)"
    ctypedef unsigned long  __f_blocks  "STATFS_TYPE(f_blocks)"
    ctypedef unsigned long  __f_bfree   "STATFS_TYPE(f_bfree)"
    ctypedef unsigned long  __f_bavail  "STATFS_TYPE(f_bavail)"
    ctypedef unsigned long  __f_files   "STATFS_TYPE(f_files)"
    ctypedef unsigned long  __f_ffree   "STATFS_TYPE(f_ffree)"
    ctypedef void*          __f_fsid    "STATFS_TYPE(f_fsid)"
    ctypedef signed long    __f_namelen "STATFS_TYPE(f_namelen)"
    ctypedef signed long    __f_frsize  "STATFS_TYPE(f_frsize)"
    ctypedef signed long    __f_flags   "STATFS_TYPE(f_flags)"
    ctypedef signed long    __f_spare   "STATFS_TYPE(f_spare[0])"

    cdef struct statfs_t "statfs":
        __f_type    f_type
        __f_bsize   f_bsize
        __f_blocks  f_blocks
        __f_bfree   f_bfree
        __f_bavail  f_bavail
        __f_files   f_files
        __f_ffree   f_ffree
        __f_fsid    f_fsid
        __f_namelen f_namelen
        __f_frsize  f_frsize
        __f_flags   f_flags
        __f_spare   f_spare[0]

    int statfs(const char* path, statfs_t* buf)
    int fstatfs(int fd, statfs_t* buf)

cdef extern from *:
    """
    #include <sys/statvfs.h>
    #ifndef ST_MANDLOCK
    # define ST_MANDLOCK -1
    #endif
    #ifndef ST_NOATIME
    # define ST_NOATIME -1
    #endif
    #ifndef ST_NODEV
    # define ST_NODEV -1
    #endif
    #ifndef ST_NODIRATIME
    # define ST_NODIRATIME -1
    #endif
    #ifndef ST_NOEXEC
    # define ST_NOEXEC -1
    #endif
    #ifndef ST_NOSUID
    # define ST_NOSUID -1
    #endif
    #ifndef ST_RDONLY
    # define ST_RDONLY -1
    #endif
    #ifndef ST_RELATIME
    # define ST_RELATIME -1
    #endif
    #ifndef ST_SYNCHRONOUS
    # define ST_SYNCHRONOUS -1
    #endif
    #ifndef ST_NOSYMFOLLOW
    # define ST_NOSYMFOLLOW -1
    #endif
    """
    unsigned long ST_MANDLOCK
    unsigned long ST_NOATIME
    unsigned long ST_NODEV
    unsigned long ST_NODIRATIME
    unsigned long ST_NOEXEC
    unsigned long ST_NOSUID
    unsigned long ST_RDONLY
    unsigned long ST_RELATIME
    unsigned long ST_SYNCHRONOUS
    unsigned long ST_NOSYMFOLLOW

cdef extern from *:
    """
    #ifdef __linux__
    # include <linux/magic.h>
    #else
    # warning "unknown host OS"
    #endif
    #ifndef ADFS_SUPER_MAGIC
    # ifndef _ADFS_SUPER_MAGIC
    #  define ADFS_SUPER_MAGIC -1
    # else
    #  define ADFS_SUPER_MAGIC _ADFS_SUPER_MAGIC
    # endif
    #endif
    #ifndef AFFS_SUPER_MAGIC
    # ifndef _AFFS_SUPER_MAGIC
    #  define AFFS_SUPER_MAGIC -1
    # else
    #  define AFFS_SUPER_MAGIC _AFFS_SUPER_MAGIC
    # endif
    #endif
    #ifndef AFS_SUPER_MAGIC
    # ifndef _AFS_SUPER_MAGIC
    #  define AFS_SUPER_MAGIC -1
    # else
    #  define AFS_SUPER_MAGIC _AFS_SUPER_MAGIC
    # endif
    #endif
    #ifndef ANON_INODE_FS_MAGIC
    # ifndef _ANON_INODE_FS_MAGIC
    #  define ANON_INODE_FS_MAGIC -1
    # else
    #  define ANON_INODE_FS_MAGIC _ANON_INODE_FS_MAGIC
    # endif
    #endif
    #ifndef AUTOFS_SUPER_MAGIC
    # ifndef _AUTOFS_SUPER_MAGIC
    #  define AUTOFS_SUPER_MAGIC -1
    # else
    #  define AUTOFS_SUPER_MAGIC _AUTOFS_SUPER_MAGIC
    # endif
    #endif
    #ifndef BDEVFS_MAGIC
    # ifndef _BDEVFS_MAGIC
    #  define BDEVFS_MAGIC -1
    # else
    #  define BDEVFS_MAGIC _BDEVFS_MAGIC
    # endif
    #endif
    #ifndef BEFS_SUPER_MAGIC
    # ifndef _BEFS_SUPER_MAGIC
    #  define BEFS_SUPER_MAGIC -1
    # else
    #  define BEFS_SUPER_MAGIC _BEFS_SUPER_MAGIC
    # endif
    #endif
    #ifndef BFS_MAGIC
    # ifndef _BFS_MAGIC
    #  define BFS_MAGIC -1
    # else
    #  define BFS_MAGIC _BFS_MAGIC
    # endif
    #endif
    #ifndef BINFMTFS_MAGIC
    # ifndef _BINFMTFS_MAGIC
    #  define BINFMTFS_MAGIC -1
    # else
    #  define BINFMTFS_MAGIC _BINFMTFS_MAGIC
    # endif
    #endif
    #ifndef BPF_FS_MAGIC
    # ifndef _BPF_FS_MAGIC
    #  define BPF_FS_MAGIC -1
    # else
    #  define BPF_FS_MAGIC _BPF_FS_MAGIC
    # endif
    #endif
    #ifndef BTRFS_SUPER_MAGIC
    # ifndef _BTRFS_SUPER_MAGIC
    #  define BTRFS_SUPER_MAGIC -1
    # else
    #  define BTRFS_SUPER_MAGIC _BTRFS_SUPER_MAGIC
    # endif
    #endif
    #ifndef BTRFS_TEST_MAGIC
    # ifndef _BTRFS_TEST_MAGIC
    #  define BTRFS_TEST_MAGIC -1
    # else
    #  define BTRFS_TEST_MAGIC _BTRFS_TEST_MAGIC
    # endif
    #endif
    #ifndef CGROUP_SUPER_MAGIC
    # ifndef _CGROUP_SUPER_MAGIC
    #  define CGROUP_SUPER_MAGIC -1
    # else
    #  define CGROUP_SUPER_MAGIC _CGROUP_SUPER_MAGIC
    # endif
    #endif
    #ifndef CGROUP2_SUPER_MAGIC
    # ifndef _CGROUP2_SUPER_MAGIC
    #  define CGROUP2_SUPER_MAGIC -1
    # else
    #  define CGROUP2_SUPER_MAGIC _CGROUP2_SUPER_MAGIC
    # endif
    #endif
    #ifndef CIFS_MAGIC_NUMBER
    # ifndef _CIFS_MAGIC_NUMBER
    #  define CIFS_MAGIC_NUMBER -1
    # else
    #  define CIFS_MAGIC_NUMBER _CIFS_MAGIC_NUMBER
    # endif
    #endif
    #ifndef CODA_SUPER_MAGIC
    # ifndef _CODA_SUPER_MAGIC
    #  define CODA_SUPER_MAGIC -1
    # else
    #  define CODA_SUPER_MAGIC _CODA_SUPER_MAGIC
    # endif
    #endif
    #ifndef COH_SUPER_MAGIC
    # ifndef _COH_SUPER_MAGIC
    #  define COH_SUPER_MAGIC -1
    # else
    #  define COH_SUPER_MAGIC _COH_SUPER_MAGIC
    # endif
    #endif
    #ifndef CRAMFS_MAGIC
    # ifndef _CRAMFS_MAGIC
    #  define CRAMFS_MAGIC -1
    # else
    #  define CRAMFS_MAGIC _CRAMFS_MAGIC
    # endif
    #endif
    #ifndef DEBUGFS_MAGIC
    # ifndef _DEBUGFS_MAGIC
    #  define DEBUGFS_MAGIC -1
    # else
    #  define DEBUGFS_MAGIC _DEBUGFS_MAGIC
    # endif
    #endif
    #ifndef DEVFS_SUPER_MAGIC
    # ifndef _DEVFS_SUPER_MAGIC
    #  define DEVFS_SUPER_MAGIC -1
    # else
    #  define DEVFS_SUPER_MAGIC _DEVFS_SUPER_MAGIC
    # endif
    #endif
    #ifndef DEVPTS_SUPER_MAGIC
    # ifndef _DEVPTS_SUPER_MAGIC
    #  define DEVPTS_SUPER_MAGIC -1
    # else
    #  define DEVPTS_SUPER_MAGIC _DEVPTS_SUPER_MAGIC
    # endif
    #endif
    #ifndef ECRYPTFS_SUPER_MAGIC
    # ifndef _ECRYPTFS_SUPER_MAGIC
    #  define ECRYPTFS_SUPER_MAGIC -1
    # else
    #  define ECRYPTFS_SUPER_MAGIC _ECRYPTFS_SUPER_MAGIC
    # endif
    #endif
    #ifndef EFIVARFS_MAGIC
    # ifndef _EFIVARFS_MAGIC
    #  define EFIVARFS_MAGIC -1
    # else
    #  define EFIVARFS_MAGIC _EFIVARFS_MAGIC
    # endif
    #endif
    #ifndef EFS_SUPER_MAGIC
    # ifndef _EFS_SUPER_MAGIC
    #  define EFS_SUPER_MAGIC -1
    # else
    #  define EFS_SUPER_MAGIC _EFS_SUPER_MAGIC
    # endif
    #endif
    #ifndef EXT_SUPER_MAGIC
    # ifndef _EXT_SUPER_MAGIC
    #  define EXT_SUPER_MAGIC -1
    # else
    #  define EXT_SUPER_MAGIC _EXT_SUPER_MAGIC
    # endif
    #endif
    #ifndef EXT2_OLD_SUPER_MAGIC
    # ifndef _EXT2_OLD_SUPER_MAGIC
    #  define EXT2_OLD_SUPER_MAGIC -1
    # else
    #  define EXT2_OLD_SUPER_MAGIC _EXT2_OLD_SUPER_MAGIC
    # endif
    #endif
    #ifndef EXT2_SUPER_MAGIC
    # ifndef _EXT2_SUPER_MAGIC
    #  define EXT2_SUPER_MAGIC -1
    # else
    #  define EXT2_SUPER_MAGIC _EXT2_SUPER_MAGIC
    # endif
    #endif
    #ifndef EXT3_SUPER_MAGIC
    # ifndef _EXT3_SUPER_MAGIC
    #  define EXT3_SUPER_MAGIC -1
    # else
    #  define EXT3_SUPER_MAGIC _EXT3_SUPER_MAGIC
    # endif
    #endif
    #ifndef EXT4_SUPER_MAGIC
    # ifndef _EXT4_SUPER_MAGIC
    #  define EXT4_SUPER_MAGIC -1
    # else
    #  define EXT4_SUPER_MAGIC _EXT4_SUPER_MAGIC
    # endif
    #endif
    #ifndef F2FS_SUPER_MAGIC
    # ifndef _F2FS_SUPER_MAGIC
    #  define F2FS_SUPER_MAGIC -1
    # else
    #  define F2FS_SUPER_MAGIC _F2FS_SUPER_MAGIC
    # endif
    #endif
    #ifndef FUSE_SUPER_MAGIC
    # ifndef _FUSE_SUPER_MAGIC
    #  define FUSE_SUPER_MAGIC -1
    # else
    #  define FUSE_SUPER_MAGIC _FUSE_SUPER_MAGIC
    # endif
    #endif
    #ifndef FUTEXFS_SUPER_MAGIC
    # ifndef _FUTEXFS_SUPER_MAGIC
    #  define FUTEXFS_SUPER_MAGIC -1
    # else
    #  define FUTEXFS_SUPER_MAGIC _FUTEXFS_SUPER_MAGIC
    # endif
    #endif
    #ifndef HFS_SUPER_MAGIC
    # ifndef _HFS_SUPER_MAGIC
    #  define HFS_SUPER_MAGIC -1
    # else
    #  define HFS_SUPER_MAGIC _HFS_SUPER_MAGIC
    # endif
    #endif
    #ifndef HOSTFS_SUPER_MAGIC
    # ifndef _HOSTFS_SUPER_MAGIC
    #  define HOSTFS_SUPER_MAGIC -1
    # else
    #  define HOSTFS_SUPER_MAGIC _HOSTFS_SUPER_MAGIC
    # endif
    #endif
    #ifndef HPFS_SUPER_MAGIC
    # ifndef _HPFS_SUPER_MAGIC
    #  define HPFS_SUPER_MAGIC -1
    # else
    #  define HPFS_SUPER_MAGIC _HPFS_SUPER_MAGIC
    # endif
    #endif
    #ifndef HUGETLBFS_MAGIC
    # ifndef _HUGETLBFS_MAGIC
    #  define HUGETLBFS_MAGIC -1
    # else
    #  define HUGETLBFS_MAGIC _HUGETLBFS_MAGIC
    # endif
    #endif
    #ifndef ISOFS_SUPER_MAGIC
    # ifndef _ISOFS_SUPER_MAGIC
    #  define ISOFS_SUPER_MAGIC -1
    # else
    #  define ISOFS_SUPER_MAGIC _ISOFS_SUPER_MAGIC
    # endif
    #endif
    #ifndef JFFS2_SUPER_MAGIC
    # ifndef _JFFS2_SUPER_MAGIC
    #  define JFFS2_SUPER_MAGIC -1
    # else
    #  define JFFS2_SUPER_MAGIC _JFFS2_SUPER_MAGIC
    # endif
    #endif
    #ifndef JFS_SUPER_MAGIC
    # ifndef _JFS_SUPER_MAGIC
    #  define JFS_SUPER_MAGIC -1
    # else
    #  define JFS_SUPER_MAGIC _JFS_SUPER_MAGIC
    # endif
    #endif
    #ifndef MINIX_SUPER_MAGIC
    # ifndef _MINIX_SUPER_MAGIC
    #  define MINIX_SUPER_MAGIC -1
    # else
    #  define MINIX_SUPER_MAGIC _MINIX_SUPER_MAGIC
    # endif
    #endif
    #ifndef MINIX_SUPER_MAGIC2
    # ifndef _MINIX_SUPER_MAGIC2
    #  define MINIX_SUPER_MAGIC2 -1
    # else
    #  define MINIX_SUPER_MAGIC2 _MINIX_SUPER_MAGIC2
    # endif
    #endif
    #ifndef MINIX2_SUPER_MAGIC
    # ifndef _MINIX2_SUPER_MAGIC
    #  define MINIX2_SUPER_MAGIC -1
    # else
    #  define MINIX2_SUPER_MAGIC _MINIX2_SUPER_MAGIC
    # endif
    #endif
    #ifndef MINIX2_SUPER_MAGIC2
    # ifndef _MINIX2_SUPER_MAGIC2
    #  define MINIX2_SUPER_MAGIC2 -1
    # else
    #  define MINIX2_SUPER_MAGIC2 _MINIX2_SUPER_MAGIC2
    # endif
    #endif
    #ifndef MINIX3_SUPER_MAGIC
    # ifndef _MINIX3_SUPER_MAGIC
    #  define MINIX3_SUPER_MAGIC -1
    # else
    #  define MINIX3_SUPER_MAGIC _MINIX3_SUPER_MAGIC
    # endif
    #endif
    #ifndef MQUEUE_MAGIC
    # ifndef _MQUEUE_MAGIC
    #  define MQUEUE_MAGIC -1
    # else
    #  define MQUEUE_MAGIC _MQUEUE_MAGIC
    # endif
    #endif
    #ifndef MSDOS_SUPER_MAGIC
    # ifndef _MSDOS_SUPER_MAGIC
    #  define MSDOS_SUPER_MAGIC -1
    # else
    #  define MSDOS_SUPER_MAGIC _MSDOS_SUPER_MAGIC
    # endif
    #endif
    #ifndef MTD_INODE_FS_MAGIC
    # ifndef _MTD_INODE_FS_MAGIC
    #  define MTD_INODE_FS_MAGIC -1
    # else
    #  define MTD_INODE_FS_MAGIC _MTD_INODE_FS_MAGIC
    # endif
    #endif
    #ifndef NCP_SUPER_MAGIC
    # ifndef _NCP_SUPER_MAGIC
    #  define NCP_SUPER_MAGIC -1
    # else
    #  define NCP_SUPER_MAGIC _NCP_SUPER_MAGIC
    # endif
    #endif
    #ifndef NFS_SUPER_MAGIC
    # ifndef _NFS_SUPER_MAGIC
    #  define NFS_SUPER_MAGIC -1
    # else
    #  define NFS_SUPER_MAGIC _NFS_SUPER_MAGIC
    # endif
    #endif
    #ifndef NILFS_SUPER_MAGIC
    # ifndef _NILFS_SUPER_MAGIC
    #  define NILFS_SUPER_MAGIC -1
    # else
    #  define NILFS_SUPER_MAGIC _NILFS_SUPER_MAGIC
    # endif
    #endif
    #ifndef NSFS_MAGIC
    # ifndef _NSFS_MAGIC
    #  define NSFS_MAGIC -1
    # else
    #  define NSFS_MAGIC _NSFS_MAGIC
    # endif
    #endif
    #ifndef NTFS_SB_MAGIC
    # ifndef _NTFS_SB_MAGIC
    #  define NTFS_SB_MAGIC -1
    # else
    #  define NTFS_SB_MAGIC _NTFS_SB_MAGIC
    # endif
    #endif
    #ifndef OCFS2_SUPER_MAGIC
    # ifndef _OCFS2_SUPER_MAGIC
    #  define OCFS2_SUPER_MAGIC -1
    # else
    #  define OCFS2_SUPER_MAGIC _OCFS2_SUPER_MAGIC
    # endif
    #endif
    #ifndef OPENPROM_SUPER_MAGIC
    # ifndef _OPENPROM_SUPER_MAGIC
    #  define OPENPROM_SUPER_MAGIC -1
    # else
    #  define OPENPROM_SUPER_MAGIC _OPENPROM_SUPER_MAGIC
    # endif
    #endif
    #ifndef OVERLAYFS_SUPER_MAGIC
    # ifndef _OVERLAYFS_SUPER_MAGIC
    #  define OVERLAYFS_SUPER_MAGIC -1
    # else
    #  define OVERLAYFS_SUPER_MAGIC _OVERLAYFS_SUPER_MAGIC
    # endif
    #endif
    #ifndef PIPEFS_MAGIC
    # ifndef _PIPEFS_MAGIC
    #  define PIPEFS_MAGIC -1
    # else
    #  define PIPEFS_MAGIC _PIPEFS_MAGIC
    # endif
    #endif
    #ifndef PROC_SUPER_MAGIC
    # ifndef _PROC_SUPER_MAGIC
    #  define PROC_SUPER_MAGIC -1
    # else
    #  define PROC_SUPER_MAGIC _PROC_SUPER_MAGIC
    # endif
    #endif
    #ifndef PSTOREFS_MAGIC
    # ifndef _PSTOREFS_MAGIC
    #  define PSTOREFS_MAGIC -1
    # else
    #  define PSTOREFS_MAGIC _PSTOREFS_MAGIC
    # endif
    #endif
    #ifndef QNX4_SUPER_MAGIC
    # ifndef _QNX4_SUPER_MAGIC
    #  define QNX4_SUPER_MAGIC -1
    # else
    #  define QNX4_SUPER_MAGIC _QNX4_SUPER_MAGIC
    # endif
    #endif
    #ifndef QNX6_SUPER_MAGIC
    # ifndef _QNX6_SUPER_MAGIC
    #  define QNX6_SUPER_MAGIC -1
    # else
    #  define QNX6_SUPER_MAGIC _QNX6_SUPER_MAGIC
    # endif
    #endif
    #ifndef RAMFS_MAGIC
    # ifndef _RAMFS_MAGIC
    #  define RAMFS_MAGIC -1
    # else
    #  define RAMFS_MAGIC _RAMFS_MAGIC
    # endif
    #endif
    #ifndef REISERFS_SUPER_MAGIC
    # ifndef _REISERFS_SUPER_MAGIC
    #  define REISERFS_SUPER_MAGIC -1
    # else
    #  define REISERFS_SUPER_MAGIC _REISERFS_SUPER_MAGIC
    # endif
    #endif
    #ifndef ROMFS_MAGIC
    # ifndef _ROMFS_MAGIC
    #  define ROMFS_MAGIC -1
    # else
    #  define ROMFS_MAGIC _ROMFS_MAGIC
    # endif
    #endif
    #ifndef SECURITYFS_MAGIC
    # ifndef _SECURITYFS_MAGIC
    #  define SECURITYFS_MAGIC -1
    # else
    #  define SECURITYFS_MAGIC _SECURITYFS_MAGIC
    # endif
    #endif
    #ifndef SELINUX_MAGIC
    # ifndef _SELINUX_MAGIC
    #  define SELINUX_MAGIC -1
    # else
    #  define SELINUX_MAGIC _SELINUX_MAGIC
    # endif
    #endif
    #ifndef SMACK_MAGIC
    # ifndef _SMACK_MAGIC
    #  define SMACK_MAGIC -1
    # else
    #  define SMACK_MAGIC _SMACK_MAGIC
    # endif
    #endif
    #ifndef SMB_SUPER_MAGIC
    # ifndef _SMB_SUPER_MAGIC
    #  define SMB_SUPER_MAGIC -1
    # else
    #  define SMB_SUPER_MAGIC _SMB_SUPER_MAGIC
    # endif
    #endif
    #ifndef SMB2_MAGIC_NUMBER
    # ifndef _SMB2_MAGIC_NUMBER
    #  define SMB2_MAGIC_NUMBER -1
    # else
    #  define SMB2_MAGIC_NUMBER _SMB2_MAGIC_NUMBER
    # endif
    #endif
    #ifndef SOCKFS_MAGIC
    # ifndef _SOCKFS_MAGIC
    #  define SOCKFS_MAGIC -1
    # else
    #  define SOCKFS_MAGIC _SOCKFS_MAGIC
    # endif
    #endif
    #ifndef SQUASHFS_MAGIC
    # ifndef _SQUASHFS_MAGIC
    #  define SQUASHFS_MAGIC -1
    # else
    #  define SQUASHFS_MAGIC _SQUASHFS_MAGIC
    # endif
    #endif
    #ifndef SYSFS_MAGIC
    # ifndef _SYSFS_MAGIC
    #  define SYSFS_MAGIC -1
    # else
    #  define SYSFS_MAGIC _SYSFS_MAGIC
    # endif
    #endif
    #ifndef SYSV2_SUPER_MAGIC
    # ifndef _SYSV2_SUPER_MAGIC
    #  define SYSV2_SUPER_MAGIC -1
    # else
    #  define SYSV2_SUPER_MAGIC _SYSV2_SUPER_MAGIC
    # endif
    #endif
    #ifndef SYSV4_SUPER_MAGIC
    # ifndef _SYSV4_SUPER_MAGIC
    #  define SYSV4_SUPER_MAGIC -1
    # else
    #  define SYSV4_SUPER_MAGIC _SYSV4_SUPER_MAGIC
    # endif
    #endif
    #ifndef TMPFS_MAGIC
    # ifndef _TMPFS_MAGIC
    #  define TMPFS_MAGIC -1
    # else
    #  define TMPFS_MAGIC _TMPFS_MAGIC
    # endif
    #endif
    #ifndef TRACEFS_MAGIC
    # ifndef _TRACEFS_MAGIC
    #  define TRACEFS_MAGIC -1
    # else
    #  define TRACEFS_MAGIC _TRACEFS_MAGIC
    # endif
    #endif
    #ifndef UDF_SUPER_MAGIC
    # ifndef _UDF_SUPER_MAGIC
    #  define UDF_SUPER_MAGIC -1
    # else
    #  define UDF_SUPER_MAGIC _UDF_SUPER_MAGIC
    # endif
    #endif
    #ifndef UFS_MAGIC
    # ifndef _UFS_MAGIC
    #  define UFS_MAGIC -1
    # else
    #  define UFS_MAGIC _UFS_MAGIC
    # endif
    #endif
    #ifndef USBDEVICE_SUPER_MAGIC
    # ifndef _USBDEVICE_SUPER_MAGIC
    #  define USBDEVICE_SUPER_MAGIC -1
    # else
    #  define USBDEVICE_SUPER_MAGIC _USBDEVICE_SUPER_MAGIC
    # endif
    #endif
    #ifndef V9FS_MAGIC
    # ifndef _V9FS_MAGIC
    #  define V9FS_MAGIC -1
    # else
    #  define V9FS_MAGIC _V9FS_MAGIC
    # endif
    #endif
    #ifndef VXFS_SUPER_MAGIC
    # ifndef _VXFS_SUPER_MAGIC
    #  define VXFS_SUPER_MAGIC -1
    # else
    #  define VXFS_SUPER_MAGIC _VXFS_SUPER_MAGIC
    # endif
    #endif
    #ifndef XENFS_SUPER_MAGIC
    # ifndef _XENFS_SUPER_MAGIC
    #  define XENFS_SUPER_MAGIC -1
    # else
    #  define XENFS_SUPER_MAGIC _XENFS_SUPER_MAGIC
    # endif
    #endif
    #ifndef XENIX_SUPER_MAGIC
    # ifndef _XENIX_SUPER_MAGIC
    #  define XENIX_SUPER_MAGIC -1
    # else
    #  define XENIX_SUPER_MAGIC _XENIX_SUPER_MAGIC
    # endif
    #endif
    #ifndef XFS_SUPER_MAGIC
    # ifndef _XFS_SUPER_MAGIC
    #  define XFS_SUPER_MAGIC -1
    # else
    #  define XFS_SUPER_MAGIC _XFS_SUPER_MAGIC
    # endif
    #endif
    #ifndef XIAFS_SUPER_MAGIC
    # ifndef _XIAFS_SUPER_MAGIC
    #  define XIAFS_SUPER_MAGIC -1
    # else
    #  define XIAFS_SUPER_MAGIC _XIAFS_SUPER_MAGIC
    # endif
    #endif
    """
    unsigned long ADFS_SUPER_MAGIC
    unsigned long AFFS_SUPER_MAGIC
    unsigned long AFS_SUPER_MAGIC
    unsigned long ANON_INODE_FS_MAGIC
    unsigned long AUTOFS_SUPER_MAGIC
    unsigned long BDEVFS_MAGIC
    unsigned long BEFS_SUPER_MAGIC
    unsigned long BFS_MAGIC
    unsigned long BINFMTFS_MAGIC
    unsigned long BPF_FS_MAGIC
    unsigned long BTRFS_SUPER_MAGIC
    unsigned long BTRFS_TEST_MAGIC
    unsigned long CGROUP_SUPER_MAGIC
    unsigned long CGROUP2_SUPER_MAGIC
    unsigned long CIFS_MAGIC_NUMBER
    unsigned long CODA_SUPER_MAGIC
    unsigned long COH_SUPER_MAGIC
    unsigned long CRAMFS_MAGIC
    unsigned long DEBUGFS_MAGIC
    unsigned long DEVFS_SUPER_MAGIC
    unsigned long DEVPTS_SUPER_MAGIC
    unsigned long ECRYPTFS_SUPER_MAGIC
    unsigned long EFIVARFS_MAGIC
    unsigned long EFS_SUPER_MAGIC
    unsigned long EXT_SUPER_MAGIC
    unsigned long EXT2_OLD_SUPER_MAGIC
    unsigned long EXT2_SUPER_MAGIC
    unsigned long EXT3_SUPER_MAGIC
    unsigned long EXT4_SUPER_MAGIC
    unsigned long F2FS_SUPER_MAGIC
    unsigned long FUSE_SUPER_MAGIC
    unsigned long FUTEXFS_SUPER_MAGIC
    unsigned long HFS_SUPER_MAGIC
    unsigned long HOSTFS_SUPER_MAGIC
    unsigned long HPFS_SUPER_MAGIC
    unsigned long HUGETLBFS_MAGIC
    unsigned long ISOFS_SUPER_MAGIC
    unsigned long JFFS2_SUPER_MAGIC
    unsigned long JFS_SUPER_MAGIC
    unsigned long MINIX_SUPER_MAGIC
    unsigned long MINIX_SUPER_MAGIC2
    unsigned long MINIX2_SUPER_MAGIC
    unsigned long MINIX2_SUPER_MAGIC2
    unsigned long MINIX3_SUPER_MAGIC
    unsigned long MQUEUE_MAGIC
    unsigned long MSDOS_SUPER_MAGIC
    unsigned long MTD_INODE_FS_MAGIC
    unsigned long NCP_SUPER_MAGIC
    unsigned long NFS_SUPER_MAGIC
    unsigned long NILFS_SUPER_MAGIC
    unsigned long NSFS_MAGIC
    unsigned long NTFS_SB_MAGIC
    unsigned long OCFS2_SUPER_MAGIC
    unsigned long OPENPROM_SUPER_MAGIC
    unsigned long OVERLAYFS_SUPER_MAGIC
    unsigned long PIPEFS_MAGIC
    unsigned long PROC_SUPER_MAGIC
    unsigned long PSTOREFS_MAGIC
    unsigned long QNX4_SUPER_MAGIC
    unsigned long QNX6_SUPER_MAGIC
    unsigned long RAMFS_MAGIC
    unsigned long REISERFS_SUPER_MAGIC
    unsigned long ROMFS_MAGIC
    unsigned long SECURITYFS_MAGIC
    unsigned long SELINUX_MAGIC
    unsigned long SMACK_MAGIC
    unsigned long SMB_SUPER_MAGIC
    unsigned long SMB2_MAGIC_NUMBER
    unsigned long SOCKFS_MAGIC
    unsigned long SQUASHFS_MAGIC
    unsigned long SYSFS_MAGIC
    unsigned long SYSV2_SUPER_MAGIC
    unsigned long SYSV4_SUPER_MAGIC
    unsigned long TMPFS_MAGIC
    unsigned long TRACEFS_MAGIC
    unsigned long UDF_SUPER_MAGIC
    unsigned long UFS_MAGIC
    unsigned long USBDEVICE_SUPER_MAGIC
    unsigned long V9FS_MAGIC
    unsigned long VXFS_SUPER_MAGIC
    unsigned long XENFS_SUPER_MAGIC
    unsigned long XENIX_SUPER_MAGIC
    unsigned long XFS_SUPER_MAGIC
    unsigned long XIAFS_SUPER_MAGIC


