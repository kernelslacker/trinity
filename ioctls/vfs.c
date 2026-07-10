#include <linux/fiemap.h>
#include <linux/fs.h>
#include <linux/blktrace_api.h>
#ifdef USE_FSMAP
#include <linux/fsmap.h>
#endif
#include <linux/ioctl.h>
#include <asm/ioctls.h>
#include <string.h>
#include "ioctls.h"
#include "net.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

static int vfs_fd_test(int fd, const struct stat *st __attribute__((unused)))
{
	struct objhead *head;
	struct object *obj;
	unsigned int idx;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_PIPE);
	for_each_obj(head, obj, idx) {
		if (obj->pipeobj.fd == fd)
			return 0;
	}

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_DEVFILE);
	for_each_obj(head, obj, idx) {
		if (obj->fileobj.fd == fd)
			return 0;
	}

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_PROCFILE);
	for_each_obj(head, obj, idx) {
		if (obj->fileobj.fd == fd)
			return 0;
	}

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_SYSFILE);
	for_each_obj(head, obj, idx) {
		if (obj->fileobj.fd == fd)
			return 0;
	}

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_TESTFILE);
	for_each_obj(head, obj, idx) {
		if (obj->testfileobj.fd == fd)
			return 0;
	}

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_MEMFD);
	for_each_obj(head, obj, idx) {
		if (obj->memfdobj.fd == fd)
			return 0;
	}

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_TIMERFD);
	for_each_obj(head, obj, idx) {
		if (obj->timerfdobj.fd == fd)
			return 0;
	}

	return -1;
}

#ifndef FICLONE
#define FICLONE		_IOW(0x94, 9, int)
#endif

#ifndef FICLONERANGE
struct file_clone_range {
	__s64 src_fd;
	__u64 src_offset;
	__u64 src_length;
	__u64 dest_offset;
};
#define FICLONERANGE	_IOW(0x94, 13, struct file_clone_range)
#endif

#ifndef FIDEDUPERANGE
/* from struct btrfs_ioctl_file_extent_same_info */
struct file_dedupe_range_info {
	__s64 dest_fd;          /* in - destination file */
	__u64 dest_offset;      /* in - start of extent in destination */
	__u64 bytes_deduped;    /* out - total # of bytes we were able
				 * to dedupe from this file. */
	/* status of this dedupe operation:
	 * < 0 for error
	 * == FILE_DEDUPE_RANGE_SAME if dedupe succeeds
	 * == FILE_DEDUPE_RANGE_DIFFERS if data differs
	 */
	__s32 status;           /* out - see above description */
	__u32 reserved;         /* must be zero */
};

/* from struct btrfs_ioctl_file_extent_same_args */
struct file_dedupe_range {
	__u64 src_offset;       /* in - start of extent in source */
	__u64 src_length;       /* in - length of extent */
	__u16 dest_count;       /* in - total elements in info array */
	__u16 reserved1;        /* must be zero */
	__u32 reserved2;        /* must be zero */
	struct file_dedupe_range_info info[0];
};
#define FIDEDUPERANGE	_IOWR(0x94, 54, struct file_dedupe_range)
#endif

#ifndef FS_IOC_RESVSP
struct space_resv {
	__s16 l_type;
	__s16 l_whence;
	__s64 l_start;
	__s64 l_len;          /* len == 0 means until end of file */
	__s32 l_sysid;
	__u32 l_pid;
	__s32 l_pad[4];       /* reserved area */
};
#define FS_IOC_RESVSP		_IOW('X', 40, struct space_resv)
#endif
#ifndef FS_IOC_RESVSP64
#define FS_IOC_RESVSP64		_IOW('X', 42, struct space_resv)
#endif

/*
 * Compile-time: every fixed-shape vfs ioctl command whose arg is a
 * kernel struct must have sizeof(struct) matching the _IOC_SIZE
 * encoded in its request bits.  A mismatch means the kernel uapi
 * header moved under us and the request bits now encode a different
 * struct than we're passing (or vice versa) -- either short of the
 * kernel's copy_from_user() / copy_to_user() or past it.  Commands
 * sharing a struct (FS_IOC_RESVSP and FS_IOC_RESVSP64 both take
 * space_resv; FS_IOC_FSGETXATTR and FS_IOC_FSSETXATTR both take
 * fsxattr; FS_IOC_SET_ENCRYPTION_POLICY and
 * FS_IOC_GET_ENCRYPTION_POLICY both take fscrypt_policy) get one
 * assert each -- the two sides can drift independently in a header
 * refactor.
 *
 * FS_IOC_FIEMAP, FS_IOC_GETFSMAP and FIDEDUPERANGE encode a fixed
 * head followed by a variable-length flex-array tail (fm_extents[],
 * fmh_recs[], info[]); FIO*, BLK* and FS_IOC_GETFLAGS-family commands
 * encode a bare scalar (int / long / loff_t / size_t) or nothing at
 * all.  All are intentionally absent -- asserting sizeof(struct)
 * against a flex-array tail, a scalar, or a zero _IOC_SIZE would be
 * the wrong shape of check.
 */
_Static_assert(sizeof(struct file_clone_range) ==
	       _IOC_SIZE(FICLONERANGE),
	       "file_clone_range size vs _IOC_SIZE mismatch");
_Static_assert(sizeof(struct space_resv) ==
	       _IOC_SIZE(FS_IOC_RESVSP),
	       "space_resv size vs FS_IOC_RESVSP mismatch");
_Static_assert(sizeof(struct space_resv) ==
	       _IOC_SIZE(FS_IOC_RESVSP64),
	       "space_resv size vs FS_IOC_RESVSP64 mismatch");
#ifdef BLKTRACESETUP
_Static_assert(sizeof(struct blk_user_trace_setup) ==
	       _IOC_SIZE(BLKTRACESETUP),
	       "blk_user_trace_setup size vs _IOC_SIZE mismatch");
#endif
#ifdef FITRIM
_Static_assert(sizeof(struct fstrim_range) ==
	       _IOC_SIZE(FITRIM),
	       "fstrim_range size vs _IOC_SIZE mismatch");
#endif
#ifdef FS_IOC_FSGETXATTR
_Static_assert(sizeof(struct fsxattr) ==
	       _IOC_SIZE(FS_IOC_FSGETXATTR),
	       "fsxattr size vs FS_IOC_FSGETXATTR mismatch");
#endif
#ifdef FS_IOC_FSSETXATTR
_Static_assert(sizeof(struct fsxattr) ==
	       _IOC_SIZE(FS_IOC_FSSETXATTR),
	       "fsxattr size vs FS_IOC_FSSETXATTR mismatch");
#endif
#ifdef FS_IOC_SET_ENCRYPTION_POLICY
_Static_assert(sizeof(struct fscrypt_policy) ==
	       _IOC_SIZE(FS_IOC_SET_ENCRYPTION_POLICY),
	       "fscrypt_policy size vs FS_IOC_SET_ENCRYPTION_POLICY mismatch");
#endif
#ifdef FS_IOC_GET_ENCRYPTION_POLICY
_Static_assert(sizeof(struct fscrypt_policy) ==
	       _IOC_SIZE(FS_IOC_GET_ENCRYPTION_POLICY),
	       "fscrypt_policy size vs FS_IOC_GET_ENCRYPTION_POLICY mismatch");
#endif

/*
 * Header-count gated query: fm_extent_count == 0 makes FIEMAP a pure
 * read-only "how many extents?" probe — the kernel never reads or writes
 * the fm_extents[] tail and only stores the count in fm_mapped_extents.
 */
static void sanitise_fiemap(struct syscallrecord *rec)
{
	struct fiemap *fm;

	fm = (struct fiemap *) get_writable_struct(sizeof(*fm));
	if (!fm)
		return;
	memset(fm, 0, sizeof(*fm));
	fm->fm_start = rand64() & 0xFFFFFFFFULL;
	fm->fm_length = FIEMAP_MAX_OFFSET;
	fm->fm_flags = 0;
	fm->fm_extent_count = 0;
	rec->a3 = (unsigned long) fm;
}

#if defined(USE_FSMAP) && defined(FS_IOC_GETFSMAP)
/*
 * Same trick for GETFSMAP: fmh_count == 0 → kernel reports the rmap
 * total in fmh_entries and never touches the variable-length fmh_recs[]
 * tail. Low key all zeroes, high key all ones = "from the start, no
 * upper bound", per the fsmap.h header doc.
 */
static void sanitise_getfsmap(struct syscallrecord *rec)
{
	struct fsmap_head *fh;

	fh = (struct fsmap_head *) get_writable_struct(sizeof(*fh));
	if (!fh)
		return;
	memset(fh, 0, sizeof(*fh));
	fh->fmh_count = 0;
	memset(&fh->fmh_keys[1], 0xff, sizeof(fh->fmh_keys[1]));
	rec->a3 = (unsigned long) fh;
}
#endif

static void vfs_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case FS_IOC_FIEMAP:
		sanitise_fiemap(rec);
		break;
#ifdef FS_IOC_GETFSMAP
	case FS_IOC_GETFSMAP:
		sanitise_getfsmap(rec);
		break;
#endif
	default:
		break;
	}
}

static const struct ioctl vfs_ioctls[] = {
	{ .name = "FIOCLEX", .request = FIOCLEX, },
	{ .name = "FIONCLEX", .request = FIONCLEX, },
	{ .name = "FIONBIO", .request = FIONBIO, },
	{ .name = "FIOASYNC", .request = FIOASYNC, },
	{ .name = "FIOQSIZE", .request = FIOQSIZE, },
	{ .name = "FIFREEZE", .request = FIFREEZE, },
	{ .name = "FITHAW", .request = FITHAW, },
	{ .name = "FS_IOC_FIEMAP", .request = FS_IOC_FIEMAP, },
	{ .name = "FIGETBSZ", .request = FIGETBSZ, },
	{ .name = "FICLONE", .request = FICLONE, },
	{ .name = "FICLONERANGE", .request = FICLONERANGE, },
	{ .name = "FIDEDUPERANGE", .request = FIDEDUPERANGE, },
	{ .name = "FIBMAP", .request = FIBMAP, },
	{ .name = "FIONREAD", .request = FIONREAD, },
	{ .name = "FS_IOC_RESVSP", .request = FS_IOC_RESVSP, },
	{ .name = "FS_IOC_RESVSP64", .request = FS_IOC_RESVSP64, },
#ifdef BLKROSET
	{ .name = "BLKROSET", .request = BLKROSET, },
#endif
#ifdef BLKROGET
	{ .name = "BLKROGET", .request = BLKROGET, },
#endif
#ifdef BLKRRPART
	{ .name = "BLKRRPART", .request = BLKRRPART, },
#endif
#ifdef BLKGETSIZE
	{ .name = "BLKGETSIZE", .request = BLKGETSIZE, },
#endif
#ifdef BLKFLSBUF
	{ .name = "BLKFLSBUF", .request = BLKFLSBUF, },
#endif
#ifdef BLKRASET
	{ .name = "BLKRASET", .request = BLKRASET, },
#endif
#ifdef BLKRAGET
	{ .name = "BLKRAGET", .request = BLKRAGET, },
#endif
#ifdef BLKFRASET
	{ .name = "BLKFRASET", .request = BLKFRASET, },
#endif
#ifdef BLKFRAGET
	{ .name = "BLKFRAGET", .request = BLKFRAGET, },
#endif
#ifdef BLKSECTSET
	{ .name = "BLKSECTSET", .request = BLKSECTSET, },
#endif
#ifdef BLKSECTGET
	{ .name = "BLKSECTGET", .request = BLKSECTGET, },
#endif
#ifdef BLKSSZGET
	{ .name = "BLKSSZGET", .request = BLKSSZGET, },
#endif
#ifdef BLKBSZGET
	{ .name = "BLKBSZGET", .request = BLKBSZGET, },
#endif
#ifdef BLKBSZSET
	{ .name = "BLKBSZSET", .request = BLKBSZSET, },
#endif
#ifdef BLKGETSIZE64
	{ .name = "BLKGETSIZE64", .request = BLKGETSIZE64, },
#endif
#ifdef BLKTRACESETUP
	{ .name = "BLKTRACESETUP", .request = BLKTRACESETUP, },
#endif
#ifdef BLKTRACESTART
	{ .name = "BLKTRACESTART", .request = BLKTRACESTART, },
#endif
#ifdef BLKTRACESTOP
	{ .name = "BLKTRACESTOP", .request = BLKTRACESTOP, },
#endif
#ifdef BLKTRACETEARDOWN
	{ .name = "BLKTRACETEARDOWN", .request = BLKTRACETEARDOWN, },
#endif
#ifdef BLKDISCARD
	{ .name = "BLKDISCARD", .request = BLKDISCARD, },
#endif
#ifdef BLKIOMIN
	{ .name = "BLKIOMIN", .request = BLKIOMIN, },
#endif
#ifdef BLKIOOPT
	{ .name = "BLKIOOPT", .request = BLKIOOPT, },
#endif
#ifdef BLKALIGNOFF
	{ .name = "BLKALIGNOFF", .request = BLKALIGNOFF, },
#endif
#ifdef BLKPBSZGET
	{ .name = "BLKPBSZGET", .request = BLKPBSZGET, },
#endif
#ifdef BLKDISCARDZEROES
	{ .name = "BLKDISCARDZEROES", .request = BLKDISCARDZEROES, },
#endif
#ifdef BLKSECDISCARD
	{ .name = "BLKSECDISCARD", .request = BLKSECDISCARD, },
#endif
#ifdef BLKROTATIONAL
	{ .name = "BLKROTATIONAL", .request = BLKROTATIONAL, },
#endif
#ifdef BLKZEROOUT
	{ .name = "BLKZEROOUT", .request = BLKZEROOUT, },
#endif
#ifdef FITRIM
	{ .name = "FITRIM", .request = FITRIM, },
#endif
#ifdef FS_IOC_GETFLAGS
	{ .name = "FS_IOC_GETFLAGS", .request = FS_IOC_GETFLAGS, },
#endif
#ifdef FS_IOC_SETFLAGS
	{ .name = "FS_IOC_SETFLAGS", .request = FS_IOC_SETFLAGS, },
#endif
#ifdef FS_IOC_GETVERSION
	{ .name = "FS_IOC_GETVERSION", .request = FS_IOC_GETVERSION, },
#endif
#ifdef FS_IOC_SETVERSION
	{ .name = "FS_IOC_SETVERSION", .request = FS_IOC_SETVERSION, },
#endif
#ifdef FS_IOC32_GETFLAGS
	{ .name = "FS_IOC32_GETFLAGS", .request = FS_IOC32_GETFLAGS, },
#endif
#ifdef FS_IOC32_SETFLAGS
	{ .name = "FS_IOC32_SETFLAGS", .request = FS_IOC32_SETFLAGS, },
#endif
#ifdef FS_IOC32_GETVERSION
	{ .name = "FS_IOC32_GETVERSION", .request = FS_IOC32_GETVERSION, },
#endif
#ifdef FS_IOC32_SETVERSION
	{ .name = "FS_IOC32_SETVERSION", .request = FS_IOC32_SETVERSION, },
#endif
#ifdef FS_IOC_FSGETXATTR
	{ .name = "FS_IOC_FSGETXATTR", .request = FS_IOC_FSGETXATTR, },
#endif
#ifdef FS_IOC_FSSETXATTR
	{ .name = "FS_IOC_FSSETXATTR", .request = FS_IOC_FSSETXATTR, },
#endif
#ifdef FS_IOC_SET_ENCRYPTION_POLICY
	{ .name = "FS_IOC_SET_ENCRYPTION_POLICY", .request = FS_IOC_SET_ENCRYPTION_POLICY, },
#endif
#ifdef FS_IOC_GET_ENCRYPTION_PWSALT
	{ .name = "FS_IOC_GET_ENCRYPTION_PWSALT", .request = FS_IOC_GET_ENCRYPTION_PWSALT, },
#endif
#ifdef FS_IOC_GET_ENCRYPTION_POLICY
	{ .name = "FS_IOC_GET_ENCRYPTION_POLICY", .request = FS_IOC_GET_ENCRYPTION_POLICY, },
#endif
#ifdef FS_IOC_GETFSMAP
	{ .name = "FS_IOC_GETFSMAP", .request = FS_IOC_GETFSMAP, },
#endif
};

static const struct ioctl_group vfs_grp = {
	.name = "vfs",
	.fd_test = vfs_fd_test,
	.sanitise = vfs_sanitise,
	.ioctls = vfs_ioctls,
	.ioctls_cnt = ARRAY_SIZE(vfs_ioctls),
};

REG_IOCTL_GROUP(vfs_grp)
