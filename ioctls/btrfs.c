#ifdef USE_BTRFS
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <linux/fs.h>
#include <linux/btrfs.h>
#include <linux/btrfs_tree.h>
#include "ioctls.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "scratch_block.h"
#include "shm.h"
#include "syscall.h"
#include "utils.h"

#ifndef BTRFS_LABEL_SIZE
#define BTRFS_LABEL_SIZE 256
#endif

#ifndef BTRFS_IOC_SET_RECEIVED_SUBVOL_32

/* If we have a 32-bit userspace and 64-bit kernel, then the UAPI
 * structures are incorrect, as the timespec structure from userspace
 * is 4 bytes too small. We define these alternatives here to teach
 * the kernel about the 32-bit struct packing.
 */
struct btrfs_ioctl_timespec_32 {
	__u64 sec;
	__u32 nsec;
} __attribute__((__packed__));

struct btrfs_ioctl_received_subvol_args_32 {
	char	uuid[BTRFS_UUID_SIZE];  /* in */
	__u64   stransid;		/* in */
	__u64   rtransid;		/* out */
	struct btrfs_ioctl_timespec_32 stime; /* in */
	struct btrfs_ioctl_timespec_32 rtime; /* out */
	__u64   flags;			/* in */
	__u64   reserved[16];		/* in */
};

#define BTRFS_IOC_SET_RECEIVED_SUBVOL_32 _IOWR(BTRFS_IOCTL_MAGIC, 37, \
	struct btrfs_ioctl_received_subvol_args_32)
#endif

/*
 * Compile-time: fixed-shape ioctl args must match _IOC_SIZE.  A
 * failure means the btrfs UAPI moved and the sanitiser's
 * memset(sizeof(*args)) is against a stale layout -- fix the
 * sanitiser, do not silence.  Flex-tail cmds (TREE_SEARCH_V2 with
 * buf[], SPACE_INFO with spaces[]) are intentionally absent --
 * _IOC_SIZE covers only the header there.
 */
IOCTL_SIZE_ASSERT(BTRFS_IOC_TREE_SEARCH, struct btrfs_ioctl_search_args);
IOCTL_SIZE_ASSERT(BTRFS_IOC_INO_LOOKUP, struct btrfs_ioctl_ino_lookup_args);
IOCTL_SIZE_ASSERT(BTRFS_IOC_INO_PATHS, struct btrfs_ioctl_ino_path_args);
IOCTL_SIZE_ASSERT(BTRFS_IOC_LOGICAL_INO, struct btrfs_ioctl_logical_ino_args);
#ifdef BTRFS_IOC_LOGICAL_INO_V2
IOCTL_SIZE_ASSERT(BTRFS_IOC_LOGICAL_INO_V2, struct btrfs_ioctl_logical_ino_args);
#endif
IOCTL_SIZE_ASSERT(BTRFS_IOC_DEV_INFO, struct btrfs_ioctl_dev_info_args);
IOCTL_SIZE_ASSERT(BTRFS_IOC_FS_INFO, struct btrfs_ioctl_fs_info_args);
IOCTL_SIZE_ASSERT(BTRFS_IOC_GET_FEATURES, struct btrfs_ioctl_feature_flags);
IOCTL_SIZE_ASSERT(BTRFS_IOC_QUOTA_RESCAN_STATUS, struct btrfs_ioctl_quota_rescan_args);
#ifdef BTRFS_IOC_GET_SUBVOL_INFO
IOCTL_SIZE_ASSERT(BTRFS_IOC_GET_SUBVOL_INFO, struct btrfs_ioctl_get_subvol_info_args);
#endif
IOCTL_SIZE_ASSERT(BTRFS_IOC_SNAP_CREATE_V2, struct btrfs_ioctl_vol_args_v2);
IOCTL_SIZE_ASSERT(BTRFS_IOC_SUBVOL_CREATE_V2, struct btrfs_ioctl_vol_args_v2);
IOCTL_SIZE_ASSERT(BTRFS_IOC_SUBVOL_GETFLAGS, __u64);

static int btrfs_fd_test(int fd, const struct stat *st __attribute__((unused)))
{
	struct objhead *head;
	struct object *obj;
	unsigned int idx;
	unsigned int count;
	unsigned int i;
	bool isolated;
	bool seen_btrfs = false;

	/*
	 * Box-safety + isolation gate (mirror childops/fs/umount-race.c's
	 * mnt_ready + scratch_block_ready double-check).  When the parent
	 * latched a private mount namespace AND the scratch_block pool
	 * stood up AND it published a btrfs-typed entry, the only block
	 * fd this group is allowed to claim is that entry's loop fd --
	 * never a host disk node, never an OBJ_FD_TESTFILE plain file
	 * (those live in trinity's cwd, which on a typical fuzz box sits
	 * on the host's real-root btrfs filesystem).  When any latch is
	 * false, or no btrfs entry is published in the pool, fall
	 * through to today's OBJ_FD_TESTFILE walk byte-for-byte so the
	 * non-root / non-isolated dev path is unchanged.
	 */
	isolated = __atomic_load_n(&shm->isolation.mnt_ready,
				   __ATOMIC_RELAXED) &&
		   __atomic_load_n(&shm->isolation.scratch_block_ready,
				   __ATOMIC_RELAXED);
	if (isolated) {
		count = load_scratch_block_count();
		for (i = 0; i < count; i++) {
			struct scratch_block_entry *e =
				&shm->isolation.scratch_block[i];

			if (strncmp(e->fs_type, "btrfs",
				    sizeof(e->fs_type)) != 0)
				continue;
			seen_btrfs = true;
			if (e->loop_fd >= 0 && e->loop_fd == fd)
				return 0;
		}
		/*
		 * A published btrfs entry exists but @fd isn't its loop
		 * fd: refuse the claim.  Falling through to the
		 * OBJ_FD_TESTFILE walk would put btrfs ioctls back on
		 * host-fs files.
		 */
		if (seen_btrfs)
			return -1;
	}

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_TESTFILE);

	for_each_obj(head, obj, idx) {
		if (obj->testfileobj.fd == fd)
			return 0;
	}

	return -1;
}

static const struct ioctl btrfs_ioctls[] = {
	{ .name = "FS_IOC_GETFLAGS", .request = FS_IOC_GETFLAGS, },
	{ .name = "FS_IOC_SETFLAGS", .request = FS_IOC_SETFLAGS, },
	{ .name = "FS_IOC_GETVERSION", .request = FS_IOC_GETVERSION, },
	{ .name = "FITRIM", .request = FITRIM, },

	{ .name = "BTRFS_IOC_SNAP_CREATE", .request = BTRFS_IOC_SNAP_CREATE, },
	{ .name = "BTRFS_IOC_SNAP_CREATE_V2", .request = BTRFS_IOC_SNAP_CREATE_V2, },
	{ .name = "BTRFS_IOC_SUBVOL_CREATE", .request = BTRFS_IOC_SUBVOL_CREATE, },
	{ .name = "BTRFS_IOC_SUBVOL_CREATE_V2", .request = BTRFS_IOC_SUBVOL_CREATE_V2, },
	{ .name = "BTRFS_IOC_SNAP_DESTROY", .request = BTRFS_IOC_SNAP_DESTROY, },
#ifdef BTRFS_IOC_SNAP_DESTROY_V2
	{ .name = "BTRFS_IOC_SNAP_DESTROY_V2", .request = BTRFS_IOC_SNAP_DESTROY_V2, },
#endif
	{ .name = "BTRFS_IOC_SUBVOL_GETFLAGS", .request = BTRFS_IOC_SUBVOL_GETFLAGS, },
	{ .name = "BTRFS_IOC_SUBVOL_SETFLAGS", .request = BTRFS_IOC_SUBVOL_SETFLAGS, },
#ifdef BTRFS_IOC_SUBVOL_SYNC_WAIT
	{ .name = "BTRFS_IOC_SUBVOL_SYNC_WAIT", .request = BTRFS_IOC_SUBVOL_SYNC_WAIT, },
#endif
	{ .name = "BTRFS_IOC_DEFAULT_SUBVOL", .request = BTRFS_IOC_DEFAULT_SUBVOL, },
	{ .name = "BTRFS_IOC_DEFRAG", .request = BTRFS_IOC_DEFRAG, },
	{ .name = "BTRFS_IOC_DEFRAG_RANGE", .request = BTRFS_IOC_DEFRAG_RANGE, },
	{ .name = "BTRFS_IOC_RESIZE", .request = BTRFS_IOC_RESIZE, },
	{ .name = "BTRFS_IOC_SCAN_DEV", .request = BTRFS_IOC_SCAN_DEV, },
#ifdef BTRFS_IOC_FORGET_DEV
	{ .name = "BTRFS_IOC_FORGET_DEV", .request = BTRFS_IOC_FORGET_DEV, },
#endif
	{ .name = "BTRFS_IOC_ADD_DEV", .request = BTRFS_IOC_ADD_DEV, },
	{ .name = "BTRFS_IOC_RM_DEV", .request = BTRFS_IOC_RM_DEV, },
#ifdef BTRFS_IOC_RM_DEV_V2
	{ .name = "BTRFS_IOC_RM_DEV_V2", .request = BTRFS_IOC_RM_DEV_V2, },
#endif
#ifdef BTRFS_IOC_DEVICES_READY
	{ .name = "BTRFS_IOC_DEVICES_READY", .request = BTRFS_IOC_DEVICES_READY, },
#endif
	{ .name = "BTRFS_IOC_FS_INFO", .request = BTRFS_IOC_FS_INFO, },
	{ .name = "BTRFS_IOC_DEV_INFO", .request = BTRFS_IOC_DEV_INFO, },
	{ .name = "BTRFS_IOC_BALANCE", .request = BTRFS_IOC_BALANCE, },
	{ .name = "BTRFS_IOC_TRANS_START", .request = BTRFS_IOC_TRANS_START, },
	{ .name = "BTRFS_IOC_TRANS_END", .request = BTRFS_IOC_TRANS_END, },
	{ .name = "BTRFS_IOC_TREE_SEARCH", .request = BTRFS_IOC_TREE_SEARCH, },
	{ .name = "BTRFS_IOC_TREE_SEARCH_V2", .request = BTRFS_IOC_TREE_SEARCH_V2, },
	{ .name = "BTRFS_IOC_INO_LOOKUP", .request = BTRFS_IOC_INO_LOOKUP, },
#ifdef BTRFS_IOC_INO_LOOKUP_USER
	{ .name = "BTRFS_IOC_INO_LOOKUP_USER", .request = BTRFS_IOC_INO_LOOKUP_USER, },
#endif
	{ .name = "BTRFS_IOC_INO_PATHS", .request = BTRFS_IOC_INO_PATHS, },
	{ .name = "BTRFS_IOC_LOGICAL_INO", .request = BTRFS_IOC_LOGICAL_INO, },
#ifdef BTRFS_IOC_LOGICAL_INO_V2
	{ .name = "BTRFS_IOC_LOGICAL_INO_V2", .request = BTRFS_IOC_LOGICAL_INO_V2, },
#endif
	{ .name = "BTRFS_IOC_SPACE_INFO", .request = BTRFS_IOC_SPACE_INFO, },
	{ .name = "BTRFS_IOC_SYNC", .request = BTRFS_IOC_SYNC, },
	{ .name = "BTRFS_IOC_START_SYNC", .request = BTRFS_IOC_START_SYNC, },
	{ .name = "BTRFS_IOC_WAIT_SYNC", .request = BTRFS_IOC_WAIT_SYNC, },
	{ .name = "BTRFS_IOC_SCRUB", .request = BTRFS_IOC_SCRUB, },
	{ .name = "BTRFS_IOC_SCRUB_CANCEL", .request = BTRFS_IOC_SCRUB_CANCEL, },
	{ .name = "BTRFS_IOC_SCRUB_PROGRESS", .request = BTRFS_IOC_SCRUB_PROGRESS, },
	{ .name = "BTRFS_IOC_BALANCE_V2", .request = BTRFS_IOC_BALANCE_V2, },
	{ .name = "BTRFS_IOC_BALANCE_CTL", .request = BTRFS_IOC_BALANCE_CTL, },
	{ .name = "BTRFS_IOC_BALANCE_PROGRESS", .request = BTRFS_IOC_BALANCE_PROGRESS, },
	{ .name = "BTRFS_IOC_SET_RECEIVED_SUBVOL", .request = BTRFS_IOC_SET_RECEIVED_SUBVOL, },
	{ .name = "BTRFS_IOC_SET_RECEIVED_SUBVOL_32", .request = BTRFS_IOC_SET_RECEIVED_SUBVOL_32, },
	{ .name = "BTRFS_IOC_SEND", .request = BTRFS_IOC_SEND, },
#ifdef BTRFS_IOC_ENCODED_READ
	{ .name = "BTRFS_IOC_ENCODED_READ", .request = BTRFS_IOC_ENCODED_READ, },
#endif
#ifdef BTRFS_IOC_ENCODED_WRITE
	{ .name = "BTRFS_IOC_ENCODED_WRITE", .request = BTRFS_IOC_ENCODED_WRITE, },
#endif
	{ .name = "BTRFS_IOC_GET_DEV_STATS", .request = BTRFS_IOC_GET_DEV_STATS, },
	{ .name = "BTRFS_IOC_QUOTA_CTL", .request = BTRFS_IOC_QUOTA_CTL, },
	{ .name = "BTRFS_IOC_QGROUP_ASSIGN", .request = BTRFS_IOC_QGROUP_ASSIGN, },
	{ .name = "BTRFS_IOC_QGROUP_CREATE", .request = BTRFS_IOC_QGROUP_CREATE, },
	{ .name = "BTRFS_IOC_QGROUP_LIMIT", .request = BTRFS_IOC_QGROUP_LIMIT, },
	{ .name = "BTRFS_IOC_QUOTA_RESCAN", .request = BTRFS_IOC_QUOTA_RESCAN, },
	{ .name = "BTRFS_IOC_QUOTA_RESCAN_STATUS", .request = BTRFS_IOC_QUOTA_RESCAN_STATUS, },
	{ .name = "BTRFS_IOC_QUOTA_RESCAN_WAIT", .request = BTRFS_IOC_QUOTA_RESCAN_WAIT, },
	{ .name = "BTRFS_IOC_DEV_REPLACE", .request = BTRFS_IOC_DEV_REPLACE, },
	{ .name = "BTRFS_IOC_GET_FSLABEL", .request = BTRFS_IOC_GET_FSLABEL, },
	{ .name = "BTRFS_IOC_SET_FSLABEL", .request = BTRFS_IOC_SET_FSLABEL, },
	{ .name = "BTRFS_IOC_GET_SUPPORTED_FEATURES", .request = BTRFS_IOC_GET_SUPPORTED_FEATURES, },
	{ .name = "BTRFS_IOC_GET_FEATURES", .request = BTRFS_IOC_GET_FEATURES, },
	{ .name = "BTRFS_IOC_SET_FEATURES", .request = BTRFS_IOC_SET_FEATURES, },
#ifdef BTRFS_IOC_GET_SUBVOL_INFO
	{ .name = "BTRFS_IOC_GET_SUBVOL_INFO", .request = BTRFS_IOC_GET_SUBVOL_INFO, },
#endif
#ifdef BTRFS_IOC_GET_SUBVOL_ROOTREF
	{ .name = "BTRFS_IOC_GET_SUBVOL_ROOTREF", .request = BTRFS_IOC_GET_SUBVOL_ROOTREF, },
#endif
	{ .name = "BTRFS_IOC_CLONE", .request = BTRFS_IOC_CLONE, },
	{ .name = "BTRFS_IOC_CLONE_RANGE", .request = BTRFS_IOC_CLONE_RANGE, },
	{ .name = "BTRFS_IOC_FILE_EXTENT_SAME", .request = BTRFS_IOC_FILE_EXTENT_SAME, },
};

/*
 * Bounded flex-array sizings.  TREE_SEARCH_V2's buf[] and SPACE_INFO's
 * spaces[] are flex tails whose payload is sized by a leading count/size
 * field; the generic _IOC_SIZE-shaped buffer from pick_random_ioctl()
 * doesn't reserve room for them and would have the kernel write past the
 * buffer.  Cap at small counts so the tail allocation always covers what
 * the leading field claims, and randomise the rest so the parser still
 * sees varied keys / slot counts.
 */
#define BTRFS_FUZZ_SEARCH_V2_BUF		4096
#define BTRFS_FUZZ_DATA_CONTAINER_BUF		4096
#define BTRFS_FUZZ_SPACE_SLOTS			8

/*
 * Seed a btrfs_ioctl_search_key with a sane low-id tree, full key range,
 * bounded nr_items, and full transid range.  The kernel walks the b-tree
 * for keys in [min_*, max_*] up to nr_items entries -- bounded counts
 * keep the walk short so the child returns to the fuzz loop quickly.
 * tree_id 0 means "the subvolume that owns the inode the ioctl is on"
 * (typical real-mount usage); the small vocab covers fs_tree / extent /
 * chunk / dev / root trees too.
 */
static void seed_btrfs_search_key(struct btrfs_ioctl_search_key *k)
{
	k->tree_id = (__u64)rnd_modulo_u32(8);
	k->min_objectid = 0;
	k->max_objectid = BTRFS_LAST_FREE_OBJECTID;
	k->min_offset = 0;
	k->max_offset = (__u64)-1ULL;
	k->min_transid = 0;
	k->max_transid = (__u64)-1ULL;
	k->min_type = 0;
	k->max_type = 0xff;
	k->nr_items = (__u32)(rnd_modulo_u32(64) + 1);
	k->unused = 0;
	k->unused1 = 0;
	k->unused2 = 0;
	k->unused3 = 0;
	k->unused4 = 0;
}

static void sanitise_btrfs_tree_search(struct syscallrecord *rec)
{
	struct btrfs_ioctl_search_args *args;

	args = get_writable_address(sizeof(*args));
	if (args == NULL)
		return;

	generate_rand_bytes((unsigned char *)args, sizeof(*args));
	seed_btrfs_search_key(&args->key);

	rec->a3 = (unsigned long)args;
}

static void sanitise_btrfs_tree_search_v2(struct syscallrecord *rec)
{
	struct btrfs_ioctl_search_args_v2 *args;
	unsigned long sz;

	sz = sizeof(*args) + BTRFS_FUZZ_SEARCH_V2_BUF;
	args = get_writable_address(sz);
	if (args == NULL)
		return;

	generate_rand_bytes((unsigned char *)args, sz);
	seed_btrfs_search_key(&args->key);
	args->buf_size = BTRFS_FUZZ_SEARCH_V2_BUF;

	rec->a3 = (unsigned long)args;
}

static void sanitise_btrfs_ino_lookup(struct syscallrecord *rec)
{
	struct btrfs_ioctl_ino_lookup_args *args;

	args = get_writable_address(sizeof(*args));
	if (args == NULL)
		return;

	generate_rand_bytes((unsigned char *)args, sizeof(*args));
	args->treeid = (__u64)rnd_modulo_u32(8);
	args->objectid = BTRFS_FIRST_FREE_OBJECTID +
			 (__u64)rnd_modulo_u32(4096);
	/* Output path field -- NUL-terminate the leading byte so the
	 * kernel doesn't read garbage if it ever inspects the input
	 * side, and so the return path has a defined initial state. */
	args->name[0] = '\0';

	rec->a3 = (unsigned long)args;
}

static void sanitise_btrfs_ino_paths(struct syscallrecord *rec)
{
	struct btrfs_ioctl_ino_path_args *args;
	void *databuf;

	args = get_writable_address(sizeof(*args));
	if (args == NULL)
		return;

	databuf = get_writable_address(BTRFS_FUZZ_DATA_CONTAINER_BUF);
	if (databuf == NULL)
		return;

	generate_rand_bytes((unsigned char *)args, sizeof(*args));
	args->inum = BTRFS_FIRST_FREE_OBJECTID +
		     (__u64)rnd_modulo_u32(4096);
	args->size = BTRFS_FUZZ_DATA_CONTAINER_BUF;
	args->reserved[0] = 0;
	args->reserved[1] = 0;
	args->reserved[2] = 0;
	args->reserved[3] = 0;
	args->fspath = (__u64)(unsigned long)databuf;

	rec->a3 = (unsigned long)args;
}

static void sanitise_btrfs_logical_ino(struct syscallrecord *rec)
{
	struct btrfs_ioctl_logical_ino_args *args;
	void *databuf;

	args = get_writable_address(sizeof(*args));
	if (args == NULL)
		return;

	databuf = get_writable_address(BTRFS_FUZZ_DATA_CONTAINER_BUF);
	if (databuf == NULL)
		return;

	generate_rand_bytes((unsigned char *)args, sizeof(*args));
	args->logical = rnd_u64();
	args->size = BTRFS_FUZZ_DATA_CONTAINER_BUF;
	args->reserved[0] = 0;
	args->reserved[1] = 0;
	args->reserved[2] = 0;
	args->flags = (__u64)rnd_u32() & BTRFS_LOGICAL_INO_ARGS_IGNORE_OFFSET;
	args->inodes = (__u64)(unsigned long)databuf;

	rec->a3 = (unsigned long)args;
}

static void sanitise_btrfs_space_info(struct syscallrecord *rec)
{
	struct btrfs_ioctl_space_args *args;
	unsigned long sz;

	sz = sizeof(*args) +
	     (unsigned long)BTRFS_FUZZ_SPACE_SLOTS *
	     sizeof(struct btrfs_ioctl_space_info);
	args = get_writable_address(sz);
	if (args == NULL)
		return;

	generate_rand_bytes((unsigned char *)args, sz);
	args->space_slots = BTRFS_FUZZ_SPACE_SLOTS;
	args->total_spaces = 0;

	rec->a3 = (unsigned long)args;
}

static void sanitise_btrfs_dev_info(struct syscallrecord *rec)
{
	struct btrfs_ioctl_dev_info_args *args;

	args = get_writable_address(sizeof(*args));
	if (args == NULL)
		return;

	generate_rand_bytes((unsigned char *)args, sizeof(*args));
	/* devid is in/out -- low values to maximise the chance of a hit
	 * on a real device slot.  uuid stays random; the kernel uses
	 * devid OR uuid to resolve the device. */
	args->devid = (__u64)rnd_modulo_u32(8);

	rec->a3 = (unsigned long)args;
}

static void sanitise_btrfs_out_buf(struct syscallrecord *rec, unsigned long sz)
{
	void *buf;

	buf = get_writable_address(sz);
	if (buf == NULL)
		return;

	/* Pure out-buf: zero so a partial-write kernel doesn't leave
	 * the caller looking at stale heap bits if the ioctl bails
	 * after copying only a prefix. */
	memset(buf, 0, sz);
	rec->a3 = (unsigned long)buf;
}

static void sanitise_btrfs_vol_args_v2(struct syscallrecord *rec)
{
	struct btrfs_ioctl_vol_args_v2 *args;

	args = get_writable_address(sizeof(*args));
	if (args == NULL)
		return;

	memset(args, 0, sizeof(*args));
	/*
	 * fd is the source-subvol fd for SNAP_CREATE_V2 (ignored for
	 * SUBVOL_CREATE_V2).  rec->a1 is the testfile fd -- almost never
	 * a real subvol root, so most calls EINVAL/EBADF after the
	 * parser walks the args.  That IS the edge yield here:
	 * reach + parse btrfs_ioctl_snap_create_v2 / args validation.
	 */
	args->fd = (__s64)(int)rec->a1;
	args->transid = 0;
	/*
	 * Mask to flags the kernel accepts on the create path, and
	 * drop QGROUP_INHERIT -- with it set the kernel dereferences
	 * args->qgroup_inherit, and we keep that union NULL.
	 */
	args->flags = (__u64)rnd_u32() & BTRFS_SUBVOL_CREATE_ARGS_MASK;
	args->flags &= ~(__u64)BTRFS_SUBVOL_QGROUP_INHERIT;

	/*
	 * Short bounded name, NUL-terminated.  Lands UNDER the testfile
	 * dir as a child subvolume -- recoverable via 'btrfs subvolume
	 * delete'.  The "trin_" prefix makes leftovers from a crashed
	 * run trivially identifiable.
	 */
	snprintf(args->name, sizeof(args->name), "trin_%08x",
		 rnd_u32() & 0x0fffffffu);
	args->name[sizeof(args->name) - 1] = '\0';

	rec->a3 = (unsigned long)args;
}

/*
 * btrfs_sanitise -- seed the leading discriminator fields of the
 * struct args expected by the non-destructive parse/grammar ioctls so
 * pick_random_ioctl()'s _IOC_SIZE-shaped random buffer doesn't EFAULT
 * on the first copy_from_user().  The yield is REACHING + PARSING the
 * arg structs and hitting the read-only handlers -- not executing the
 * mutators.
 *
 * 🛑 BOX-SAFETY DENYLIST (HARD -- read before adding any case below):
 * btrfs_grp's fd_test resolves OBJ_FD_TESTFILE -- plain open(O_CREAT|
 * O_RDWR) files in trinity's cwd.  On the fuzz box that cwd is the
 * REAL ROOT btrfs filesystem.  A destructive ioctl on that fd hits
 * production storage = box brick = zero coverage.  The cmds below
 * MUST NEVER be added to this switch -- leave them to the default:
 * case so pick_random_ioctl()'s random arg fill EFAULTs/EINVALs the
 * kernel out before the mutator runs:
 *
 *   BTRFS_IOC_RESIZE                  -- shrink the live root fs
 *   BTRFS_IOC_DEV_REPLACE             -- starts a device replace
 *   BTRFS_IOC_ADD_DEV                 -- adds a device to the fs
 *   BTRFS_IOC_RM_DEV, RM_DEV_V2       -- removes a device from the fs
 *   BTRFS_IOC_SCAN_DEV, FORGET_DEV    -- global device-registry mutation
 *   BTRFS_IOC_BALANCE, _V2, _CTL      -- heavy real-disk balance work
 *   BTRFS_IOC_SCRUB, SCRUB_CANCEL     -- heavy real-disk scrub work
 *   BTRFS_IOC_DEFAULT_SUBVOL          -- persistent mount-default change
 *   BTRFS_IOC_SET_RECEIVED_SUBVOL     -- stamps received_uuid on subvol
 *   BTRFS_IOC_DEFRAG, DEFRAG_RANGE    -- heavy real-disk defrag IO
 *
 * Capture the parser edges, not the drive operation.
 */
static void btrfs_sanitise(const struct ioctl_group *grp,
			   struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case BTRFS_IOC_TREE_SEARCH:
		sanitise_btrfs_tree_search(rec);
		break;
	case BTRFS_IOC_TREE_SEARCH_V2:
		sanitise_btrfs_tree_search_v2(rec);
		break;
	case BTRFS_IOC_INO_LOOKUP:
		sanitise_btrfs_ino_lookup(rec);
		break;
	case BTRFS_IOC_INO_PATHS:
		sanitise_btrfs_ino_paths(rec);
		break;
	case BTRFS_IOC_LOGICAL_INO:
#ifdef BTRFS_IOC_LOGICAL_INO_V2
	case BTRFS_IOC_LOGICAL_INO_V2:
#endif
		sanitise_btrfs_logical_ino(rec);
		break;
#ifdef BTRFS_IOC_GET_SUBVOL_INFO
	case BTRFS_IOC_GET_SUBVOL_INFO:
		sanitise_btrfs_out_buf(rec,
			sizeof(struct btrfs_ioctl_get_subvol_info_args));
		break;
#endif
	case BTRFS_IOC_SUBVOL_GETFLAGS:
		sanitise_btrfs_out_buf(rec, sizeof(__u64));
		break;
	case BTRFS_IOC_GET_FEATURES:
		sanitise_btrfs_out_buf(rec,
			sizeof(struct btrfs_ioctl_feature_flags));
		break;
	case BTRFS_IOC_FS_INFO:
		sanitise_btrfs_out_buf(rec,
			sizeof(struct btrfs_ioctl_fs_info_args));
		break;
	case BTRFS_IOC_DEV_INFO:
		sanitise_btrfs_dev_info(rec);
		break;
	case BTRFS_IOC_SPACE_INFO:
		sanitise_btrfs_space_info(rec);
		break;
	case BTRFS_IOC_QUOTA_RESCAN_STATUS:
		sanitise_btrfs_out_buf(rec,
			sizeof(struct btrfs_ioctl_quota_rescan_args));
		break;
	case BTRFS_IOC_SNAP_CREATE_V2:
	case BTRFS_IOC_SUBVOL_CREATE_V2:
		sanitise_btrfs_vol_args_v2(rec);
		break;
	default:
		break;
	}

	__atomic_add_fetch(&shm->stats.btrfs_ioctls_dispatched, 1,
			   __ATOMIC_RELAXED);
}

static const struct ioctl_group btrfs_grp = {
	.name = "btrfs",
	.fd_test = btrfs_fd_test,
	.sanitise = btrfs_sanitise,
	.ioctls = btrfs_ioctls,
	.ioctls_cnt = ARRAY_SIZE(btrfs_ioctls),
};

REG_IOCTL_GROUP(btrfs_grp)
#endif /* USE_BTRFS */
