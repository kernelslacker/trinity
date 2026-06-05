/*
 * SYSCALL_DEFINE5(open_tree_attr, int, dfd, const char __user *, filename,
 *		unsigned, flags, struct mount_attr __user *, uattr, size_t, usize)
 */
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <linux/mount.h>
#include "csfu.h"
#include "deferred-free.h"
#include "object-types.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE		1
#define OPEN_TREE_CLOEXEC	O_CLOEXEC
#endif

#ifndef AT_RECURSIVE
#define AT_RECURSIVE		0x8000
#endif

/*
 * Mutually-exclusive propagation flags.  do_change_type() EINVALs the
 * moment two bits are set, so an OR over the four-element pool would
 * almost always trip the validator before the propagation arm runs.
 * Pick exactly one per call.
 */
static const __u64 mount_attr_propagation[] = {
	MS_PRIVATE, MS_SLAVE, MS_SHARED, MS_UNBINDABLE,
};

/*
 * nosuid/nodev/noexec form a safe OR co-bucket: every non-empty
 * subset is accepted in attr_set on any mount.  RDONLY gets its own
 * bucket above -- in real workloads attr_set is overwhelmingly
 * RDONLY-alone, so carving it out keeps that shape dominant while
 * leaving the secure-mode subset exercised on its own dispatch.
 */
static const __u64 mount_attr_ndns[] = {
	MOUNT_ATTR_NOSUID, MOUNT_ATTR_NODEV, MOUNT_ATTR_NOEXEC,
};

/*
 * Lazy-cache a real user-namespace fd for the MOUNT_ATTR_IDMAP /
 * userns_fd bucket.  Per-process static is enough: trinity forks per
 * child and the open file is inherited through the fork, so the fd
 * survives without a re-open in the child.  If the kernel was built
 * without CONFIG_USER_NS or /proc is not mounted, open() returns -1
 * and the caller falls back to the all-zero attrs shape so the slot
 * still produces a valid syscall.
 */
static int get_cached_userns_fd(void)
{
	static int cached = -2;

	if (cached == -2)
		cached = open("/proc/self/ns/user", O_RDONLY | O_CLOEXEC);
	return cached;
}

/*
 * Build the mount_attr structure from explicit shape buckets.  Random
 * byte-fill rarely produces a legal combination: the propagation
 * field has mutually-exclusive bits, userns_fd must be a real
 * namespace fd or zero, and attr_set / attr_clr can conflict with
 * each other.  The explicit buckets steer past those early EINVAL
 * gates into the per-attr arms while keeping a small random tail to
 * exercise unmodelled bit patterns.
 */
static void build_mount_attr(struct mount_attr *ma)
{
	unsigned int bucket = rnd_modulo_u32(100);
	unsigned int i, n;

	memset(ma, 0, sizeof(*ma));

	if (bucket < 30)
		return;					/* 30%: no attrs */

	if (bucket < 55) {
		/* 25%: RDONLY-only -- the dominant real-world shape. */
		ma->attr_set = MOUNT_ATTR_RDONLY;
		return;
	}

	if (bucket < 70) {
		/* 15%: non-empty subset of nosuid/nodev/noexec. */
		n = 1 + rnd_modulo_u32(ARRAY_SIZE(mount_attr_ndns));
		for (i = 0; i < n; i++)
			ma->attr_set |=
				mount_attr_ndns[rnd_modulo_u32(ARRAY_SIZE(mount_attr_ndns))];
		return;
	}

	if (bucket < 80) {
		/* 10%: exactly one propagation type. */
		ma->propagation =
			mount_attr_propagation[rnd_modulo_u32(ARRAY_SIZE(mount_attr_propagation))];
		return;
	}

	if (bucket < 90) {
		/* 10%: idmapped mount via a real userns fd.  Falls back to
		 * the all-zero shape if userns is unavailable so the slot
		 * still issues a valid call rather than a guaranteed
		 * EBADF on a bogus userns_fd. */
		int ufd = get_cached_userns_fd();

		if (ufd >= 0) {
			ma->attr_set = MOUNT_ATTR_IDMAP;
			ma->userns_fd = (__u64) (unsigned int) ufd;
		}
		return;
	}

	/* 10%: pure random bytes -- copy_struct_from_user, attr_set
	 * validator, and the propagation OR-check stay warm against
	 * unmodelled bit patterns. */
	generate_rand_bytes((unsigned char *) ma, sizeof(*ma));
}

static unsigned long pick_open_tree_attr_flags(void)
{
	unsigned int bucket = rnd_modulo_u32(10);

	switch (bucket) {
	case 0: case 1: case 2:
		return OPEN_TREE_CLONE;			/* 30% */
	case 3: case 4: case 5:
		return OPEN_TREE_CLOEXEC;		/* 30% */
	case 6: case 7:
		return OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC;	/* 20% */
	case 8:
		return 0;				/* 10% attach-in-place */
	default:
		/* 10%: high-bit garbage to keep the flag validator warm. */
		return OPEN_TREE_CLONE |
			(1UL << (16 + rnd_modulo_u32(16)));
	}
}

/*
 * dfd bias.  Most pathnames trinity feeds open_tree_attr are absolute,
 * so AT_FDCWD gets the dominant share -- with a random-FD slot kept
 * for AT_EMPTY_PATH / relative-path coverage and explicit -1 / random
 * arms for the bounds-check paths.  The "real fd" slot reuses the
 * value generic_sanitise() already pulled from the ARG_FD pool.
 */
static unsigned long pick_open_tree_attr_dfd(unsigned long generic)
{
	unsigned int bucket = rnd_modulo_u32(10);

	if (bucket < 5)
		return (unsigned long) (long) AT_FDCWD;
	if (bucket < 8)
		return generic;
	if (bucket < 9)
		return (unsigned long) -1L;
	return (unsigned long) rnd_u32();
}

/*
 * Pre-ksize ABI floor for the csfu UNDERSIZE bucket.  Today
 * sizeof(struct mount_attr) == MOUNT_ATTR_SIZE_VER0, so the EXACT
 * bucket already covers VER0; the entry is kept in the pool so the
 * UNDERSIZE bucket still has a meaningful named ABI floor to draw
 * from once the kernel grows a VER1 and ksize moves past VER0.
 */
static const size_t open_tree_attr_known_sizes[] = {
	MOUNT_ATTR_SIZE_VER0,
};

static const struct csfu_desc desc_open_tree_attr = {
	.name = "mount_attr",
	.ksize = sizeof(struct mount_attr),
	.known_sizes = open_tree_attr_known_sizes,
	.n_known_sizes = ARRAY_SIZE(open_tree_attr_known_sizes),
};

static void sanitise_open_tree_attr(struct syscallrecord *rec)
{
	struct csfu_buf buf = build_csfu_struct(&desc_open_tree_attr);
	struct mount_attr *ma = buf.ptr;

	if (!ma)
		return;

	rec->a1 = pick_open_tree_attr_dfd(rec->a1);
	rec->a3 = pick_open_tree_attr_flags();

	/*
	 * Body population is gated on CSFU_BUCKET_EXACT — the kernel
	 * rejects on usize before reading any body field for the
	 * non-exact buckets, and OVERSIZE_NONZERO / TAIL_MISMATCH need
	 * their tail garbage preserved.  zmalloc_tracked() already
	 * zeroed the buffer where the kernel cares to look.
	 */
	if (buf.bucket == CSFU_BUCKET_EXACT)
		build_mount_attr(ma);

	rec->a4 = (unsigned long) ma;
	avoid_shared_buffer_inout(&rec->a4, sizeof(*ma));
	rec->a5 = buf.usize;

	/*
	 * Hand the csfu buffer to the deferred-free queue at sanitise
	 * time — open_tree_attr has no post handler, so this is the
	 * only place the zmalloc_tracked() allocation gets released.
	 */
	deferred_free_enqueue_or_leak(ma);
}

struct syscallentry syscall_open_tree_attr = {
	.name = "open_tree_attr",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [3] = ARG_STRUCT_PTR_IN, [4] = ARG_STRUCT_SIZE },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "flags", [3] = "uattr", [4] = "usize" },
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_MOUNT,
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT | KCOV_REMOTE_HEAVY,
	.sanitise = sanitise_open_tree_attr,
	.post = post_mount_fd,
};
