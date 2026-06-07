/*
 * SYSCALL_DEFINE3(landlock_create_ruleset,
 *                const struct landlock_ruleset_attr __user *const, attr,
 *                const size_t, size, const __u32, flags)
 */
#include <linux/landlock.h>
#include "csfu.h"
#include "deferred-free.h"
#include "publish_resource.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION			(1U << 0)
#endif
#ifndef LANDLOCK_CREATE_RULESET_ERRATA
#define LANDLOCK_CREATE_RULESET_ERRATA			(1U << 1)
#endif

static unsigned long landlock_create_ruleset_flags[] = {
	LANDLOCK_CREATE_RULESET_VERSION,
	LANDLOCK_CREATE_RULESET_ERRATA,
};

/*
 * Compatibility shims so older uapi headers (pre-v6) still compile.
 * The kernel either accepts the bit (loaded LSM supports it) or
 * EINVALs at the gate -- harmless either way.
 */
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER	(1ULL << 13)
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE	(1ULL << 14)
#endif
#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV	(1ULL << 15)
#endif
#ifndef LANDLOCK_ACCESS_NET_BIND_TCP
#define LANDLOCK_ACCESS_NET_BIND_TCP	(1ULL << 0)
#endif
#ifndef LANDLOCK_ACCESS_NET_CONNECT_TCP
#define LANDLOCK_ACCESS_NET_CONNECT_TCP	(1ULL << 1)
#endif
#ifndef LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
#define LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET	(1ULL << 0)
#endif
#ifndef LANDLOCK_SCOPE_SIGNAL
#define LANDLOCK_SCOPE_SIGNAL		(1ULL << 1)
#endif

/*
 * All currently-defined LANDLOCK_ACCESS_FS_* bits (ABI v1 -> v6).
 * Drawn from a curated set rather than rand32() & MASK so an OR of
 * two or three picks is much more likely to land on a real
 * fs_parser-recognised combination than a random byte.
 */
static const __u64 landlock_access_fs_bits[] = {
	LANDLOCK_ACCESS_FS_EXECUTE,
	LANDLOCK_ACCESS_FS_WRITE_FILE,
	LANDLOCK_ACCESS_FS_READ_FILE,
	LANDLOCK_ACCESS_FS_READ_DIR,
	LANDLOCK_ACCESS_FS_REMOVE_DIR,
	LANDLOCK_ACCESS_FS_REMOVE_FILE,
	LANDLOCK_ACCESS_FS_MAKE_CHAR,
	LANDLOCK_ACCESS_FS_MAKE_DIR,
	LANDLOCK_ACCESS_FS_MAKE_REG,
	LANDLOCK_ACCESS_FS_MAKE_SOCK,
	LANDLOCK_ACCESS_FS_MAKE_FIFO,
	LANDLOCK_ACCESS_FS_MAKE_BLOCK,
	LANDLOCK_ACCESS_FS_MAKE_SYM,
	LANDLOCK_ACCESS_FS_REFER,
	LANDLOCK_ACCESS_FS_TRUNCATE,
	LANDLOCK_ACCESS_FS_IOCTL_DEV,
};

static const __u64 landlock_access_net_bits[] = {
	LANDLOCK_ACCESS_NET_BIND_TCP,
	LANDLOCK_ACCESS_NET_CONNECT_TCP,
};

static const __u64 landlock_scope_bits[] = {
	LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET,
	LANDLOCK_SCOPE_SIGNAL,
};

static __u64 random_mask(const __u64 *bits, unsigned int n)
{
	unsigned int i, picks;
	__u64 mask = 0;

	picks = 1 + rnd_modulo_u32(n);
	for (i = 0; i < picks; i++)
		mask |= bits[rnd_modulo_u32(n)];
	return mask;
}

/*
 * Pre-ksize ABI floors for the csfu UNDERSIZE bucket.  Each value is
 * the size of a published struct landlock_ruleset_attr layout:
 *   8  -- ABI v1, handled_access_fs only
 *   16 -- ABI v4, + handled_access_net
 *   24 -- ABI v6, + scoped
 * build_csfu_struct() draws uniformly from this pool for UNDERSIZE;
 * the EXACT bucket already covers sizeof(struct landlock_ruleset_attr),
 * so the current ksize is not repeated here.
 */
static const size_t landlock_known_sizes[] = {
	8,
	16,
	24,
};

static const struct csfu_desc desc_landlock_create_ruleset = {
	.name = "landlock_ruleset_attr",
	.ksize = sizeof(struct landlock_ruleset_attr),
	.known_sizes = landlock_known_sizes,
	.n_known_sizes = ARRAY_SIZE(landlock_known_sizes),
};

static void sanitise_landlock_create_ruleset(struct syscallrecord *rec)
{
	struct csfu_buf buf = build_csfu_struct(&desc_landlock_create_ruleset);
	struct landlock_ruleset_attr *attr = buf.ptr;
	unsigned int flagpick;

	attr->handled_access_fs = random_mask(landlock_access_fs_bits,
					      ARRAY_SIZE(landlock_access_fs_bits));
	if (RAND_BOOL())
		attr->handled_access_net = random_mask(landlock_access_net_bits,
						       ARRAY_SIZE(landlock_access_net_bits));
	if (RAND_BOOL())
		attr->scoped = random_mask(landlock_scope_bits,
					   ARRAY_SIZE(landlock_scope_bits));

	rec->a1 = (unsigned long) attr;
	rec->a2 = buf.usize;

	/*
	 * Flags: 80% zero (normal create path), 15%
	 * LANDLOCK_CREATE_RULESET_VERSION (ABI-version oracle), 5%
	 * random bits (most reserved -- exercises the EINVAL gate).
	 */
	flagpick = rnd_modulo_u32(20);
	if (flagpick < 16)
		rec->a3 = 0;
	else if (flagpick < 19)
		rec->a3 = LANDLOCK_CREATE_RULESET_VERSION;
	else
		rec->a3 = rnd_u32();

	/*
	 * Stash the csfu buffer in rec->post_state so the unconditional
	 * .cleanup hook frees it whether or not .post runs (.post is
	 * skipped on the retfd reject path).  post_state is private to the
	 * post/cleanup pair and less stomp-prone than rec->a1.
	 */
	rec->post_state = (unsigned long) attr;
}

static void cleanup_landlock_create_ruleset(struct syscallrecord *rec)
{
	struct landlock_ruleset_attr *attr =
		(struct landlock_ruleset_attr *) rec->post_state;

	rec->post_state = 0;

	if (attr == NULL)
		return;

	/*
	 * post_state is not exposed as a syscall arg, but the whole
	 * record can be stomped by a sibling; guard the deref.  This
	 * replaces the old deferred_free_enqueue_or_leak() pressure path.
	 */
	if (looks_like_corrupted_ptr(rec, attr))
		return;

	/*
	 * attr came from build_csfu_struct() -> zmalloc_tracked(), which
	 * registered the pointer in the alloc-track LRU.  tracked_free_now()
	 * removes it from the LRU and frees it.
	 */
	tracked_free_now(attr);
}

static void post_landlock_create_ruleset(struct syscallrecord *rec)
{
	int fd = rec->retval;

	if ((long)rec->retval < 0)
		return;

	publish_resource(OBJ_FD_LANDLOCK, fd, NULL);
}

struct syscallentry syscall_landlock_create_ruleset = {
	.name = "landlock_create_ruleset",
	.num_args = 3,
	.argtype = { [2] = ARG_LIST },
	.argname = { [0] = "attr", [1] = "size", [2] = "flags" },
	.arg_params[2].list = ARGLIST(landlock_create_ruleset_flags),
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_LANDLOCK,
	.sanitise = sanitise_landlock_create_ruleset,
	.post = post_landlock_create_ruleset,
	.cleanup = cleanup_landlock_create_ruleset,
	.group = GROUP_PROCESS,
};
