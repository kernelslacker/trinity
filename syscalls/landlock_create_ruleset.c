/*
 * SYSCALL_DEFINE3(landlock_create_ruleset,
 *                const struct landlock_ruleset_attr __user *const, attr,
 *                const size_t, size, const __u32, flags)
 */
#include <linux/landlock.h>
#include <string.h>
#include "publish_resource.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

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
 * Sized large enough to comfortably hold any plausible future
 * ABI-version growth of struct landlock_ruleset_attr (currently 24
 * bytes at ABI v6).  Anything past the kernel-known prefix must be
 * zero or the kernel returns -E2BIG.
 */
#define LANDLOCK_ATTR_BUF_SIZE 64

/* Recognised attr sizes across published Landlock ABI versions. */
static const size_t landlock_known_sizes[] = {
	8,	/* ABI v1: handled_access_fs only */
	16,	/* ABI v4: + handled_access_net */
	24,	/* ABI v6: + scoped */
};

static void sanitise_landlock_create_ruleset(struct syscallrecord *rec)
{
	struct landlock_ruleset_attr *attr;
	unsigned int sizepick, flagpick;

	attr = (struct landlock_ruleset_attr *) get_writable_address(LANDLOCK_ATTR_BUF_SIZE);
	if (attr == NULL)
		return;
	memset(attr, 0, LANDLOCK_ATTR_BUF_SIZE);

	attr->handled_access_fs = random_mask(landlock_access_fs_bits,
					      ARRAY_SIZE(landlock_access_fs_bits));
	if (RAND_BOOL())
		attr->handled_access_net = random_mask(landlock_access_net_bits,
						       ARRAY_SIZE(landlock_access_net_bits));
	if (RAND_BOOL())
		attr->scoped = random_mask(landlock_scope_bits,
					   ARRAY_SIZE(landlock_scope_bits));

	rec->a1 = (unsigned long) attr;

	/*
	 * Size distribution:
	 *   70% exact sizeof(*attr) -- the current ABI version
	 *   20% a smaller known ABI-version size (8 or 16 -- the trailing
	 *       fields are ignored on those kernels)
	 *    5% oversized (kernel checks trailing bytes are zero;
	 *       memset above guarantees they are, so this exercises the
	 *       size walk past sizeof(*attr) up to E2BIG)
	 *    5% zero (immediate EINVAL gate)
	 */
	sizepick = rnd_modulo_u32(20);
	if (sizepick < 14) {
		rec->a2 = sizeof(*attr);
	} else if (sizepick < 18) {
		rec->a2 = landlock_known_sizes[rnd_modulo_u32(ARRAY_SIZE(landlock_known_sizes))];
	} else if (sizepick < 19) {
		rec->a2 = sizeof(*attr) + 8 * (1 + rnd_modulo_u32(4));
		if (rec->a2 > LANDLOCK_ATTR_BUF_SIZE)
			rec->a2 = LANDLOCK_ATTR_BUF_SIZE;
	} else {
		rec->a2 = RAND_BOOL() ? 0 : (rnd_u32() % LANDLOCK_ATTR_BUF_SIZE);
	}

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
	.group = GROUP_PROCESS,
};
