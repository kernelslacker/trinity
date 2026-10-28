/*
 * SYSCALL_DEFINE3(landlock_create_ruleset,
 *                const struct landlock_ruleset_attr __user *const, attr,
 *                const size_t, size, const __u32, flags)
 */
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <linux/landlock.h>
#include "csfu.h"
#include "deferred-free.h"
#include "fd.h"
#include "landlock.h"
#include "publish_resource.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

#include "kernel/landlock.h"

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
#ifndef LANDLOCK_ACCESS_FS_RESOLVE_UNIX
#define LANDLOCK_ACCESS_FS_RESOLVE_UNIX	(1ULL << 16)
#endif
#ifndef LANDLOCK_ACCESS_NET_BIND_TCP
#define LANDLOCK_ACCESS_NET_BIND_TCP	(1ULL << 0)
#endif
#ifndef LANDLOCK_ACCESS_NET_CONNECT_TCP
#define LANDLOCK_ACCESS_NET_CONNECT_TCP	(1ULL << 1)
#endif
#ifndef LANDLOCK_ACCESS_NET_BIND_UDP
#define LANDLOCK_ACCESS_NET_BIND_UDP	(1ULL << 2)
#endif
#ifndef LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP
#define LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP	(1ULL << 3)
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
	LANDLOCK_ACCESS_FS_RESOLVE_UNIX,
};

static const __u64 landlock_access_net_bits[] = {
	LANDLOCK_ACCESS_NET_BIND_TCP,
	LANDLOCK_ACCESS_NET_CONNECT_TCP,
	LANDLOCK_ACCESS_NET_BIND_UDP,
	LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP,
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
 * Published struct landlock_ruleset_attr sizes for the csfu
 * UNDERSIZE bucket:
 *   8  -- ABI v1, handled_access_fs only
 *   16 -- ABI v4, + handled_access_net
 *   24 -- ABI v6, + scoped
 *   48 -- ABI v10, + quiet_*
 * build_csfu_struct() draws uniformly from this pool for UNDERSIZE;
 * the EXACT bucket already covers the 56 bytes of ABI v12 (+
 * handled_permissions), which are ksize, so they are not repeated here.
 */
static const size_t landlock_known_sizes[] = {
	8,
	16,
	24,
	48,
};

static const struct csfu_desc desc_landlock_create_ruleset = {
	.name = "landlock_ruleset_attr",
	.ksize = sizeof(struct landlock_ruleset_attr_abi12),
	.known_sizes = landlock_known_sizes,
	.n_known_sizes = ARRAY_SIZE(landlock_known_sizes),
};

/*
 * handled_permissions: a mask of the two permissions, -EINVAL for any other
 * bit, alone or with the rest, and -ENOMSG when nothing at all is handled.
 * post_landlock_create_ruleset() arms whatever a ruleset handles, so these
 * are drawn freely: with the rest, as the only thing handled, with a bit that
 * is not defined, and with nothing handled whatever.
 */
static void draw_handled_permissions(struct landlock_ruleset_attr_abi12 *attr)
{
	switch (rnd_modulo_u32(8)) {
	case 0:
	case 1:
		attr->handled_permissions = 1 + rnd_modulo_u32(3);
		break;
	case 2:
		attr->handled_permissions = 1 + rnd_modulo_u32(3);
		attr->handled_access_fs = 0;
		attr->handled_access_net = 0;
		attr->scoped = 0;
		attr->quiet_access_fs = 0;
		attr->quiet_access_net = 0;
		attr->quiet_scoped = 0;
		break;
	case 3:
		attr->handled_permissions = rand64() |
			(LANDLOCK_PERMISSION_CAPABILITY_USE << 1);
		break;
	case 4:
		memset(attr, 0, sizeof(*attr));
		break;
	default:
		break;
	}
}

static void sanitise_landlock_create_ruleset(struct syscallrecord *rec)
{
	struct csfu_buf buf = build_csfu_struct(&desc_landlock_create_ruleset);
	struct landlock_ruleset_attr_abi12 *attr = buf.ptr;
	unsigned int flagpick;

	attr->handled_access_fs = random_mask(landlock_access_fs_bits,
					      ARRAY_SIZE(landlock_access_fs_bits));
	if (RAND_BOOL())
		attr->handled_access_net = random_mask(landlock_access_net_bits,
						       ARRAY_SIZE(landlock_access_net_bits));
	if (RAND_BOOL())
		attr->scoped = random_mask(landlock_scope_bits,
					   ARRAY_SIZE(landlock_scope_bits));

	/*
	 * The kernel EINVALs unless each quiet_* is a subset of the
	 * corresponding handled_* mask, so AND against the values just
	 * picked above.  The EXACT size is the 56 bytes of ABI 12, and a
	 * kernel that predates a field answers -E2BIG to a size that reaches
	 * past what it knows unless the extra bytes are zero, so the newer
	 * fields are a minority draw.
	 */
	if (buf.usize >= 48 && ONE_IN(4)) {
		attr->quiet_access_fs = random_mask(landlock_access_fs_bits,
						    ARRAY_SIZE(landlock_access_fs_bits))
					& attr->handled_access_fs;
		attr->quiet_access_net = random_mask(landlock_access_net_bits,
						     ARRAY_SIZE(landlock_access_net_bits))
					 & attr->handled_access_net;
		attr->quiet_scoped = random_mask(landlock_scope_bits,
						 ARRAY_SIZE(landlock_scope_bits))
				     & attr->scoped;
	}

	if (buf.usize >= 56 && ONE_IN(4))
		draw_handled_permissions(attr);

	rec->a1 = (unsigned long) attr;
	avoid_shared_buffer_inout(&rec->a1, buf.usize);
	rec->a2 = buf.usize;

	/*
	 * Flags: 80% zero (normal create path), 15%
	 * LANDLOCK_CREATE_RULESET_VERSION (ABI-version oracle), 5%
	 * random bits (most reserved -- exercises the EINVAL gate).
	 */
	flagpick = rnd_modulo_u32(20);
	if (flagpick < 16)
		rec->a3 = 0;
	else if (flagpick < 19) {
		rec->a3 = LANDLOCK_CREATE_RULESET_VERSION;
		rec->a1 = 0;
		rec->a2 = 0;
	}
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
	cleanup_release_post_state(rec);
}

/*
 * What sys_landlock_create_ruleset() took as handled_permissions.  The kernel
 * copies min(56, size) bytes of the attr and zero-fills the rest, so a size
 * inside the field exposes only its low bytes, and a compat call hands it the
 * low 32 bits of the pointer and the size.  Copying the same bytes into a
 * zeroed struct reads the field as the kernel did, whatever the byte order.
 * The shadows hold what __do_syscall() passed the kernel.  False when the attr
 * cannot be read back.
 */
static bool kernel_handled_permissions(struct syscallrecord *rec, __u64 *handled)
{
	struct landlock_ruleset_attr_abi12 seen = { 0 };
	unsigned long attr = get_arg_snapshot(rec, 1);
	unsigned long size = get_arg_snapshot(rec, 2);

	if (rec->do32bit) {
		attr = (uint32_t) attr;
		size = (uint32_t) size;
	}
	if (!post_snapshot_or_skip(&seen, (const void *) attr,
				   min(size, sizeof(seen))))
		return false;

	*handled = seen.handled_permissions;
	return true;
}

static void post_landlock_create_ruleset(struct syscallrecord *rec)
{
	__u64 handled;
	int fd = rec->retval;

	if ((long)rec->retval < 0)
		return;

	/*
	 * The kernel takes flags as a __u32, and with any it returns the ABI
	 * version or the errata: a number, not a ruleset, so there is nothing to
	 * arm, pool or close.  The number may still be one of the child's fds,
	 * so the retval goes to -1UL, or register_returned_fd() would pool it
	 * and account_fd_and_group() retire and reuse it as one.
	 */
	if ((uint32_t) get_arg_snapshot(rec, 3) != 0) {
		rec->retval = -1UL;
		return;
	}

	/*
	 * landlock_allow_permissions() says why a ruleset is armed before it is
	 * published.  One that cannot be armed is closed: left open and out of
	 * the pool, a guessed number could still restrict the child with it.
	 * So is one whose attr cannot be read back to say what it handles, and
	 * one the pool turns away, so whatever stays open is armed.  A stdio or
	 * protected number is never closed here: it is the child's own plumbing
	 * unless the child closed it, and a stomped retval must not close it.
	 */
	if (kernel_handled_permissions(rec, &handled) &&
	    landlock_allow_permissions(fd, handled) &&
	    publish_resource(OBJ_FD_LANDLOCK, fd, NULL) != NULL)
		return;

	if (fd > 2 && !fd_is_protected(fd))
		close(fd);
	rec->retval = -1UL;
}

struct syscallentry syscall_landlock_create_ruleset = {
	.name = "landlock_create_ruleset",
	.num_args = 3,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_LEN, [2] = ARG_LIST },
	.argname = { [0] = "attr", [1] = "size", [2] = "flags" },
	.arg_params[2].list = ARGLIST(landlock_create_ruleset_flags),
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_LANDLOCK,
	.sanitise = sanitise_landlock_create_ruleset,
	.post = post_landlock_create_ruleset,
	.cleanup = cleanup_landlock_create_ruleset,
	.group = GROUP_PROCESS,
	.flags = REEXEC_SANITISE_OK,
	/* What the post handler arms the ruleset from: the flags say whether
	 * the return is a ruleset fd or a number, and the attr and its size say
	 * which permissions the ruleset handles.  Shadowed so a sibling stomp
	 * cannot turn a version query into a ruleset, or one that handles a
	 * permission into one that handles none. */
	.arg_snapshot_mask = (1u << 0) | (1u << 1) | (1u << 2),
};
