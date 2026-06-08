/*
 * SYSCALL_DEFINE6(setxattrat, int, dfd, const char __user *, pathname,
 *		unsigned int, at_flags, const char __user *, name,
 *		const struct xattr_args __user *, uargs, size_t, usize)
 */
#include <fcntl.h>
#include "arch.h"
#include "csfu.h"
#include "deferred-free.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"
#include "xattr.h"
#include "compat.h"
#ifdef USE_XATTR_ARGS
#include <linux/xattr.h>
#endif

static unsigned long setxattrat_at_flags[] = {
	AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH,
};

#ifdef USE_XATTR_ARGS
/*
 * Single-version ABI today: struct xattr_args has only one published
 * layout, so there is no pre-ksize ABI floor to seed the UNDERSIZE
 * bucket from.  The current ksize is kept in known_sizes[] so the
 * table stays self-documenting and remains correct if the kernel
 * ever grows a VER1.
 */
static const size_t setxattrat_known_sizes[] = {
	sizeof(struct xattr_args),
};

static const struct csfu_desc desc_setxattrat = {
	.name = "xattr_args",
	.ksize = sizeof(struct xattr_args),
	.known_sizes = setxattrat_known_sizes,
	.n_known_sizes = ARRAY_SIZE(setxattrat_known_sizes),
};
#endif

static void sanitise_setxattrat(struct syscallrecord *rec)
{
	char *name = (char *) get_writable_struct(256);

	if (!name)
		return;
	gen_xattr_name(name, 256);
	rec->a4 = (unsigned long) name;

#ifdef USE_XATTR_ARGS
	{
		static const unsigned int flag_choices[] = { 0, XATTR_CREATE, XATTR_REPLACE };
		struct csfu_buf buf = build_csfu_struct(&desc_setxattrat);
		struct xattr_args *args = buf.ptr;

		if (!args)
			return;

		/*
		 * Stash the csfu buffer in rec->post_state up front so the
		 * unconditional .cleanup hook frees it even on the value-buffer
		 * allocation-failure return below.  setxattrat has no .post handler,
		 * so this was the only release point; post_state is private to the
		 * cleanup path and less stomp-prone than rec->a5.
		 */
		rec->post_state = (unsigned long) args;

		/*
		 * Non-EXACT buckets get rejected on size by the validator
		 * before the kernel reads any body field, so populating
		 * args->value / size / flags (and allocating the value
		 * sub-buffer they reference) is wasted work.  The
		 * zmalloc_tracked() buffer is already zeroed where the
		 * kernel cares to look.
		 */
		if (buf.bucket == CSFU_BUCKET_EXACT) {
			__u32 chosen;

			switch (rnd_modulo_u32(9)) {
			case 0:  chosen = 0;                  break;
			case 1:  chosen = 1;                  break;
			case 2:  chosen = 32;                 break;
			case 3:  chosen = 256;                break;
			case 4:  chosen = page_size;          break;
			case 5:  chosen = page_size + 1;      break;
			case 6:  chosen = 65536;              break;
			case 7:  chosen = 65537;              break;
			default: chosen = rnd_modulo_u32(1u << 20); break;
			}

			if (chosen == 0) {
				args->value = 0;
			} else {
				void *value = get_writable_struct(chosen);
				if (!value) {
					/*
					 * Publish safe defaults so the syscall
					 * doesn't run with stale rec->a5/rec->a6
					 * from a prior iteration.  args/buf both
					 * stack-resident — zeroing the published
					 * slots is enough; the kernel will see
					 * NULL uargs and reject cleanly.
					 */
					rec->a5 = 0;
					rec->a6 = 0;
					return;
				}
				args->value = (unsigned long) value;
			}
			args->size = chosen;
			args->flags = flag_choices[rnd_modulo_u32(3)];
		}

		rec->a5 = (unsigned long) args;
		avoid_shared_buffer_inout(&rec->a5, sizeof(struct xattr_args));
		rec->a6 = buf.usize;
	}
#endif
}

#ifdef USE_XATTR_ARGS
static void cleanup_setxattrat(struct syscallrecord *rec)
{
	cleanup_release_post_state(rec);
}
#endif

struct syscallentry syscall_setxattrat = {
	.name = "setxattrat",
	.num_args = 6,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_LIST, [4] = ARG_ADDRESS, [5] = ARG_LEN },
	.argname = { [0] = "dfd", [1] = "pathname", [2] = "at_flags", [3] = "name", [4] = "uargs", [5] = "usize" },
	.arg_params[2].list = ARGLIST(setxattrat_at_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_setxattrat,
#ifdef USE_XATTR_ARGS
	.cleanup = cleanup_setxattrat,
#endif
};
