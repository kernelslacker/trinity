#ifndef _CHILDOPS_IOURING_RECIPES_INTERNAL_H
#define _CHILDOPS_IOURING_RECIPES_INTERNAL_H

/*
 * Shared declarations for the iouring-recipes translation units.
 *
 * The recipe catalogue was a single ~2900-line .c file; building it
 * serialised the parallel make at one slow compile.  The recipes are
 * now grouped into per-family modules (fs, net, poll-timeout,
 * register-fixedfile) that compile concurrently; iouring-recipes.c
 * keeps the dispatcher table, the per-iteration state struct, the
 * shared submission helpers, the pool-race fault handler, and the two
 * NOP/chain smoke recipes.
 *
 * Each recipe_<name>() function used to be file-local static; it is
 * declared here because the catalog[] table in iouring-recipes.c now
 * lives in a different translation unit from the implementations.
 * The submission helpers (iour_submit_sqes / iour_enter /
 * iour_drain_cqes / sqe_clear) and the pool-race address-range statics
 * are likewise widened from static to external so the per-family TUs
 * can reach them.  No other caller exists -- treat these prototypes
 * as the catalogue's cross-unit boundary, not as a general public API.
 */

#include <linux/types.h>
#include <stdbool.h>
#include <stdint.h>

#include "childops/io_uring/ring.h"

struct io_uring_sqe;

/* Local mirror of struct open_how — avoid a build-time dependency on
 * a kernel header that older distributions ship without. */
struct iour_open_how {
	__u64	flags;
	__u64	mode;
	__u64	resolve;
};

/*
 * Per-iteration recipe resources.  Recipes may allocate fds, pipes,
 * sockets, malloc'd buffers, an inner io_uring ring, or io_uring-side
 * registrations (registered buffers / files / provided buffers).  The
 * pool-race siglongjmp in iouring_recipes() unwinds straight to the
 * wrap's setjmp landing pad, skipping the recipe's own cleanup; this
 * struct lives in the wrap's stack frame so it survives the longjmp,
 * and iour_recipe_state_cleanup() releases every populated field.
 *
 * Sentinels: -1 for fds, NULL for pointers, false for bools.  The
 * cleanup is idempotent — recipes may clear fields after a deliberate
 * teardown mid-execution (e.g. recipe_provide_buffers' REMOVE_BUFFERS),
 * and the wrap calls cleanup unconditionally on both the success and
 * abort paths.
 */
struct iour_recipe_state {
	struct iour_ring *ctx;		/* outer ring; convenience handle */

	int		evfd;
	int		sock[2];
	int		pipefd[2];
	int		pipefd2[2];	/* second pipe pair (SPLICE/TEE) */
	int		open_fd;	/* /dev/null, /dev/zero, etc. */
	int		memfd;		/* memfd_create-backed regular file */
	int		epoll_fd;
	void		*malloc_buf;

	struct iour_ring inner;		/* recipe_msg_ring destination */
	bool		inner_active;

	bool		registered_buf;	  /* IORING_REGISTER_BUFFERS active */
	bool		registered_files; /* IORING_REGISTER_FILES active */

	bool		provided_buf_active;
	unsigned int	provided_buf_group_id;
	unsigned int	provided_buf_count;
};

/*
 * Submission helpers shared between the dispatcher and every per-family
 * recipe TU.  Defined in iouring-recipes.c; widened from file-local
 * static so the split sibling TUs can reach them.
 */
bool iour_submit_sqes(struct iour_ring *ctx, struct io_uring_sqe *sqe,
		      unsigned int n);
int iour_enter(struct iour_ring *ctx, unsigned int n,
	       unsigned int min_complete);
void iour_drain_cqes(struct iour_ring *ctx);
void sqe_clear(struct io_uring_sqe *s);

/*
 * Pool-race published address range.  The 3 pool-drawing recipes
 * (recipe_fixed_buffer_read, recipe_write_read_fixed,
 * recipe_futex_wait_wake) publish the drawn map's range into these
 * volatiles right after get_map_with_prot() returns so the
 * iouring_recipes_pool_race_handler can route in-range faults to the
 * sigsetjmp landing pad in iouring_recipes().  Non-pool-drawing
 * recipes leave them at 0..0 so every si_addr falls outside.
 *
 * Defined in iouring-recipes.c; widened from file-local static so the
 * fs and poll-timeout TUs that house the pool-drawing recipes can
 * publish into the range.
 */
extern volatile uintptr_t iouring_recipes_pool_race_addr_low;
extern volatile uintptr_t iouring_recipes_pool_race_addr_high;

/* fs family -- childops/iouring-recipes-fs.c */
bool recipe_openat_close_linked(struct iour_recipe_state *s, bool *unsupported);
bool recipe_fsync(struct iour_recipe_state *s, bool *unsupported);
bool recipe_sync_file_range(struct iour_recipe_state *s, bool *unsupported);
bool recipe_readv(struct iour_recipe_state *s, bool *unsupported);
bool recipe_writev(struct iour_recipe_state *s, bool *unsupported);
bool recipe_fallocate(struct iour_recipe_state *s, bool *unsupported);
bool recipe_ftruncate(struct iour_recipe_state *s, bool *unsupported);
bool recipe_fadvise(struct iour_recipe_state *s, bool *unsupported);
bool recipe_read_multishot(struct iour_recipe_state *s, bool *unsupported);
bool recipe_openat2(struct iour_recipe_state *s, bool *unsupported);
bool recipe_openat2_leak_combos(struct iour_recipe_state *s, bool *unsupported);
bool recipe_splice(struct iour_recipe_state *s, bool *unsupported);
bool recipe_tee(struct iour_recipe_state *s, bool *unsupported);
bool recipe_renameat(struct iour_recipe_state *s, bool *unsupported);
bool recipe_unlinkat(struct iour_recipe_state *s, bool *unsupported);
bool recipe_mkdirat(struct iour_recipe_state *s, bool *unsupported);
bool recipe_symlinkat(struct iour_recipe_state *s, bool *unsupported);
bool recipe_linkat(struct iour_recipe_state *s, bool *unsupported);
bool recipe_setxattr(struct iour_recipe_state *s, bool *unsupported);
bool recipe_fsetxattr(struct iour_recipe_state *s, bool *unsupported);
bool recipe_getxattr(struct iour_recipe_state *s, bool *unsupported);
bool recipe_fgetxattr(struct iour_recipe_state *s, bool *unsupported);

/* net family -- childops/iouring-recipes-net.c */
bool recipe_send_recv_linked(struct iour_recipe_state *s, bool *unsupported);
bool recipe_socket_shutdown_linked(struct iour_recipe_state *s, bool *unsupported);
bool recipe_sendmsg(struct iour_recipe_state *s, bool *unsupported);
bool recipe_recvmsg(struct iour_recipe_state *s, bool *unsupported);
bool recipe_accept(struct iour_recipe_state *s, bool *unsupported);
bool recipe_connect(struct iour_recipe_state *s, bool *unsupported);
#ifndef TRINITY_COMPAT_BACKFILLED_BIND
bool recipe_bind(struct iour_recipe_state *s, bool *unsupported);
#endif
bool recipe_listen(struct iour_recipe_state *s, bool *unsupported);

/* poll-timeout family -- childops/iouring-recipes-poll-timeout.c */
bool recipe_timeout_drain(struct iour_recipe_state *s, bool *unsupported);
bool recipe_poll_multishot(struct iour_recipe_state *s, bool *unsupported);
bool recipe_async_cancel(struct iour_recipe_state *s, bool *unsupported);
bool recipe_epoll_wait(struct iour_recipe_state *s, bool *unsupported);
bool recipe_epoll_ctl(struct iour_recipe_state *s, bool *unsupported);
bool recipe_link_timeout(struct iour_recipe_state *s, bool *unsupported);
bool recipe_timeout_remove(struct iour_recipe_state *s, bool *unsupported);
#ifndef TRINITY_COMPAT_BACKFILLED_FUTEX_WAIT_WAKE
bool recipe_futex_wait_wake(struct iour_recipe_state *s, bool *unsupported);
#endif
bool recipe_waitid(struct iour_recipe_state *s, bool *unsupported);

/* register-fixedfile family -- childops/iouring-recipes-register.c */
bool recipe_fixed_buffer_read(struct iour_recipe_state *s, bool *unsupported);
bool recipe_write_read_fixed(struct iour_recipe_state *s, bool *unsupported);
bool recipe_provide_buffers(struct iour_recipe_state *s, bool *unsupported);
bool recipe_msg_ring(struct iour_recipe_state *s, bool *unsupported);
bool recipe_statx_fixed_file(struct iour_recipe_state *s, bool *unsupported);
bool recipe_files_update(struct iour_recipe_state *s, bool *unsupported);
bool recipe_eventfd_recursive(struct iour_recipe_state *s, bool *unsupported);

#endif /* _CHILDOPS_IOURING_RECIPES_INTERNAL_H */
