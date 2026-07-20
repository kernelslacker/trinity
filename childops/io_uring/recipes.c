/*
 * iouring_recipes - structured io_uring submission sequences.
 *
 * The default io_uring_enter path fills SQEs with random values, which
 * rarely produces structurally valid submissions.  Deep io_uring code
 * paths — linked-SQE chains, drain ordering, registered-buffer ops,
 * async cancellation interactions — stay cold unless the kernel sees
 * semantically coherent request sequences.
 *
 * Each recipe here is a self-contained sequence: set up a ring, submit
 * a purposefully constructed batch of SQEs, reap the CQEs, and tear the
 * ring down.  The interesting surface is the sequence of state transitions
 * the kernel traverses, not the argument values themselves — so args are
 * kept intentionally simple (zero offsets, page-size buffers, loopback
 * addresses) to avoid false negatives from EFAULT or EINVAL before the
 * kernel reaches the code path we care about.
 *
 * Where a recipe exercises a kernel feature that may be absent (ENOSYS,
 * missing config), it latches a per-recipe disabled flag in shm so
 * siblings skip the probe on subsequent iterations.
 *
 * The recipe bodies live in per-family sibling translation units
 * (iouring-recipes-{fs,net,poll-timeout,register}.c) so they compile
 * in parallel; this file keeps the per-iteration state struct, the
 * shared submission helpers, the pool-race fault handler, the two
 * NOP/chain smoke recipes, and the dispatcher catalog.  See
 * iouring-recipes-internal.h for the cross-TU symbol boundary.
 */

#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>
#include <linux/io_uring.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "syscall-gate.h"
#include "pids.h"


#include "arch.h"
#include "child.h"
#include "childops-iouring.h"
#include "childops/io_uring/recipes.h"
#include "childops/io_uring/recipes-internal.h"
#include "errno-classify.h"
#include "maps.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "stats.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/io_uring.h"
#include "kernel/unistd.h"
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup	425
#define __NR_io_uring_enter	426
#define __NR_io_uring_register	427
#endif

#ifndef IORING_OFF_CQ_RING
#define IORING_OFF_CQ_RING	0x8000000ULL
#endif

/*
 * Ring lifecycle moved to childops/iouring-ring.{c,h}.  Callers in
 * this file invoke iour_ring_setup / iour_ring_teardown directly --
 * see iouring_recipes() for the outer-ring setup and recipe_msg_ring
 * for the inner-ring setup.
 */

/*
 * Place n SQEs starting at sqe[] into the submission ring and update the
 * published tail.  Returns false if n exceeds the available ring space.
 */
bool iour_submit_sqes(struct iour_ring *ctx,
			      struct io_uring_sqe *sqe, unsigned int n)
{
	unsigned int mask  = ring_u32(ctx->sq_ring, ctx->sq_off_mask);
	unsigned int head  = ring_u32(ctx->sq_ring, ctx->sq_off_head);
	unsigned int tail  = ring_u32(ctx->sq_ring, ctx->sq_off_tail);
	unsigned int avail = ctx->sq_entries - (tail - head);
	unsigned int *sq_array;
	struct io_uring_sqe *sqes = ctx->sqes;
	unsigned int i;

	if (n > avail)
		return false;

	sq_array = (unsigned int *)((char *)ctx->sq_ring + ctx->sq_off_array);

	for (i = 0; i < n; i++) {
		unsigned int slot = (tail + i) & mask;

		sqes[slot] = sqe[i];
		sq_array[slot] = slot;
	}

	__sync_synchronize();
	ring_store_u32(ctx->sq_ring, ctx->sq_off_tail, tail + n);
	return true;
}

/*
 * Submit n SQEs and optionally wait for min_complete CQEs.
 */
int iour_enter(struct iour_ring *ctx, unsigned int n,
		      unsigned int min_complete)
{
	return (int)trinity_raw_syscall(__NR_io_uring_enter, ctx->fd, n, min_complete,
			    IORING_ENTER_GETEVENTS, NULL, 0);
}

/*
 * Drain all available CQEs from the completion ring, advancing the head.
 */
void iour_drain_cqes(struct iour_ring *ctx)
{
	unsigned int head = ring_u32(ctx->cq_ring, ctx->cq_off_head);
	unsigned int tail;

	tail = ring_u32(ctx->cq_ring, ctx->cq_off_tail);

	while (head != tail) {
		head++;
		tail = ring_u32(ctx->cq_ring, ctx->cq_off_tail);
	}

	__sync_synchronize();
	ring_store_u32(ctx->cq_ring, ctx->cq_off_head, head);
}

/*
 * Drain variant that closes the fd carried in a matching CQE's res.
 * See the header comment for the why.  We skip res 0/1/2 defensively --
 * a recipe that just clobbers stdin/stdout/stderr breaks the child's
 * ability to report subsequent failures; the fuzz value of closing them
 * is nil.
 */
void iour_drain_cqes_close_fd(struct iour_ring *ctx, __u64 want_ud)
{
	unsigned int head = ring_u32(ctx->cq_ring, ctx->cq_off_head);
	unsigned int mask = ring_u32(ctx->cq_ring, ctx->cq_off_mask);
	struct io_uring_cqe *cqes = (struct io_uring_cqe *)
		((char *)ctx->cq_ring + ctx->cq_off_cqes);
	unsigned int tail;

	tail = ring_u32(ctx->cq_ring, ctx->cq_off_tail);

	while (head != tail) {
		struct io_uring_cqe *cqe = &cqes[head & mask];

		if (cqe->user_data == want_ud && cqe->res > 2)
			close(cqe->res);
		head++;
		tail = ring_u32(ctx->cq_ring, ctx->cq_off_tail);
	}

	__sync_synchronize();
	ring_store_u32(ctx->cq_ring, ctx->cq_off_head, head);
}

void sqe_clear(struct io_uring_sqe *s)
{
	memset(s, 0, sizeof(*s));
}

static void iour_recipe_state_init(struct iour_recipe_state *s,
				   struct iour_ring *ctx)
{
	memset(s, 0, sizeof(*s));
	s->ctx        = ctx;
	s->evfd       = -1;
	s->sock[0]    = -1;
	s->sock[1]    = -1;
	s->pipefd[0]  = -1;
	s->pipefd[1]  = -1;
	s->pipefd2[0] = -1;
	s->pipefd2[1] = -1;
	s->open_fd    = -1;
	s->memfd      = -1;
	s->epoll_fd   = -1;
}

/*
 * Tear down every populated recipe resource.  Idempotent: each branch
 * checks the field's sentinel and clears it after release, so the caller
 * may invoke this on both the success path (after the recipe has cleared
 * the fields it deliberately tore down) and the siglongjmp landing path
 * (where fields hold whatever the aborted recipe had set).
 *
 * Order matters: io_uring registrations and the inner ring must be torn
 * down before the outer ring (which the wrap closes after this returns),
 * and provided-buffer REMOVE_BUFFERS must run before UNREGISTER because
 * it submits an SQE on the outer ring.
 */
static void iour_recipe_state_cleanup(struct iour_recipe_state *s)
{
	if (s->provided_buf_active) {
		struct io_uring_sqe sqe;
		unsigned int sq_head = ring_u32(s->ctx->sq_ring,
						s->ctx->sq_off_head);
		unsigned int sq_tail = ring_u32(s->ctx->sq_ring,
						s->ctx->sq_off_tail);
		unsigned int sq_avail = s->ctx->sq_entries -
					(sq_tail - sq_head);

		/* SQ-full at teardown time is expected when a recipe
		 * has already crammed the ring on its way to the
		 * landing path.  Skip the REMOVE_BUFFERS submission
		 * rather than spinning on a retry loop -- the kernel
		 * reclaims the provided-buffer pool when the ring
		 * itself is closed in iour_ring_teardown(), so the only
		 * thing we lose by skipping is the ability to reuse
		 * the group id within this same ring before the close,
		 * which no recipe path does. */
		if (sq_avail > 0) {
			sqe_clear(&sqe);
			sqe.opcode    = IORING_OP_REMOVE_BUFFERS;
			sqe.fd        = s->provided_buf_count;
			sqe.buf_group = s->provided_buf_group_id;
			sqe.user_data = 999;
			if (iour_submit_sqes(s->ctx, &sqe, 1))
				(void)iour_enter(s->ctx, 1, 0);
			iour_drain_cqes(s->ctx);
		}
		s->provided_buf_active = false;
	}
	if (s->registered_buf) {
		(void)trinity_raw_syscall(__NR_io_uring_register, s->ctx->fd,
			      IORING_UNREGISTER_BUFFERS, NULL, 0);
		s->registered_buf = false;
	}
	if (s->registered_files) {
		(void)trinity_raw_syscall(__NR_io_uring_register, s->ctx->fd,
			      IORING_UNREGISTER_FILES, NULL, 0);
		s->registered_files = false;
	}
	if (s->inner_active) {
		iour_ring_teardown(&s->inner);
		s->inner_active = false;
	}
	if (s->evfd >= 0) {
		close(s->evfd);
		s->evfd = -1;
	}
	if (s->sock[0] >= 0) {
		close(s->sock[0]);
		s->sock[0] = -1;
	}
	if (s->sock[1] >= 0) {
		close(s->sock[1]);
		s->sock[1] = -1;
	}
	if (s->pipefd[0] >= 0) {
		close(s->pipefd[0]);
		s->pipefd[0] = -1;
	}
	if (s->pipefd[1] >= 0) {
		close(s->pipefd[1]);
		s->pipefd[1] = -1;
	}
	if (s->pipefd2[0] >= 0) {
		close(s->pipefd2[0]);
		s->pipefd2[0] = -1;
	}
	if (s->pipefd2[1] >= 0) {
		close(s->pipefd2[1]);
		s->pipefd2[1] = -1;
	}
	if (s->open_fd >= 0) {
		close(s->open_fd);
		s->open_fd = -1;
	}
	if (s->memfd >= 0) {
		close(s->memfd);
		s->memfd = -1;
	}
	if (s->epoll_fd >= 0) {
		close(s->epoll_fd);
		s->epoll_fd = -1;
	}
	if (s->malloc_buf) {
		free(s->malloc_buf);
		s->malloc_buf = NULL;
	}
}

/*
 * A discoverable recipe sets *unsupported = true when it first encounters
 * ENOSYS or a missing kernel feature.  The dispatcher latches the recipe off
 * in shm so siblings stop probing.
 */
struct iour_recipe {
	const char *name;
	bool (*run)(struct iour_recipe_state *s, bool *unsupported);
};

/* Pool-race fault guard.  See childops/mm/memory-pressure.c for the full
 * rationale.  The wrap below catches a sibling-driven UAF on a pool-
 * drawn buffer used inside r->run().  Only 3 of the 15 catalog recipes
 * draw from the parent's mapping pool (recipe_fixed_buffer_read,
 * recipe_write_read_fixed, recipe_futex_wait_wake); the other 12 do
 * not touch pool memory at all.
 *
 * The handler siglongjmps only when (a) the fault is a real kernel
 * fault (si_code > 0) and (b) si_addr is inside the pool mapping
 * range that the dispatched recipe drew.  The 3 pool-drawing recipes
 * publish their drawn range into the file-scope statics below right
 * after get_map_with_prot() returns; non-pool-drawing recipes never
 * touch the statics, so the range stays at 0..0 (set by the wrap
 * site before sigsetjmp) and every si_addr falls outside.  An
 * outside-range fault — including any fault from a non-pool recipe —
 * restores SIG_DFL and re-raises so child_fault_handler diagnoses +
 * exits and the per-pid bug log path is preserved.
 *
 * Volatile-qualified for the same reason as the equivalent statics
 * in memory-pressure: stop the compiler hoisting/coalescing reads
 * across the asynchronous handler entry.  Aligned word reads are
 * atomic on supported arches; the writes complete before sigaction
 * installs the handler so ordering is provided by the kernel-side
 * sigaction barrier (or, for the per-recipe writes, by the fact
 * that the handler can only be entered as a result of a fault
 * delivered to this thread after the writes have committed). */
static sigjmp_buf iouring_recipes_pool_race_jmp;
volatile uintptr_t iouring_recipes_pool_race_addr_low;
volatile uintptr_t iouring_recipes_pool_race_addr_high;

static __attribute__((no_sanitize("address")))
void iouring_recipes_pool_race_handler(int sig, siginfo_t *info,
					      void *ctx)
{
	uintptr_t fault_addr;

	(void)ctx;
	if (info->si_code <= 0 && info->si_pid != mypid()) {
		/* Sibling-spoofed — kernel consumed the signal already. */
		return;
	}
	if (info->si_code <= 0) {
		/* Self-sent (glibc abort etc.) — restore default and
		 * re-raise so child_fault_handler diagnoses + exits.
		 * siglongjmp here would orphan the allocator lock. */
		signal(sig, SIG_DFL);
		raise(sig);
		return;
	}

	fault_addr = (uintptr_t)info->si_addr;
	if (fault_addr < iouring_recipes_pool_race_addr_low ||
	    fault_addr >= iouring_recipes_pool_race_addr_high) {
		/* Real kernel fault but si_addr is outside the drawn
		 * pool range (including the range-empty case for the 12
		 * non-pool-drawing recipes) — not the race we're guarding
		 * against.  Restore default and re-raise so
		 * child_fault_handler diagnoses + exits and the bug log
		 * path is preserved. */
		signal(sig, SIG_DFL);
		raise(sig);
		return;
	}
	siglongjmp(iouring_recipes_pool_race_jmp, 1);
}

/* ------------------------------------------------------------------ *
 * Recipe 1: NOP chain (sanity + linked-SQE chain dispatch)
 *
 * Submit three IORING_OP_NOP SQEs where the first two carry
 * IOSQE_IO_LINK so they execute as a linked sequence.  NOP has no
 * side effects; the target here is the chain-dispatch logic: the kernel
 * must propagate the linked state through two members before posting
 * the final unlinked completion.
 * ------------------------------------------------------------------ */
static bool recipe_nop_chain(struct iour_recipe_state *s,
			      bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqes[3];
	int r;

	sqe_clear(&sqes[0]);
	sqes[0].opcode    = IORING_OP_NOP;
	sqes[0].flags     = IOSQE_IO_LINK;
	sqes[0].user_data = 1;

	sqe_clear(&sqes[1]);
	sqes[1].opcode    = IORING_OP_NOP;
	sqes[1].flags     = IOSQE_IO_LINK;
	sqes[1].user_data = 2;

	sqe_clear(&sqes[2]);
	sqes[2].opcode    = IORING_OP_NOP;
	sqes[2].user_data = 3;

	if (!iour_submit_sqes(ctx, sqes, 3))
		return false;

	r = iour_enter(ctx, 3, 3);
	if (r < 0)
		return false;

	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe 7: NOP chain with IOSQE_CQE_SKIP_SUCCESS
 *
 * Submit three NOPs where the middle one has IOSQE_CQE_SKIP_SUCCESS.
 * The kernel should post CQEs for the first and last but suppress the
 * middle one on success.  This exercises the CQE-skip accounting path
 * and its interaction with linked requests.
 * ------------------------------------------------------------------ */
static bool recipe_nop_cqe_skip(struct iour_recipe_state *s,
				bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqes[3];
	int r;

	sqe_clear(&sqes[0]);
	sqes[0].opcode    = IORING_OP_NOP;
	sqes[0].flags     = IOSQE_IO_LINK;
	sqes[0].user_data = 60;

	sqe_clear(&sqes[1]);
	sqes[1].opcode    = IORING_OP_NOP;
	sqes[1].flags     = IOSQE_IO_LINK | IOSQE_CQE_SKIP_SUCCESS;
	sqes[1].user_data = 61;

	sqe_clear(&sqes[2]);
	sqes[2].opcode    = IORING_OP_NOP;
	sqes[2].user_data = 62;

	if (!iour_submit_sqes(ctx, sqes, 3))
		return false;

	r = iour_enter(ctx, 3, 2);
	if (r < 0)
		return false;

	iour_drain_cqes(ctx);
	return true;
}

static const struct iour_recipe catalog[] = {
	{ "nop_chain",              recipe_nop_chain              },
	{ "timeout_drain",          recipe_timeout_drain          },
	{ "poll_multishot",         recipe_poll_multishot         },
	{ "send_recv_linked",       recipe_send_recv_linked       },
	{ "openat_close_linked",    recipe_openat_close_linked    },
	{ "socket_shutdown_linked", recipe_socket_shutdown_linked },
	{ "nop_cqe_skip",           recipe_nop_cqe_skip           },
	{ "async_cancel",           recipe_async_cancel           },
	{ "fixed_buffer_read",      recipe_fixed_buffer_read      },
	{ "write_read_fixed",       recipe_write_read_fixed       },
	{ "provide_buffers",        recipe_provide_buffers        },
	{ "msg_ring",               recipe_msg_ring               },
	{ "statx_fixed_file",       recipe_statx_fixed_file       },
#ifndef TRINITY_COMPAT_BACKFILLED_FUTEX_WAIT_WAKE
	{ "futex_wait_wake",        recipe_futex_wait_wake        },
#endif
	{ "epoll_wait",             recipe_epoll_wait             },
	{ "sendmsg",                recipe_sendmsg                },
	{ "recvmsg",                recipe_recvmsg                },
	{ "accept",                 recipe_accept                 },
	{ "connect",                recipe_connect                },
#ifndef TRINITY_COMPAT_BACKFILLED_BIND
	{ "bind",                   recipe_bind                   },
#endif
	{ "listen",                 recipe_listen                 },
	{ "fsync",                  recipe_fsync                  },
	{ "sync_file_range",        recipe_sync_file_range        },
	{ "readv",                  recipe_readv                  },
	{ "writev",                 recipe_writev                 },
	{ "fallocate",              recipe_fallocate              },
	{ "ftruncate",              recipe_ftruncate              },
	{ "fadvise",                recipe_fadvise                },
	{ "read_multishot",         recipe_read_multishot         },
	{ "openat2",                recipe_openat2                },
	{ "openat2_leak_combos",    recipe_openat2_leak_combos    },
	{ "epoll_ctl",              recipe_epoll_ctl              },
	{ "splice",                 recipe_splice                 },
	{ "tee",                    recipe_tee                    },
	{ "files_update",           recipe_files_update           },
	{ "link_timeout",           recipe_link_timeout           },
	{ "timeout_remove",         recipe_timeout_remove         },
	{ "renameat",               recipe_renameat               },
	{ "unlinkat",               recipe_unlinkat               },
	{ "mkdirat",                recipe_mkdirat                },
	{ "symlinkat",              recipe_symlinkat              },
	{ "linkat",                 recipe_linkat                 },
	{ "setxattr",               recipe_setxattr               },
	{ "fsetxattr",              recipe_fsetxattr              },
	{ "getxattr",               recipe_getxattr               },
	{ "fgetxattr",              recipe_fgetxattr              },
	{ "waitid",                 recipe_waitid                 },
	{ "eventfd_recursive",      recipe_eventfd_recursive      },
	/*
	 * Deferred to follow-up: per-op submission requires setup the
	 * recipe harness doesn't track yet, so they're intentionally
	 * absent from the catalog rather than stubbed:
	 *   IORING_OP_FUTEX_WAITV       — needs a struct futex_waitv[] vector
	 *   IORING_OP_FIXED_FD_INSTALL  — needs a registered-file slot index
	 *                                 to be wired up at submission time
	 *   IORING_OP_NOP128            — needs IORING_SETUP_SQE128 ring
	 *   IORING_OP_URING_CMD128      — needs IORING_SETUP_SQE128 ring
	 */
};

_Static_assert(ARRAY_SIZE(catalog) <= MAX_IOURING_RECIPES,
	       "iouring recipe catalog outgrew MAX_IOURING_RECIPES; bump it");

bool iouring_recipes(struct childdata *child)
{
	struct iour_ring ctx;
	struct iour_recipe_state state;
	const struct iour_recipe *r;
	/* volatile: read after sigsetjmp/siglongjmp window so the value
	 * must survive the longjmp register-clobber per ISO C 7.13.2.1. */
	volatile unsigned int idx;
	unsigned int tries;
	bool unsupported = false;
	bool ok;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.iouring_recipes.runs, 1,
			   __ATOMIC_RELAXED);

	/* Latch: once we know io_uring_setup returns ENOSYS, stop trying. */
	if (__atomic_load_n(&shm->iouring_enosys, __ATOMIC_RELAXED))
		return true;

	/* Pick a recipe that hasn't been disabled. */
	for (tries = 0; tries < 8; tries++) {
		idx = rnd_modulo_u32((unsigned int)ARRAY_SIZE(catalog));
		if (!__atomic_load_n(&shm->iouring_recipe_disabled[idx],
				     __ATOMIC_RELAXED))
			break;
	}
	if (tries == 8)
		return true;

	r = &catalog[idx];

	{
		struct io_uring_params p;
		enum iour_setup_status st;

		memset(&p, 0, sizeof(p));
		st = iour_ring_setup(&p, (unsigned int)RAND_NEGATIVE_OR(16),
				     &ctx);
		if (st != IOUR_SUPPORTED) {
			/* Latch the per-process iouring_enosys gate only on
			 * a real "this kernel won't ever support io_uring"
			 * verdict.  A transient (ENOMEM/EAGAIN/EMFILE, an
			 * overflow-rejected hostile kernel return, an mmap
			 * blip) skips this invocation but leaves siblings
			 * free to retry on the next dispatch. */
			if (st == IOUR_UNSUPPORTED)
				__atomic_store_n(&shm->iouring_enosys, true,
						 __ATOMIC_RELAXED);
			return true;
		}
	}

	/* Ring is up: the per-process io_uring probe was accepted and
	 * the dispatcher is committed to driving a recipe through it.
	 * Bump setup_accepted before data_path so the invariant
	 * data_path <= setup_accepted holds at every observation point. */
	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	iour_recipe_state_init(&state, &ctx);

	{
		struct sigaction sa, old_segv, old_bus;
		bool aborted = false;

		/* Default empty range — non-pool-drawing recipes leave it
		 * empty so every si_addr falls outside and the handler
		 * defers to child_fault_handler.  The 3 pool-drawing
		 * recipes overwrite it from inside r->run() right after
		 * their get_map_with_prot() draw. */
		iouring_recipes_pool_race_addr_low  = 0;
		iouring_recipes_pool_race_addr_high = 0;

		memset(&sa, 0, sizeof(sa));
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = SA_SIGINFO;
		sa.sa_sigaction = iouring_recipes_pool_race_handler;
		sigaction(SIGSEGV, &sa, &old_segv);
		sigaction(SIGBUS,  &sa, &old_bus);

		if (sigsetjmp(iouring_recipes_pool_race_jmp, 1) == 0) {
			ok = r->run(&state, &unsupported);
		} else {
			aborted = true;
			ok = false;
		}

		sigaction(SIGSEGV, &old_segv, NULL);
		sigaction(SIGBUS,  &old_bus,  NULL);

		iouring_recipes_pool_race_addr_low  = 0;
		iouring_recipes_pool_race_addr_high = 0;

		if (aborted) {
			/* siglongjmp skipped the recipe's own out: cleanup,
			 * but the per-iteration resources it allocated are
			 * recorded in &state and torn down by
			 * iour_recipe_state_cleanup() below.  The outer
			 * iour_ring_teardown() then releases the ring mmaps +
			 * ring fd that iour_ring_setup() populated above.
			 * Don't latch
			 * iouring_recipe_disabled[idx] — faults are not
			 * ENOSYS. */
			__atomic_add_fetch(
				&shm->stats.childop.pool_race_aborted[CHILD_OP_IOURING_RECIPES],
				1, __ATOMIC_RELAXED);
		}
	}

	iour_recipe_state_cleanup(&state);
	iour_ring_teardown(&ctx);

	if (unsupported)
		__atomic_store_n(&shm->iouring_recipe_disabled[idx], true,
				 __ATOMIC_RELAXED);

	if (ok) {
		__atomic_add_fetch(&shm->stats.iouring_recipes.completed, 1,
				   __ATOMIC_RELAXED);
		__atomic_add_fetch(
			&shm->stats.iouring_recipes.completed_per[idx], 1,
			__ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&shm->stats.iouring_recipes.partial, 1,
				   __ATOMIC_RELAXED);
	}

	return true;
}

void __cold iouring_recipes_dump_stats(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(catalog); i++) {
		unsigned long n = __atomic_load_n(
			&shm->stats.iouring_recipes.completed_per[i],
			__ATOMIC_RELAXED);
		bool disabled = __atomic_load_n(
			&shm->iouring_recipe_disabled[i],
			__ATOMIC_RELAXED);

		if (n == 0 && !disabled)
			continue;

		output(0, "  %-24s %lu%s\n", /* check-static: child-output-ok */
			catalog[i].name, n,
			disabled ? " (disabled — kernel feature absent)" : "");
	}
}
