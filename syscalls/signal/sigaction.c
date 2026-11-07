/*
 * SYSCALL_DEFINE4(rt_sigaction, int, sig,
	const struct sigaction __user *, act,
	struct sigaction __user *, oact,
	size_t, sigsetsize)
 */
#include <signal.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "output-poison.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "utils-mem.h"

#include "kernel/prctl.h"

/* Kernel sigset_t is a fixed 64-bit mask; sizeof matches on every arch. */
#define KERNEL_SIGSET_SIZE	8

/*
 * rt_sigaction copies in the kernel's struct sigaction
 * (include/linux/signal_types.h), not glibc's, which puts a 1024-bit
 * sa_mask straight after the handler.  sa_restorer sits before the mask
 * where the arch has SA_RESTORER; a compat call reads 32-bit fields.
 */
#if defined(__x86_64__) || defined(__i386__) || defined(__arm__) || defined(__aarch64__)
#define KERNEL_SA_HAS_RESTORER
#ifndef SA_RESTORER
#define SA_RESTORER	0x04000000	/* the uapi value; glibc keeps it to itself */
#endif
#endif

struct kernel_sigaction {
	unsigned long handler;
	unsigned long flags;
#ifdef KERNEL_SA_HAS_RESTORER
	unsigned long restorer;
#endif
	unsigned long mask[KERNEL_SIGSET_SIZE / sizeof(unsigned long)];
};

struct compat_kernel_sigaction {
	uint32_t handler;
	uint32_t flags;
	uint32_t restorer;
	uint32_t mask[2];
};

/*
 * Snapshot of the rt_sigaction args the post oracle reads, captured at
 * sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect the oact discriminator at a foreign
 * user buffer or invalidate the poison_seed the untouched-buffer check
 * matches against.
 */
#define RT_SIGACTION_POST_STATE_MAGIC	0x52545347UL	/* "RTSG" */
struct rt_sigaction_post_state {
	unsigned long magic;
	unsigned long oact;
	/*
	 * Seed for the poison pattern stamped over the oact struct at
	 * sanitise time.  Returned by poison_output_struct() and fed back
	 * into check_output_struct_user_or_skip() in the post handler so a
	 * stomp of rec->a3 cannot redirect the check against an unrelated
	 * heap page that happens to still carry the original (or any) byte
	 * pattern.  Stays 0 when sanitise refused to stamp (oact == 0 or
	 * the range is not provably readable), which the post handler
	 * treats as "skip the arm".
	 */
	uint64_t poison_seed;
	/* Length of the oact struct for the call's ABI: what the poison
	 * covers and the check walks. */
	unsigned long size;
};

/*
 * sa_flags shapes.  We assemble subsets out of this pool and (depending
 * on the bucket draw) bolt on a random extra bit or fall through to a
 * pure rand32(), so the validation paths around SA_SIGINFO,
 * SA_NODEFER, SA_RESETHAND, SA_RESTART, SA_ONSTACK, SA_NOCLDSTOP and
 * SA_NOCLDWAIT all stay warm without random draws stalling forever on
 * undefined bits.
 */
static const unsigned int sa_flag_pool[] = {
	SA_SIGINFO,
	SA_NODEFER,
	SA_RESETHAND,
	SA_RESTART,
	SA_ONSTACK,
	SA_NOCLDSTOP,
	SA_NOCLDWAIT,
};

/* Real signals we are willing to install a handler for via the default
 * settable bucket below.  The synchronous-fault class (SIGILL/SIGTRAP/
 * SIGABRT/SIGBUS/SIGFPE/SIGSEGV) is deliberately excluded here: a
 * draw that pairs one of those signos with the SIG_DFL/SIG_IGN/dummy/
 * wild-pointer handler bucket in alloc_sigaction() replaces trinity's
 * own child_fault_handler (installed exactly once per child in
 * health/signals-policy.c::mask_signals_child, never re-armed), so the
 * next benign self-fault -- a scrubbed-pointer deref during arg-gen, a
 * sibling shm scribble -- either kills the child uncaught or is
 * mis-attributed by the parent's reaper as a kernel crash.  Same
 * self-instrumentation-defeat class as PR_SET_MDWE in prctl().  The
 * fault signals stay reachable via the small fault_class_signals[]
 * bucket in pick_signal_target() so install-path coverage for those
 * signos is preserved at a rate low enough not to dominate runs with
 * mis-attributed deaths.
 *
 * SIGKILL/SIGSTOP are rejected by the kernel before sa_flags are ever
 * inspected; the forbidden bucket targets them explicitly to keep the
 * EINVAL gate exercised.
 */
static const unsigned long settable_signals[] = {
	SIGHUP, SIGINT, SIGQUIT, SIGUSR1, SIGUSR2,
	SIGPIPE, SIGALRM, SIGCHLD, SIGCONT, SIGTSTP,
	SIGTTIN, SIGTTOU, SIGURG, SIGXCPU, SIGXFSZ,
	SIGVTALRM, SIGPROF, SIGWINCH, SIGIO, SIGPWR,
	SIGSYS,
};

/* Synchronous-fault class -- excluded from settable_signals[] above to
 * avoid wiping trinity's child_fault_handler.  Drawn at low rate in
 * pick_signal_target() so do_sigaction() coverage for these signos
 * stays warm without the per-call handler-clobber probability that the
 * pre-curation default pool carried.
 */
static const unsigned long fault_class_signals[] = {
	SIGILL, SIGTRAP, SIGABRT, SIGBUS, SIGFPE, SIGSEGV,
};

/*
 * A stand-in for "looks like a valid handler address".  Using the
 * address of an in-binary function gives the kernel a pointer that
 * passes the cursory access check; the kernel does not deref this on
 * the install path (only on delivery), but having one bucket aim at a
 * mapped code address keeps the install-side cache effects realistic.
 * sighandler() in health/signals-policy.c is static, so we route
 * through a local function whose address we can take.
 */
static void sigaction_dummy_handler(int sig)
{
	(void) sig;
}

static void sigaction_dummy_sigaction(int sig, siginfo_t *info, void *uctx)
{
	(void) sig;
	(void) info;
	(void) uctx;
}

static unsigned int build_sa_flags(void)
{
	unsigned int flags = 0;
	unsigned int i, draw;

	draw = rnd_modulo_u32(10);
	if (draw < 7) {
		/* legal subset: roll each pool bit independently */
		for (i = 0; i < ARRAY_SIZE(sa_flag_pool); i++) {
			if (RAND_BOOL())
				flags |= sa_flag_pool[i];
		}
	} else if (draw < 9) {
		/* legal subset plus a stray random bit */
		for (i = 0; i < ARRAY_SIZE(sa_flag_pool); i++) {
			if (RAND_BOOL())
				flags |= sa_flag_pool[i];
		}
		flags |= (1u << rnd_modulo_u32(32));
	} else {
		/* pure random */
		flags = (unsigned int) rand32();
	}
	return flags;
}

static uint64_t build_sa_mask(void)
{
	unsigned int draw = rnd_modulo_u32(10);

	if (draw < 7)
		/* sigfillset minus the forbidden ones -- legal "block all
		 * I can block" mask, what real userspace tends to use. */
		return ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
	if (draw < 9)
		return 0;
	return rnd_u64();
}

#ifdef __x86_64__
/*
 * x86-64 sets up a signal frame only through the restorer the action
 * names (arch/x86/kernel/signal_64.c refuses one without SA_RESTORER),
 * and a raw rt_sigaction gets none from glibc.  Borrow glibc's from the
 * child's SIGALRM flag-setter, which glibc's sigaction() installed: a
 * child reads it here, building its first act, before any install of
 * its own can have replaced that handler.
 */
static unsigned long glibc_restorer(void)
{
	static unsigned long restorer;
	struct kernel_sigaction cur;

	if (restorer == 0 &&
	    syscall(__NR_rt_sigaction, SIGALRM, NULL, &cur,
		    KERNEL_SIGSET_SIZE) == 0 &&
	    (cur.flags & SA_RESTORER))
		restorer = cur.restorer;
	return restorer;
}
#endif

/*
 * Build an act in the call's ABI layout in the writable pool, or return
 * 0 when the pool has none to give.
 */
static unsigned long alloc_sigaction(const struct syscallrecord *rec)
{
	unsigned long handler, flags;
	uint64_t mask;
	unsigned int draw;
	void *act;

	act = get_writable_address(rec->do32bit ?
				   sizeof(struct compat_kernel_sigaction) :
				   sizeof(struct kernel_sigaction));
	if (act == NULL)
		return 0;

	mask = build_sa_mask();
	flags = build_sa_flags();

	/* Handler bucket distribution: roughly 25/25/30/10/10. */
	draw = rnd_modulo_u32(100);
	if (draw < 25) {
		handler = (unsigned long) SIG_DFL;
		flags &= ~SA_SIGINFO;
	} else if (draw < 50) {
		handler = (unsigned long) SIG_IGN;
		flags &= ~SA_SIGINFO;
	} else if (draw < 80) {
		handler = (unsigned long) sigaction_dummy_handler;
		flags &= ~SA_SIGINFO;
	} else if (draw < 90) {
		handler = (unsigned long) sigaction_dummy_sigaction;
		flags |= SA_SIGINFO;
	} else {
		/* Intentionally invalid pointer -- the kernel does not deref
		 * sa_handler on install, but copy_from_user on the struct is
		 * still exercised, and the install of a wild handler keeps
		 * the eventual-delivery validation path realistic. */
		handler = rand32();
	}

	/* Every field is written: the writable-address pool returns
	 * uninitialised bytes, and the kernel copies the whole struct
	 * in on every install. */
	if (rec->do32bit) {
		struct compat_kernel_sigaction *csa = act;

		csa->handler = (uint32_t) handler;
		csa->flags = (uint32_t) flags;
		csa->restorer = 0;	/* glibc's is 64-bit code */
		csa->mask[0] = (uint32_t) mask;
		csa->mask[1] = (uint32_t) (mask >> 32);
	} else {
		struct kernel_sigaction *sa = act;
		unsigned int i;

		sa->handler = handler;
#ifdef __x86_64__
		sa->restorer = glibc_restorer();
		if (sa->restorer != 0)
			flags |= SA_RESTORER;
#elif defined(KERNEL_SA_HAS_RESTORER)
		sa->restorer = 0;
#endif
		sa->flags = flags;
		for (i = 0; i < ARRAY_SIZE(sa->mask); i++)
			sa->mask[i] = (unsigned long)
				(mask >> (i * 8 * sizeof(unsigned long)));
	}
	return (unsigned long) act;
}

static unsigned long pick_signal_target(void)
{
	unsigned int draw = rnd_modulo_u32(100);
	int rtcount = SIGRTMAX - SIGRTMIN + 1;

	if (draw < 5) {
		/* Intentionally-uninstallable bucket -- keeps EINVAL gate
		 * for SIGKILL/SIGSTOP warm. */
		static const unsigned long forbidden[] = { SIGKILL, SIGSTOP };
		return RAND_ARRAY(forbidden);
	}
	if (draw < 10)
		/* Synchronous-fault class: kept reachable at low rate so
		 * do_sigaction() coverage for these signos stays warm; see
		 * settable_signals[] for why this is not folded into the
		 * default bucket. */
		return RAND_ARRAY(fault_class_signals);
	if (draw < 70)
		return RAND_ARRAY(settable_signals);
	if (rtcount > 0)
		return SIGRTMIN + rnd_modulo_u32(rtcount);
	return RAND_ARRAY(settable_signals);
}

static void sanitise_rt_sigaction(struct syscallrecord *rec)
{
	struct rt_sigaction_post_state *snap;
	unsigned long size = rec->do32bit ?
			     sizeof(struct compat_kernel_sigaction) :
			     sizeof(struct kernel_sigaction);

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	rec->a1 = pick_signal_target();
	rec->a2 = RAND_BOOL() ? 0 : alloc_sigaction(rec);
	avoid_shared_buffer_inout(&rec->a2, size);
	rec->a3 = RAND_BOOL() ? 0 : alloc_sigaction(rec);
	rec->a4 = KERNEL_SIGSET_SIZE;

	avoid_shared_buffer_out(&rec->a3, size);

	/*
	 * Snapshot oact for the post oracle.  Without this the post handler
	 * reads rec->a3 at post-time, when a sibling syscall may have
	 * scribbled the slot: looks_like_corrupted_ptr() cannot tell a
	 * real-but-wrong heap address from the original user buffer pointer,
	 * so the poison-writeback check would run against a foreign
	 * allocation.  post_state is private to the post handler.
	 * post_state_install pairs the rec->post_state assign with the
	 * ownership-table register so the observable window between the two
	 * is closed; post_rt_sigaction() will then gate the snap through
	 * post_state_claim_owned() and prove ownership before dereferencing
	 * any field.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic       = RT_SIGACTION_POST_STATE_MAGIC;
	snap->oact        = rec->a3;
	snap->poison_seed = 0;
	snap->size        = size;

	/*
	 * Stamp a per-call poison pattern into the oact struct the kernel
	 * is about to fill.  The post handler asks
	 * check_output_struct_user_or_skip() whether the pattern survived
	 * intact on a success return; if it did, the kernel reported
	 * success but skipped copy_to_user across the region it is
	 * contractually required to fill -- torn copy, early-exit before
	 * fill, or mis-wired compat wrapper.  Done after
	 * avoid_shared_buffer_out() so the poison lands on the final
	 * buffer the kernel will see (the relocation may have swapped
	 * rec->a3 for a fresh page).  Gate on range_readable_user() so a
	 * writable-pool draw that avoid_shared_buffer_out relocated to
	 * an address no longer provably mapped does not SIGSEGV inside
	 * poison_output_struct's byte-walk; on skip poison_seed stays 0
	 * and the post handler no-ops the arm.  Seed is drawn from
	 * rnd_u64() only after all input-selection RNG draws above have
	 * settled, so --dry-run byte-output stays identical to a build
	 * without this oracle (poison writes are byte-identical to a
	 * post-selection scribble on already-uninitialised writable-pool
	 * memory).
	 */
	if (rec->a3 != 0 &&
	    range_readable_user((void *)(unsigned long) rec->a3, size))
		snap->poison_seed =
			poison_output_struct((void *)(unsigned long) rec->a3,
					     size, 0);

	post_state_install(rec, snap);
}

/*
 * Oracle: if the caller asked for the old action via a non-NULL oact,
 * run two complementary checks on the buffer the kernel wrote back.
 *
 * Arm 1 (poison writeback, every call): check_output_struct_user_or_skip
 * returns true iff every byte of the oact struct still matches the
 * per-call poison pattern poison_output_struct stamped at sanitise time.
 * A match on a retval == 0 return means the kernel reported success but
 * skipped copy_to_user across the region it is contractually required to
 * fill -- torn copy, early-exit before fill, or mis-wired compat wrapper.
 * Silent when sanitise refused to stamp (poison_seed == 0) or snap->oact
 * is NULL.  Not sampled -- cheap enough (a bounded byte-walk with no
 * re-entry into the kernel) that dilution through ONE_IN would waste
 * signal on a real bug.
 *
 * Arm 2 (sa_handler discriminator, 1/64 sample): sa_handler is either
 * SIG_DFL, SIG_IGN, or a function pointer; SA_SIGINFO chooses the
 * sa_sigaction union arm.  An uninitialised-stack write from the kernel
 * would land in neither bucket: zero is SIG_DFL by definition but a
 * non-zero ~kernel pointer that is neither SIG_IGN nor a mapped code
 * address shows up here.  Sampled sparingly so a misbehaving kernel does
 * not drown the log.  Routes through snap->oact so a sibling that
 * scribbled rec->a3 between syscall return and post entry cannot retarget
 * the deref at a foreign heap allocation.
 */
static void post_rt_sigaction(struct syscallrecord *rec)
{
	struct rt_sigaction_post_state *snap;
	const struct kernel_sigaction *oact;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, RT_SIGACTION_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_release;
	if (snap->oact == 0)
		goto out_release;

	if (snap->poison_seed != 0 &&
	    check_output_struct_user_or_skip((void *)(unsigned long) snap->oact,
					     snap->size, snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	/* A compat oact's handler is 32 bits, which the check below
	 * cannot fault. */
	if (!ONE_IN(64) || snap->size != sizeof(struct kernel_sigaction))
		goto out_release;

	oact = (const struct kernel_sigaction *)(unsigned long) snap->oact;
	/* SIG_DFL is (void *)0; SIG_IGN is (void *)1.  Anything else
	 * must look like a code pointer.  We cannot probe mapping
	 * legitimacy from here, but we can flag obvious garbage like
	 * a stack-shaped address sitting in kernel-range bits. */
	if (oact->handler == (unsigned long) SIG_DFL ||
	    oact->handler == (unsigned long) SIG_IGN)
		goto out_release;
	{
		unsigned long h = oact->handler;
		/* On 64-bit user pointers, bits 48..63 should all be 0
		 * for canonical userspace addresses.  If the top bits
		 * are set we may be looking at a kernel pointer leak or
		 * uninitialised stack data. */
		if (sizeof(void *) == 8 && (h >> 48) != 0) {
			output(0,
			       "[oracle:rt_sigaction] suspicious oact->sa_handler=0x%lx\n",
			       h);
		}
	}

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_rt_sigaction = {
	.name = "rt_sigaction",
	.group = GROUP_SIGNAL,
	.num_args = 4,
	.sanitise = sanitise_rt_sigaction,
	.post = post_rt_sigaction,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS, [3] = ARG_LEN },
	.argname = { [0] = "sig", [1] = "act", [2] = "oact", [3] = "sigsetsize" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = _NSIG,
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
};


/*
 * asmlinkage int
   sys_sigaction(int sig, const struct old_sigaction __user *act,
   struct old_sigaction __user *oact)
 */

struct syscallentry syscall_sigaction = {
	.name = "sigaction",
	.group = GROUP_SIGNAL,
	.num_args = 3,
	.sanitise = sanitise_rt_sigaction,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS },
	.argname = { [0] = "sig", [1] = "act", [2] = "oact" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = _NSIG,
	/* sanitise_rt_sigaction is re-exec clean (heap allocs + post_state
	 * only, no global side effects): keep REEXEC_SANITISE_OK.  AVOID_REEXEC
	 * belt-and-braces alongside AVOID_SYSCALL. */
	.flags = AVOID_SYSCALL | AVOID_REEXEC | REEXEC_SANITISE_OK,
	.rettype = RET_ZERO_SUCCESS,
};
