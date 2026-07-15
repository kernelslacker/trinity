/*
 * SYSCALL_DEFINE4(rt_sigaction, int, sig,
	const struct sigaction __user *, act,
	struct sigaction __user *, oact,
	size_t, sigsetsize)
 */
#include <signal.h>
#include <string.h>
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
 * signals.c::mask_signals_child, never re-armed), so the next benign
 * self-fault -- a scrubbed-pointer deref during arg-gen, a sibling shm
 * scribble -- either kills the child uncaught or is mis-attributed by
 * the parent's reaper as a kernel crash.  Same self-instrumentation-
 * defeat class as PR_SET_MDWE in prctl().  The fault signals stay
 * reachable via the small fault_class_signals[] bucket in
 * pick_signal_target() so install-path coverage for those signos is
 * preserved at a rate low enough not to dominate runs with mis-
 * attributed deaths.
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
 * sighandler() in signals.c is static, so we route through a local
 * function whose address we can take.
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

static void build_sa_mask(sigset_t *mask)
{
	unsigned int draw = rnd_modulo_u32(10);

	if (draw < 7) {
		/* sigfillset minus the forbidden ones -- legal "block all
		 * I can block" mask, what real userspace tends to use. */
		sigfillset(mask);
		sigdelset(mask, SIGKILL);
		sigdelset(mask, SIGSTOP);
	} else if (draw < 9) {
		sigemptyset(mask);
	} else {
		unsigned int i;
		sigemptyset(mask);
		for (i = 0; i < sizeof(*mask); i++)
			((unsigned char *) mask)[i] = (unsigned char) rand32();
	}
}

static struct sigaction *alloc_sigaction(void)
{
	struct sigaction *sa;
	unsigned int draw;

	sa = (struct sigaction *) get_writable_address(sizeof(*sa));
	if (sa == NULL)
		return NULL;

	/* Zero the struct before setting a subset of fields -- the
	 * writable-address pool returns uninitialised bytes, and
	 * sa_restorer (plus any reserved padding around the union) is
	 * neither picked below nor overwritten by the kernel on input,
	 * so without this the kernel copies uninitialised bytes on
	 * every rt_sigaction/sigaction install. */
	memset(sa, 0, sizeof(*sa));

	build_sa_mask(&sa->sa_mask);
	sa->sa_flags = build_sa_flags();

	/* Handler bucket distribution: roughly 25/25/30/10/10. */
	draw = rnd_modulo_u32(100);
	if (draw < 25) {
		sa->sa_handler = SIG_DFL;
		sa->sa_flags &= ~SA_SIGINFO;
	} else if (draw < 50) {
		sa->sa_handler = SIG_IGN;
		sa->sa_flags &= ~SA_SIGINFO;
	} else if (draw < 80) {
		sa->sa_handler = sigaction_dummy_handler;
		sa->sa_flags &= ~SA_SIGINFO;
	} else if (draw < 90) {
		sa->sa_sigaction = sigaction_dummy_sigaction;
		sa->sa_flags |= SA_SIGINFO;
	} else {
		/* Intentionally invalid pointer -- the kernel does not deref
		 * sa_handler on install, but copy_from_user on the struct is
		 * still exercised, and the install of a wild handler keeps
		 * the eventual-delivery validation path realistic. */
		sa->sa_handler = (void (*)(int)) (unsigned long) rand32();
	}
	return sa;
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

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	rec->a1 = pick_signal_target();
	rec->a2 = RAND_BOOL() ? 0 : (unsigned long) alloc_sigaction();
	avoid_shared_buffer_inout(&rec->a2, sizeof(struct sigaction));
	rec->a3 = RAND_BOOL() ? 0 : (unsigned long) alloc_sigaction();
	rec->a4 = KERNEL_SIGSET_SIZE;

	avoid_shared_buffer_out(&rec->a3, sizeof(struct sigaction));

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
	    range_readable_user((void *)(unsigned long) rec->a3,
				sizeof(struct sigaction)))
		snap->poison_seed =
			poison_output_struct((void *)(unsigned long) rec->a3,
					     sizeof(struct sigaction), 0);

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
	const struct sigaction *oact;

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
					     sizeof(struct sigaction),
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (!ONE_IN(64))
		goto out_release;

	oact = (const struct sigaction *)(unsigned long) snap->oact;
	/* SIG_DFL is (void *)0; SIG_IGN is (void *)1.  Anything else
	 * must look like a code pointer.  We cannot probe mapping
	 * legitimacy from here, but we can flag obvious garbage like
	 * a stack-shaped address sitting in kernel-range bits. */
	if (oact->sa_handler == SIG_DFL || oact->sa_handler == SIG_IGN)
		goto out_release;
	{
		unsigned long h = (unsigned long) oact->sa_handler;
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
	.flags = AVOID_SYSCALL,
	.rettype = RET_ZERO_SUCCESS,
};
