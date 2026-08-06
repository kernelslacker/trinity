/*
 * kvm_mmu_reclaim_race -- intentional sequencing harness for the
 * KVM shadow-MMU reclaim path (ZapScape / CVE-2026-64561 family).
 *
 * Three concurrent lanes:
 *
 *   Lane 1 (main thread): KVM_PRE_FAULT_MEMORY storm across a wide GPA
 *     range.  Drives kvm_mmu_do_page_fault() → vcpu->arch.mmu->page_fault()
 *     with no guest code execution.  With kvm.tdp_mmu=0 (boot flag)
 *     this reaches direct_page_fault() and make_mmu_pages_available() --
 *     the exact path patched by ZapScape.
 *
 *   Lane 2 (squeeze thread): KVM_SET_NR_MMU_PAGES squeeze/restore loop.
 *     Squeezes n_max_mmu_pages to KVM_MIN_FREE_MMU_PAGES (10) so every
 *     subsequent fault triggers make_mmu_pages_available() →
 *     kvm_mmu_zap_oldest_mmu_pages().  This is the engine of the bug:
 *     without the squeeze, the reclaim path never runs and the race window
 *     never opens.
 *
 *   Lane 3 (churn thread): memslot delete/re-add loop.  Concurrent root
 *     invalidation ensures reclaim has an in-use root available to zap,
 *     reproducing the precondition that lets the reclaim zap an active root
 *     and put an invalid shadow page on the active_mmu_pages list.
 *     Note: KVM_SET_MEMORY_ATTRIBUTES is only present when the kernel is
 *     built with CONFIG_KVM_GENERIC_MEMORY_ATTRIBUTES (selected by
 *     KVM_SW_PROTECTED_VM / KVM_AMD_SEV / KVM_INTEL_TDX).  That config is
 *     not set in the test config, so the ioctl returns -ENOTTY there.  The arm has
 *     been dropped; memslot churn alone is sufficient to open the race
 *     window.
 *
 * Oracle: CONFIG_KVM_PROVE_MMU (enabled in the test config) + the existing
 * WARN_ON_ONCE(sp->role.invalid) guards at kvm_zap_obsolete_pages()
 * (mmu.c:6861) and kvm_mmu_zap_all() (mmu.c:7480).  These fire when a
 * shadow page with role.invalid=1 lands on active_mmu_pages -- the exact
 * postcondition the ZapScape fix prevents.
 *
 * Note: KVM_PRE_FAULT_MEMORY is a vCPU ioctl (kvm_vcpu_ioctl() path); it
 * early-returns unless vcpu->arch.mmu->page_fault == kvm_tdp_page_fault
 * (mmu.c:5002), so it drives direct_page_fault() but not nested
 * ept_page_fault().  The squeeze and churn lanes run unconditionally.
 *
 * Part of the KVM MMU reclaim-race work.
 */

#ifdef USE_KVM

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <linux/kvm.h>

#include "child.h"
#include "childop-outcome.h"
#include "object-types.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * KVM_MIN_FREE_MMU_PAGES is defined in arch/x86/kvm/mmu/mmu_internal.h
 * (value 10) and is not exported to userspace.  KVM_SET_NR_MMU_PAGES
 * returns -EINVAL for values below this constant.  Squeezing to exactly
 * this value maximises reclaim pressure while keeping the ioctl valid.
 */
#define KVM_MMU_RECLAIM_MIN_PAGES	10

/*
 * n_max_mmu_pages value restored after each squeeze cycle.  Large
 * enough to let the shadow MMU populate a new generation of pages
 * before the next squeeze hits.
 */
#define KVM_MMU_RECLAIM_MAX_PAGES	512

/* Number of squeeze/restore cycles in the Lane 2 thread. */
#define RECLAIM_RACE_SQUEEZE_ITERS	8

/* Number of memslot delete/re-add cycles in the Lane 3 thread. */
#define RECLAIM_RACE_CHURN_ITERS	8

/*
 * GPA base for the wide fault storm window (sits above the
 * KVM_GUEST_MEMSLOT at GPA 0 installed by fds/kvm.c).
 */
#define RECLAIM_RACE_GPA_BASE		(1UL << 20)	/* 1 MB */

/*
 * Size of the fault-storm GPA window.  Must equal the anonymous mmap
 * allocated for the backing userspace_addr below.
 */
#define RECLAIM_RACE_GPA_WINDOW		(2UL << 20)	/* 2 MB */

/* Size per KVM_PRE_FAULT_MEMORY call (lane 1 inner chunk). */
#define RECLAIM_RACE_CHUNK_SIZE		(64UL << 10)	/* 64 KB */

/*
 * KVM memslot slot-ID used by this harness.  Slot 0 (KVM_GUEST_MEMSLOT)
 * is owned by fds/kvm.c's kvm_seed_guest(); we use slot 1.
 */
#define RECLAIM_RACE_SLOT		1

/* Number of fault-storm chunks that fit in the GPA window. */
#define RECLAIM_RACE_N_CHUNKS \
	((unsigned int)(RECLAIM_RACE_GPA_WINDOW / RECLAIM_RACE_CHUNK_SIZE))

/*
 * Shared concurrency anchors.  Lane 1 (fault storm) loops until both
 * Lane 2 and Lane 3 have completed their fixed cycle counts, then sets
 * stop=1.  Lanes 2 and 3 check stop at the top of each iteration so
 * they can exit early if Lane 1 bails for any reason.  The two-way
 * signalling guarantees the three lanes overlap for the full lifetime
 * of the shorter-lived worker threads, regardless of host speed.
 */
struct reclaim_shared {
	volatile int		stop;		/* Lane 1 → 2,3: exit now */
	volatile int		lanes_done;	/* 2,3 → Lane 1: I finished */
};

/*
 * Thread argument structs.  Each thread accumulates its own ioctl count
 * in a local counter; the main thread merges them after pthread_join()
 * (which provides the happens-before edge, so no atomic is needed for
 * direct_calls).  shared is written/read with __atomic builtins.
 */
struct squeeze_args {
	int			vmfd;
	unsigned long		direct_calls;
	struct reclaim_shared	*shared;
};

struct churn_args {
	int			vmfd;
	void			*ua;	/* backing region for the churn memslot */
	unsigned long		direct_calls;
	struct reclaim_shared	*shared;
};

/*
 * Lane 2: squeeze n_max_mmu_pages toward KVM_MIN_FREE_MMU_PAGES, then
 * restore a generous value, in a tight loop.  The brief usleep() between
 * squeeze and restore keeps the fault-storm thread inside
 * make_mmu_pages_available() (with its tight new limit) long enough for
 * kvm_mmu_zap_oldest_mmu_pages() to run.
 */
static void *squeeze_loop_thread(void *p)
{
	struct squeeze_args *a = p;
	int i;

	for (i = 0; i < RECLAIM_RACE_SQUEEZE_ITERS &&
	     !__atomic_load_n(&a->shared->stop, __ATOMIC_RELAXED); i++) {
		/* Squeeze toward KVM_MIN_FREE_MMU_PAGES so every subsequent
		 * fault calls make_mmu_pages_available() which in turn calls
		 * kvm_mmu_zap_oldest_mmu_pages().  Ignore errors: -EINVAL if
		 * the VM is not x86, -ENOTTY if the host does not have KVM. */
		a->direct_calls++;
		(void)ioctl(a->vmfd, KVM_SET_NR_MMU_PAGES,
			    (unsigned long)KVM_MMU_RECLAIM_MIN_PAGES);

		/* Hold the squeeze briefly so the fault storm runs into
		 * make_mmu_pages_available() while n_max is still tight. */
		usleep(200);

		/* Restore generous headroom before the next cycle. */
		a->direct_calls++;
		(void)ioctl(a->vmfd, KVM_SET_NR_MMU_PAGES,
			    (unsigned long)KVM_MMU_RECLAIM_MAX_PAGES);
	}

	/* Signal Lane 1 that this lane has completed its cycle count. */
	__atomic_add_fetch(&a->shared->lanes_done, 1, __ATOMIC_RELEASE);

	return NULL;
}

/*
 * Lane 3: delete and re-add the churn memslot.  Concurrent root
 * invalidation ensures reclaim has an in-use root available to zap -- the
 * precondition that opens the ZapScape race window.  The
 * KVM_SET_MEMORY_ATTRIBUTES arm was dropped: it requires
 * CONFIG_KVM_GENERIC_MEMORY_ATTRIBUTES (not set in the test config) and silently
 * returned -ENOTTY on every odd iteration.
 */
static void *churn_loop_thread(void *p)
{
	struct churn_args *a = p;
	int i;

	/*
	 * No startup delay: Lane 1 loops continuously for the full lifetime
	 * of this thread, so there is always an active fault storm to race
	 * against from the very first invalidation.
	 */
	for (i = 0; i < RECLAIM_RACE_CHURN_ITERS &&
	     !__atomic_load_n(&a->shared->stop, __ATOMIC_RELAXED); i++) {
		struct kvm_userspace_memory_region del = {
			.slot		 = RECLAIM_RACE_SLOT,
			.flags		 = 0,
			.guest_phys_addr = RECLAIM_RACE_GPA_BASE,
			.memory_size	 = 0,		/* memory_size=0 deletes */
			.userspace_addr	 = 0,
		};
		struct kvm_userspace_memory_region add = {
			.slot		 = RECLAIM_RACE_SLOT,
			.flags		 = 0,
			.guest_phys_addr = RECLAIM_RACE_GPA_BASE,
			.memory_size	 = RECLAIM_RACE_GPA_WINDOW,
			.userspace_addr	 = (__u64)(unsigned long)a->ua,
		};

		/* Delete: invalidates any roots covering this GPA range.
		 * This is the concurrent root invalidation that provides
		 * in-use roots for the reclaim path to zap. */
		a->direct_calls++;
		(void)ioctl(a->vmfd, KVM_SET_USER_MEMORY_REGION, &del);

		/* Re-add: installs fresh roots.  The new generation triggers
		 * shadow-page reuse, which is sufficient to open the race
		 * window without KVM_SET_MEMORY_ATTRIBUTES. */
		a->direct_calls++;
		(void)ioctl(a->vmfd, KVM_SET_USER_MEMORY_REGION, &add);
	}

	/* Signal Lane 1 that this lane has completed its cycle count. */
	__atomic_add_fetch(&a->shared->lanes_done, 1, __ATOMIC_RELEASE);

	return NULL;
}

bool kvm_mmu_reclaim_race(struct childdata *child)
{
	struct object *vcpu_obj;
	int vcpufd, vmfd;
	void *ua = MAP_FAILED;
	struct reclaim_shared shared = { .stop = 0, .lanes_done = 0 };
	struct squeeze_args sargs;
	struct churn_args cargs;
	pthread_t squeeze_tid, churn_tid;
	bool squeeze_spawned = false, churn_spawned = false;
	unsigned long direct_calls = 0;

	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int)op >= 0 && op < NR_CHILD_OP_TYPES);

	if (objects_pool_empty(OBJ_LOCAL, OBJ_FD_KVM_VCPU))
		return true;

	vcpu_obj = get_random_object(OBJ_FD_KVM_VCPU, OBJ_LOCAL);
	if (!objpool_check(vcpu_obj, OBJ_FD_KVM_VCPU))
		return true;

	vcpufd = vcpu_obj->kvmvcpuobj.fd;
	vmfd   = vcpu_obj->kvmvcpuobj.parent_vmfd;
	if (vcpufd < 0 || vmfd < 0)
		return true;

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	/*
	 * Map anonymous backing for the churn memslot.  KVM_SET_USER_MEMORY_REGION
	 * requires userspace_addr to be page-aligned and backed by real anonymous
	 * pages.  The mapping is private to this invocation: threads share the
	 * pointer but do not access the backing pages directly.
	 */
	ua = mmap(NULL, RECLAIM_RACE_GPA_WINDOW,
		  PROT_READ | PROT_WRITE,
		  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ua == MAP_FAILED)
		goto out;

	/*
	 * Arm the churn memslot before launching threads so the fault storm
	 * has a valid GPA range to pre-fault during Lane 1's first pass.
	 * Without a memslot covering the range, kvm_mmu_do_page_fault() will
	 * bail before creating any shadow pages.
	 */
	{
		struct kvm_userspace_memory_region region = {
			.slot		 = RECLAIM_RACE_SLOT,
			.flags		 = 0,
			.guest_phys_addr = RECLAIM_RACE_GPA_BASE,
			.memory_size	 = RECLAIM_RACE_GPA_WINDOW,
			.userspace_addr	 = (__u64)(unsigned long)ua,
		};
		direct_calls++;
		(void)ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);
	}

	/* Launch Lane 2: squeeze thread. */
	sargs.vmfd	  = vmfd;
	sargs.direct_calls = 0;
	sargs.shared	  = &shared;
	if (pthread_create(&squeeze_tid, NULL, squeeze_loop_thread, &sargs) == 0)
		squeeze_spawned = true;

	/* Launch Lane 3: churn thread. */
	cargs.vmfd	  = vmfd;
	cargs.ua	  = ua;
	cargs.direct_calls = 0;
	cargs.shared	  = &shared;
	if (pthread_create(&churn_tid, NULL, churn_loop_thread, &cargs) == 0)
		churn_spawned = true;

	/*
	 * Lane 1: KVM_PRE_FAULT_MEMORY storm across the GPA window.
	 *
	 * Walks chunks of RECLAIM_RACE_CHUNK_SIZE across the window in a
	 * wrapping pattern, continuously cycling through all chunks for the
	 * entire duration that Lanes 2 and 3 are alive.  The loop exits only
	 * after both worker threads have signalled completion via
	 * shared.lanes_done, guaranteeing that faulting overlaps with the
	 * full squeeze and churn sequences regardless of host speed.
	 *
	 * With kvm.tdp_mmu=0 (boot flag) this drives direct_page_fault() →
	 * make_mmu_pages_available(), where the reclaim race window lives.
	 *
	 * KVM_PRE_FAULT_MEMORY is a vCPU ioctl; we issue it on vcpufd.
	 * It early-returns without side-effects if the kernel was built
	 * without KVM_PRE_FAULT_MEMORY support (old headers: the ioctl
	 * simply does not exist) or if the vCPU's page_fault handler is
	 * not kvm_tdp_page_fault (e.g. with TDP enabled and tdp_mmu=1).
	 */
#ifdef KVM_PRE_FAULT_MEMORY
	{
		unsigned int chunk_idx = 0;

		while (__atomic_load_n(&shared.lanes_done, __ATOMIC_ACQUIRE) < 2) {
			struct kvm_pre_fault_memory req = {
				.gpa   = RECLAIM_RACE_GPA_BASE +
					 ((__u64)(chunk_idx % RECLAIM_RACE_N_CHUNKS) *
					  RECLAIM_RACE_CHUNK_SIZE),
				.size  = RECLAIM_RACE_CHUNK_SIZE,
				.flags = 0,
			};
			direct_calls++;
			(void)ioctl(vcpufd, KVM_PRE_FAULT_MEMORY, &req);
			chunk_idx++;
		}
		/* Both worker lanes are done; signal early-exit to any
		 * iteration still in its loop guard. */
		__atomic_store_n(&shared.stop, 1, __ATOMIC_RELEASE);
	}
#else
	(void)vcpufd;
#endif

	/* Join Lane 2; merge its direct-call count. */
	if (squeeze_spawned) {
		(void)pthread_join(squeeze_tid, NULL);
		direct_calls += sargs.direct_calls;
	}

	/* Join Lane 3; merge its direct-call count. */
	if (churn_spawned) {
		(void)pthread_join(churn_tid, NULL);
		direct_calls += cargs.direct_calls;
	}

	/* Tear down the churn memslot so we leave the VM in a clean
	 * state for the next invocation (or the vCPU teardown in fds/kvm.c). */
	{
		struct kvm_userspace_memory_region del = {
			.slot		 = RECLAIM_RACE_SLOT,
			.flags		 = 0,
			.guest_phys_addr = RECLAIM_RACE_GPA_BASE,
			.memory_size	 = 0,
			.userspace_addr	 = 0,
		};
		direct_calls++;
		(void)ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &del);
	}

out:
	if (ua != MAP_FAILED)
		munmap(ua, RECLAIM_RACE_GPA_WINDOW);

	if (valid_op)
		childop_direct_syscalls_add(op, direct_calls);

	return true;
}

#else /* !USE_KVM */

#include <stdbool.h>
#include "child.h"

bool kvm_mmu_reclaim_race(struct childdata *child __attribute__((unused)))
{
	return true;
}

#endif /* USE_KVM */
