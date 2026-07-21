/*
 * kvm_run_churn -- drive vCPUs through KVM_RUN with kvm_run-region
 * scribbling.
 *
 * KVM_RUN is the only ioctl that transfers control to the guest, so it
 * is the entry point for every VM-exit handler in the kernel
 * (kvm_emulate_io, kvm_handle_mmio, kvm_emulate_hypercall, the x86
 * instruction emulator, the LAPIC TPR/CR8 sync, the sync_regs valid/
 * dirty masks).  Phases 1-3 left vCPU objects with fully populated
 * kvm_run mmap regions but never invoked KVM_RUN itself, so all of
 * those handlers were unreachable via the fuzzer.  This op fills the
 * gap.
 *
 * Per outer iteration (1-3 inner KVM_RUN calls):
 *   1. Pick a random OBJ_LOCAL OBJ_FD_KVM_VCPU.  Empty pool means
 *      /dev/kvm is unavailable to this child (probe failed at fork
 *      time or the per-child KVM_CREATE_VM landed EINVAL) -- silently
 *      skip.
 *   2. Scribble the kvm_run fields the UAPI documents as userspace
 *      input: request_interrupt_window, immediate_exit, cr8, apic_base,
 *      and (when KVM_CAP_SYNC_REGS is supported) kvm_valid_regs +
 *      kvm_dirty_regs masked to the cap-reported supported bits.
 *   3. ioctl(vcpu_fd, KVM_RUN, 0).  child.c's alarm(1) bounds wall-clock
 *      time so a runaway guest that fails to take an exit can't wedge the
 *      child past the parent's per-op contract.
 *   4. Tally exit_reason; for KVM_EXIT_IO scribble the data area at
 *      kvm_run + io.data_offset, and for KVM_EXIT_MMIO scribble the
 *      inline mmio.data[8] -- the kernel re-reads both on the next
 *      KVM_RUN entry, so this exposes the IO/MMIO completion paths to
 *      fuzzed bytes that the guest itself would never have produced.
 *
 * KVM_CAP_SYNC_REGS is probed lazily on first invocation against any
 * live OBJ_LOCAL OBJ_FD_KVM_SYSTEM fd; result is cached for the rest of
 * the child's lifetime.  Probe failure or absent system fd leaves
 * sync_regs_caps at 0, which makes step 2 leave the sync-regs fields
 * untouched.
 */

#ifdef USE_KVM

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/kvm.h>

#include "child.h"
#include "object-types.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#define KVM_RUN_CHURN_INNER_MAX		3
#define KVM_RUN_CHURN_MEMSLOT_BURN	8

/*
 * Cap the number of KVM_RUN errno lines emitted per fuzzer session.
 * A stuck-at -EIO cascade (e.g. a broken per-child KVM lifecycle where
 * every child inherits an unreachable parent-context VM) would otherwise
 * flood the log; a small ceiling keeps the diagnostic useful without
 * turning it into log spam.  Under shm->debug only -- production runs
 * keep the compact kvm_run_errors counter unchanged.
 */
#define KVM_RUN_ERRNO_LOG_CAP		8

/* Cached KVM_CAP_SYNC_REGS bitmask.  0 == cap absent or not yet probed
 * (sync-regs scribble suppressed in either case). */
static uint64_t sync_regs_caps;
static bool sync_regs_probed;

/*
 * Rolling counter of KVM_RUN errno diagnostics already emitted.  Guarded
 * by shm->debug and capped at KVM_RUN_ERRNO_LOG_CAP so a stuck failure
 * mode surfaces the first N errnos in the log (enough to bucket EIO vs
 * ENOMEM vs EBADF vs the -EINTR/-ERESTARTSYS families) and then falls
 * silent, leaving the compact kvm_run_errors counter as the ongoing signal.
 */
static unsigned int kvm_run_errno_logged;

/* Memslot-race sub-mode state.  user_memory2_supported is the cached
 * KVM_CAP_USER_MEMORY2 result: false skips the v2 ioctl variant in the
 * writer rotation.  memslot_race_unsupported latches the whole sub-mode
 * off for the rest of the child's lifetime once the kernel has told us
 * the underlying interface is not available -- either v2 is missing
 * outright, or KVM_SET_USER_MEMORY_REGION came back with ENODEV /
 * EOPNOTSUPP from a writer iteration. */
static bool memslot_race_user_memory2_probed;
static bool memslot_race_user_memory2_supported;
static bool memslot_race_unsupported;

static void probe_sync_regs_caps(void)
{
	struct objhead *head;
	struct object *obj;
	unsigned int idx;
	int rc;

	if (sync_regs_probed)
		return;
	sync_regs_probed = true;

	head = get_objhead(OBJ_LOCAL, OBJ_FD_KVM_SYSTEM);
	if (head == NULL || head->array == NULL)
		return;

	for_each_obj(head, obj, idx) {
		if (obj->kvmsysobj.fd < 0)
			continue;
		rc = ioctl(obj->kvmsysobj.fd, KVM_CHECK_EXTENSION,
			   (unsigned long)KVM_CAP_SYNC_REGS);
		if (rc > 0)
			sync_regs_caps = (uint64_t)rc;
		return;
	}
}

static void scribble_pre_run(struct kvm_run *kr)
{
	kr->request_interrupt_window = (__u8)(rnd_u32() & 1);

	/* immediate_exit forces an instant return from KVM_RUN.  Bias
	 * toward setting it 3-of-4 invocations so we exercise the early-
	 * exit accounting path frequently while still occasionally
	 * letting the guest actually run -- the latter is what produces
	 * KVM_EXIT_IO / KVM_EXIT_MMIO entries from the synthetic guest
	 * state KVM_CREATE_VM leaves us with. */
	kr->immediate_exit = (__u8)(ONE_IN(4) ? 0 : 1);

	kr->cr8 = (__u64)(rnd_u32() & 0xff);

	if (RAND_BOOL()) {
		/* x86 LAPIC base lives at 0xFEE00000.  Walk +/- 0x1000
		 * around it half the time so the kernel sees a
		 * lapic-shaped value before exiting. */
		kr->apic_base = 0xFEE00000ULL +
				(uint64_t)(rnd_u32() & 0x1fff) - 0x1000ULL;
	} else {
		kr->apic_base = (uint64_t)rand64();
	}

	if (sync_regs_caps != 0) {
		kr->kvm_valid_regs = (__u64)rand64() & sync_regs_caps;
		kr->kvm_dirty_regs = (__u64)rand64() & sync_regs_caps;
	}
}

static void tally_exit(struct kvm_run *kr, size_t kvm_run_size)
{
	switch (kr->exit_reason) {
	case KVM_EXIT_IO: {
		uint64_t off = kr->io.data_offset;
		uint64_t len = (uint64_t)kr->io.size *
			       (uint64_t)kr->io.count;

		__atomic_add_fetch(&shm->stats.kvm.exit_io, 1,
				   __ATOMIC_RELAXED);
		if (off == 0 || off >= kvm_run_size || len == 0 ||
		    len > 4096)
			return;
		if (off + len > kvm_run_size)
			len = kvm_run_size - off;
		generate_rand_bytes((unsigned char *)kr + off,
				    (unsigned int)len);
		return;
	}
	case KVM_EXIT_MMIO:
		__atomic_add_fetch(&shm->stats.kvm.exit_mmio, 1,
				   __ATOMIC_RELAXED);
		generate_rand_bytes(kr->mmio.data, sizeof(kr->mmio.data));
		return;
	case KVM_EXIT_HLT:
		__atomic_add_fetch(&shm->stats.kvm.exit_hlt, 1,
				   __ATOMIC_RELAXED);
		return;
	case KVM_EXIT_SHUTDOWN:
		__atomic_add_fetch(&shm->stats.kvm.exit_shutdown, 1,
				   __ATOMIC_RELAXED);
		return;
	case KVM_EXIT_FAIL_ENTRY:
		__atomic_add_fetch(&shm->stats.kvm.exit_fail_entry, 1,
				   __ATOMIC_RELAXED);
		return;
	case KVM_EXIT_INTERNAL_ERROR:
		__atomic_add_fetch(&shm->stats.kvm.exit_internal_error,
				   1, __ATOMIC_RELAXED);
		return;
	case KVM_EXIT_INTR:
		__atomic_add_fetch(&shm->stats.kvm.exit_intr, 1,
				   __ATOMIC_RELAXED);
		return;
	default:
		__atomic_add_fetch(&shm->stats.kvm.exit_other, 1,
				   __ATOMIC_RELAXED);
		return;
	}
}

static void run_one(int vcpufd, struct kvm_run *kr, size_t kvm_run_size)
{
	int rc;

	__atomic_add_fetch(&shm->stats.kvm.invocations, 1,
			   __ATOMIC_RELAXED);

	scribble_pre_run(kr);

	rc = ioctl(vcpufd, KVM_RUN, 0UL);

	if (rc < 0) {
		int saved_errno = errno;

		__atomic_add_fetch(&shm->stats.kvm.errors, 1,
				   __ATOMIC_RELAXED);
		/*
		 * Under -D, emit the first KVM_RUN_ERRNO_LOG_CAP failing
		 * errnos so a stuck-at failure mode (e.g. mm-ownership
		 * mismatch surfacing as EIO on every child) is visible in
		 * the log rather than hiding under the compact
		 * kvm_run_errors counter.  Fetch-and-add is racy across
		 * children but that's fine -- the cap is an approximate
		 * budget, not a hard guarantee, and losing a duplicate
		 * emission to another child is preferable to a lock.
		 */
		if (shm->debug &&
		    __atomic_fetch_add(&kvm_run_errno_logged, 1,
				       __ATOMIC_RELAXED) < KVM_RUN_ERRNO_LOG_CAP)
			/* check-static: child-output-ok */
			outputerr("kvm_run_churn: KVM_RUN(vcpufd=%d) failed: %s (errno=%d)\n",
				  vcpufd, strerror(saved_errno), saved_errno);
		return;
	}

	tally_exit(kr, kvm_run_size);
}

static void probe_user_memory2_cap(void)
{
	struct objhead *head;
	struct object *obj;
	unsigned int idx;
	int rc;

	if (memslot_race_user_memory2_probed)
		return;

	head = get_objhead(OBJ_LOCAL, OBJ_FD_KVM_SYSTEM);
	if (head == NULL || head->array == NULL)
		return;

	for_each_obj(head, obj, idx) {
		if (obj->kvmsysobj.fd < 0)
			continue;
		rc = ioctl(obj->kvmsysobj.fd, KVM_CHECK_EXTENSION,
			   (unsigned long)KVM_CAP_USER_MEMORY2);
		memslot_race_user_memory2_supported = (rc > 0);
		memslot_race_user_memory2_probed = true;
		if (rc == 0) {
			memslot_race_unsupported = true;
			__atomic_add_fetch(
				&shm->stats.kvm.gpc_memslot_race_unsupported,
				1, __ATOMIC_RELAXED);
		}
		return;
	}
}

struct memslot_race_args {
	int vmfd;
	uint32_t slot;
	bool use_v2;
};

static void *memslot_race_writer(void *p)
{
	struct memslot_race_args *a = p;
	int i;

	/* Sleep briefly so the main thread is inside KVM_RUN before the
	 * first delete lands.  The kernel race window is the gpc cache
	 * walk vs memslot tree mutation; without overlap this op is just
	 * a no-op delete. */
	usleep(500);

	for (i = 0; i < KVM_RUN_CHURN_MEMSLOT_BURN; i++) {
		int rc;

		if (a->use_v2 && (i & 1)) {
			struct kvm_userspace_memory_region2 r = {
				.slot = a->slot,
			};
			rc = ioctl(a->vmfd, KVM_SET_USER_MEMORY_REGION2, &r);
		} else {
			struct kvm_userspace_memory_region r = {
				.slot = a->slot,
			};
			rc = ioctl(a->vmfd, KVM_SET_USER_MEMORY_REGION, &r);
		}
		__atomic_add_fetch(&shm->stats.kvm.gpc_memslot_race_deletes,
				   1, __ATOMIC_RELAXED);
		if (rc < 0 && (errno == ENODEV || errno == EOPNOTSUPP)) {
			__atomic_store_n(&memslot_race_unsupported, true,
					 __ATOMIC_RELAXED);
			__atomic_add_fetch(
				&shm->stats.kvm.gpc_memslot_race_unsupported,
				1, __ATOMIC_RELAXED);
			break;
		}
	}
	return NULL;
}

static void run_memslot_race(int vmfd, int vcpufd,
			     struct kvm_run *kr, size_t kvm_run_size)
{
	struct memslot_race_args args;
	pthread_t tid;
	bool spawned = false;

	probe_user_memory2_cap();
	if (memslot_race_unsupported || vmfd < 0)
		return;

	args.vmfd = vmfd;
	args.slot = (uint32_t)(rnd_u32() & 0x7);
	args.use_v2 = memslot_race_user_memory2_supported;

	__atomic_add_fetch(&shm->stats.kvm.gpc_memslot_race_runs, 1,
			   __ATOMIC_RELAXED);

	if (pthread_create(&tid, NULL, memslot_race_writer, &args) == 0)
		spawned = true;

	run_one(vcpufd, kr, kvm_run_size);

	if (spawned)
		(void)pthread_join(tid, NULL);
}

bool kvm_run_churn(struct childdata *child)
{
	struct object *obj;
	int vcpufd, iters, i;
	struct kvm_run *kr;
	size_t kvm_run_size;

	probe_sync_regs_caps();

	if (objects_pool_empty(OBJ_LOCAL, OBJ_FD_KVM_VCPU))
		return true;

	obj = get_random_object(OBJ_FD_KVM_VCPU, OBJ_LOCAL);
	if (!objpool_check(obj, OBJ_FD_KVM_VCPU))
		return true;

	vcpufd = obj->kvmvcpuobj.fd;
	kr = (struct kvm_run *)obj->kvmvcpuobj.kvm_run;
	kvm_run_size = obj->kvmvcpuobj.kvm_run_size;
	if (vcpufd < 0 || kr == NULL || kvm_run_size < sizeof(*kr))
		return true;

	/*
	 * Per-child mmap: obj lives in the child's OBJ_LOCAL pool (child-
	 * private heap) and every KVM object (including the kvm_run mmap)
	 * is created inside this child's mm by fds/kvm.c's per-child init
	 * hook.  The shared_regions[] tracker sees the child-side
	 * track_shared_region() call, so range_in_tracked_shared() catches
	 * the fresh mapping without help.  Keep the guard as a defensive
	 * belt against any future path that publishes a vcpuobj without
	 * routing kvm_run through track_shared_region().
	 */
	if (!range_in_tracked_shared((unsigned long)kr, kvm_run_size))
		return true;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	if (ONE_IN(8)) {
		run_memslot_race(obj->kvmvcpuobj.parent_vmfd, vcpufd, kr,
				 kvm_run_size);
		return true;
	}

	iters = 1 + rnd_modulo_u32(KVM_RUN_CHURN_INNER_MAX);
	for (i = 0; i < iters; i++)
		run_one(vcpufd, kr, kvm_run_size);

	return true;
}

#else /* !USE_KVM */

#include <stdbool.h>
#include "child.h"

bool kvm_run_churn(struct childdata *child __attribute__((unused)))
{
	return true;
}

#endif /* USE_KVM */
