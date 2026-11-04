/*
 * Periodic-work cap-drop oracle: asserts the capset()-to-empty drop in
 * init_child_setup_sandbox() held, sampled 1 in CAPDROP_ORACLE_SAMPLE_DENOM
 * ticks.  Every probe is built to fail on a cap-dropped child and never
 * retries the privileged action.  The bpf, mount and capget probes use
 * bare syscall(__NR_*) so --exclude=<syscall> cannot skip the oracle.
 */

#include <errno.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/capability.h>
#include <string.h>
#include <sys/types.h>

#include "config.h"
#ifdef USE_BPF
#include <linux/bpf.h>
#include "bpf.h"
#endif

#include "child-internal.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#define CAPDROP_ORACLE_SAMPLE_DENOM	1024

/*
 * Per-child anchors capturing the (st_dev, st_ino) identity of the
 * /proc/self/ns/{user,mnt} symlinks at child-sandbox-setup time --
 * i.e. immediately after init_child_setup_sandbox()'s capset()-to-empty
 * drop, after any per-child unshare() dance has already run.  Stamped by
 * capdrop_oracle_capture_init_ns_anchors() and consulted by the per-
 * probe gates below.
 *
 * Rationale: the capget and mount probes assert "no caps in this
 * task's userns / mntns".  A child that legitimately enters a
 * fresh userns (the userns-admin lane, or an alt-op that unshares in
 * place) makes those probes false-fire forever after, because the child
 * now has full caps in the bootstrapped userns.  Re-stat at tick-time and skip the gated probe
 * if the ns identity no longer matches the anchor: the oracle stays
 * silent on legitimate ns transitions but still fires on a real cap-
 * drop regression that leaves the child in its init ns.
 *
 * bpf(BPF_PROG_LOAD, KPROBE) and setsockopt(SO_RCVBUFFORCE) are NOT
 * gated: the verifier's KPROBE-load cap check and sock_setsockopt()'s
 * SO_RCVBUFFORCE check are both bound to the init user namespace
 * specifically (capable(), never ns_capable()), so a bootstrapped
 * userns cannot fool them.  Those probes remain the oracle's
 * load-bearing init-userns invariants and must keep firing on regression.
 */
struct capdrop_ns_anchor {
	bool valid;
	dev_t st_dev;
	ino_t st_ino;
};

static struct capdrop_ns_anchor anchor_user;
static struct capdrop_ns_anchor anchor_mnt;

static void capdrop_capture_anchor(struct capdrop_ns_anchor *a, const char *path)
{
	struct stat st;

	a->valid = false;
	if (stat(path, &st) != 0)
		return;
	a->st_dev = st.st_dev;
	a->st_ino = st.st_ino;
	a->valid = true;
}

void capdrop_oracle_capture_init_ns_anchors(void)
{
	capdrop_capture_anchor(&anchor_user, "/proc/self/ns/user");
	capdrop_capture_anchor(&anchor_mnt, "/proc/self/ns/mnt");
}

/*
 * Returns true iff the anchor was captured AND the current ns at `path`
 * matches it.  False on capture failure (anchor invalid), stat failure,
 * or identity mismatch.  Callers use this to skip a ns-scoped probe when
 * the child is no longer in the namespace it was sandboxed in -- the
 * conservative side: missing the probe on this tick beats emitting a
 * false-fire anomaly.  The bpf probe (the load-bearing init-userns
 * invariant) is not gated through this helper.
 */
static bool capdrop_still_in_init_ns(const struct capdrop_ns_anchor *a,
				     const char *path)
{
	struct stat st;

	if (!a->valid)
		return false;
	if (stat(path, &st) != 0)
		return false;
	return st.st_dev == a->st_dev && st.st_ino == a->st_ino;
}

static void capdrop_bump_anomaly(void)
{
	__atomic_add_fetch(&shm->stats.oracle.capdrop_oracle_anomalies, 1,
			   __ATOMIC_RELAXED);
}

#ifdef USE_BPF
static const char capdrop_bpf_license[] = "GPL";

/*
 * KPROBE rather than SOCKET_FILTER: bpf_prog_load() lets an unprivileged
 * caller load the latter when kernel.unprivileged_bpf_disabled is 0, which
 * would mask a regression.  The program is verifier-clean ("r0 = 0; exit"),
 * so only the cap gate can reject the load.
 */
static void capdrop_probe_bpf(void)
{
	struct bpf_insn insns[] = {
		EBPF_MOV64_IMM(BPF_REG_0, 0),
		EBPF_EXIT(),
	};
	union bpf_attr attr;
	long fd;
	int saved_errno;

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_KPROBE;
	attr.insn_cnt = (unsigned int) ARRAY_SIZE(insns);
	attr.insns = (uint64_t)(uintptr_t) insns;
	attr.license = (uint64_t)(uintptr_t) capdrop_bpf_license;

	fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	saved_errno = errno;

	if (fd >= 0) {
		output(0,
		       "capdrop oracle anomaly: bpf(BPF_PROG_LOAD,KPROBE) succeeded "
		       "(fd=%ld) -- cap-dropped child should not load kprobe progs\n",
		       fd);
		(void) close((int) fd);
		capdrop_bump_anomaly();
		return;
	}

	/* ENOSYS = no BPF in this kernel; not a cap-drop regression. */
	if (saved_errno == ENOSYS || saved_errno == EPERM ||
	    saved_errno == EACCES)
		return;

	output(0,
	       "capdrop oracle anomaly: bpf(BPF_PROG_LOAD,KPROBE) errno=%d (%s), "
	       "expected EPERM/EACCES from cap-dropped child\n",
	       saved_errno, strerror(saved_errno));
	capdrop_bump_anomaly();
}
#else
static void capdrop_probe_bpf(void) { }
#endif

static void capdrop_probe_mount(void)
{
	long ret;
	int saved_errno;

	/*
	 * may_mount() in path_mount() runs before the fstype lookup, so a
	 * cap-dropped child sees EPERM here.  The bogus fstype name is a
	 * belt-and-braces guard: if the drop ever regresses and may_mount()
	 * waves us through, the call still fails at fs_type lookup with
	 * ENODEV instead of actually mounting anything on "/".
	 */
	ret = syscall(__NR_mount, "none", "/",
		      "trinity_capdrop_oracle_bogus_fstype",
		      0UL, NULL);
	saved_errno = errno;

	if (ret == 0) {
		output(0,
		       "capdrop oracle anomaly: mount() succeeded -- "
		       "cap-dropped child should not hold CAP_SYS_ADMIN\n");
		capdrop_bump_anomaly();
		return;
	}

	if (saved_errno == EPERM || saved_errno == EACCES)
		return;

	output(0,
	       "capdrop oracle anomaly: mount() errno=%d (%s), expected "
	       "EPERM/EACCES from cap-dropped child (cap-check should fire "
	       "before fstype lookup)\n",
	       saved_errno, strerror(saved_errno));
	capdrop_bump_anomaly();
}

static void capdrop_probe_net_admin(void)
{
	int fd;
	int saved_errno;
	int sz = 1024;
	int ret;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return;	/* socket open failure is not the oracle's concern */

	/*
	 * SO_RCVBUFFORCE is the CAP_NET_ADMIN-gated sibling of SO_RCVBUF;
	 * sock_setsockopt() rejects it at the top of the case branch
	 * through sockopt_capable(), which is capable() -- the init
	 * user namespace -- never ns_capable() on the socket's netns.
	 * The child holds no capabilities in init_user_ns in any
	 * namespace it can reach, lane or not, so the probe must FAIL
	 * (EPERM/EACCES) everywhere; success is the anomaly, as with
	 * the bpf probe.  A lane child that held CAP_NET_ADMIN in
	 * init_user_ns would pass, and must be caught, not excused.
	 */
	ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &sz, sizeof(sz));
	saved_errno = errno;
	(void) close(fd);

	if (ret == 0) {
		output(0,
		       "capdrop oracle anomaly: setsockopt(SO_RCVBUFFORCE) "
		       "succeeded -- cap-dropped child should not hold "
		       "CAP_NET_ADMIN\n");
		capdrop_bump_anomaly();
		return;
	}

	if (saved_errno == EPERM || saved_errno == EACCES)
		return;

	output(0,
	       "capdrop oracle anomaly: setsockopt(SO_RCVBUFFORCE) errno=%d "
	       "(%s), expected EPERM/EACCES from cap-dropped child\n",
	       saved_errno, strerror(saved_errno));
	capdrop_bump_anomaly();
}

static void capdrop_probe_capget_self(void)
{
	struct __user_cap_header_struct hdr = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	struct __user_cap_data_struct data[2] = { { 0 }, { 0 } };
	long ret;

	ret = syscall(__NR_capget, &hdr, data);
	if (ret != 0)
		return;	/* a failed self-read isn't this oracle's anomaly */

	if (data[0].effective | data[0].permitted | data[0].inheritable |
	    data[1].effective | data[1].permitted | data[1].inheritable) {
		output(0,
		       "capdrop oracle anomaly: capget(self) returned non-empty "
		       "masks data[0]={eff=%x,perm=%x,inh=%x} "
		       "data[1]={eff=%x,perm=%x,inh=%x}\n",
		       data[0].effective, data[0].permitted,
		       data[0].inheritable,
		       data[1].effective, data[1].permitted,
		       data[1].inheritable);
		capdrop_bump_anomaly();
	}
}

/*
 * Sampled invariant entry point.  Called from periodic_work() with a
 * ONE_IN gate around it; this function pays the four probes only on
 * the sample tick.
 *
 * The bpf KPROBE-load and net_admin probes run UNCONDITIONALLY --
 * their cap checks are pinned to the init user namespace, so they
 * remain correct even after a legitimate alt-op enters a
 * bootstrapped userns, and are the load-bearing invariants of this
 * oracle.  The capget/mount probes are skipped when the child has
 * left its sandbox-time user / mount namespace respectively,
 * because each then legitimately succeeds in the new ns and would
 * false-fire.
 */
void capdrop_oracle_tick(void)
{
	if (!ONE_IN(CAPDROP_ORACLE_SAMPLE_DENOM))
		return;

	if (capdrop_still_in_init_ns(&anchor_user, "/proc/self/ns/user"))
		capdrop_probe_capget_self();
	capdrop_probe_bpf();
	if (capdrop_still_in_init_ns(&anchor_mnt, "/proc/self/ns/mnt"))
		capdrop_probe_mount();
	capdrop_probe_net_admin();
}
