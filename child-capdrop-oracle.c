/*
 * Periodic-work cap-drop oracle.
 *
 * Asserts the capset()-to-empty drop in init_child_setup_sandbox()
 * actually held.  Sampled once per ONE_IN(CAPDROP_ORACLE_SAMPLE_DENOM)
 * call to periodic_work().  Each probe is designed to FAIL on a
 * cap-dropped child:
 *
 *   - bpf(BPF_PROG_LOAD, BPF_PROG_TYPE_KPROBE, ...) -> expect EPERM.
 *     A verifier-clean two-instruction program ("r0=0; exit") so the
 *     only thing that can reject the load is the cap gate, not the
 *     verifier.  KPROBE rather than SOCKET_FILTER because the latter
 *     is allowed on systems with kernel.unprivileged_bpf_disabled=0,
 *     which would mask the test.
 *
 *   - mount() with a bogus fstype -> expect EPERM.  may_mount()'s cap
 *     check in path_mount() fires before the fstype lookup, so a
 *     cap-dropped child sees EPERM; if the cap drop ever regresses the
 *     bogus fstype guarantees the call fails ENODEV instead of actually
 *     mounting anything.
 *
 *   - setsockopt(SO_RCVBUFFORCE) on an AF_INET DGRAM socket ->
 *     expect EPERM.  CAP_NET_ADMIN-gated at the top of sock_setsockopt
 *     before the rmem_max bypass.
 *
 *   - capget(self) -> assert effective+permitted+inheritable are EMPTY
 *     on both v3 data slots.  Direct read-back of the drop.
 *
 * Bare syscall(__NR_*) on the bpf / mount / capget probes so the
 * --exclude=<syscall> CLI knob can't silently skip the oracle.
 *
 * SAFETY: every probe expects failure.  On the (alarming) success
 * branch the oracle bumps shm->stats.capdrop_oracle_anomalies, emits
 * an output(0, ...) anomaly line, and does NOT retry the privileged
 * action.  The bpf success branch closes the unexpectedly-loaded
 * prog fd.  Real-kernel-run validation owed: confirm the oracle stays
 * silent under the cap-dropped child and fires if the drop is
 * reverted.
 */

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/capability.h>
#include <netinet/in.h>

#include "config.h"
#ifdef USE_BPF
#include <linux/bpf.h>
#include "bpf.h"
#endif

#include "child.h"
#include "random.h"
#include "shm.h"
#include "stats.h"
#include "trinity.h"
#include "utils.h"

#define CAPDROP_ORACLE_SAMPLE_DENOM	1024

static void capdrop_bump_anomaly(void)
{
	__atomic_add_fetch(&shm->stats.capdrop_oracle_anomalies, 1,
			   __ATOMIC_RELAXED);
}

#ifdef USE_BPF
static const char capdrop_bpf_license[] = "GPL";

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
	 * sock_setsockopt() rejects it at the top of the case branch when
	 * the caller lacks CAP_NET_ADMIN in the net namespace.
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
 */
void capdrop_oracle_tick(void)
{
	if (!ONE_IN(CAPDROP_ORACLE_SAMPLE_DENOM))
		return;

	capdrop_probe_capget_self();
	capdrop_probe_bpf();
	capdrop_probe_mount();
	capdrop_probe_net_admin();
}
