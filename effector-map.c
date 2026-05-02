/*
 * Per-bit input-significance calibration.
 *
 * Drives one paired KCOV probe per (syscall, arg slot, bit) tuple to
 * estimate how much each input bit influences kernel control flow.
 * Runs once at startup in --effector-map mode and exits; the populated
 * map is consumed by argument mutators at fuzz time.
 *
 * Per probe:
 *   1. Generate a fresh baseline argument vector via generic_sanitise().
 *      We deliberately bypass minicorpus_replay: a corpus snapshot would
 *      bias the baseline toward values that already produced novel
 *      coverage, which biases the per-bit divergence measurement.
 *   2. Capture the baseline KCOV trace as a hash-bucketed bit
 *      fingerprint.
 *   3. For each bit position in each arg slot, XOR the bit into the
 *      baseline arg vector, re-issue the syscall, capture a fingerprint,
 *      and store the popcount of fp_baseline XOR fp_probe (saturated to
 *      255) into the map.
 *
 * Calibration runs in the parent process inline, with no per-syscall
 * fork.  Side effects (uid changes, process state mutation, fd table
 * churn) accumulate across probes and may inflate scores for syscalls
 * whose effect on the parent leaks into a sibling syscall's baseline.
 * The same exclusion list the mini-corpus uses (sanitise-bearing,
 * pointer-bearing argtypes, EXTRA_FORK, AVOID_SYSCALL) keeps the
 * dangerous calls out of the loop; the residual blast surface is
 * documented and acceptable for a one-shot offline run.
 */

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "arch.h"
#include "effector-map.h"
#include "kcov.h"
#include "params.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

/*
 * Process-local map.  384 KB on the stack of bss; no shared-memory
 * exposure yet (persistence and runtime consumers are wired in later
 * commits in this stack).
 */
static unsigned char effector_map[MAX_NR_SYSCALL]
	[EFFECTOR_NR_ARGS][EFFECTOR_BITS_PER_ARG];

/*
 * Per-call edge fingerprint.  We hash each PC the kernel reported into
 * a 16K-bit table and compare two fingerprints by popcounting the XOR.
 * Hash collisions slightly under-count divergence; we use 16K bits to
 * keep the false-collision rate well below the syscall's typical
 * unique-edge count, but we deliberately stay smaller than the global
 * KCOV_NUM_EDGES table to keep per-probe XOR/popcount cheap (256
 * 64-bit popcounts per probe).
 *
 * Static (process-local) buffers — calibration is single-threaded.
 */
#define EFFECTOR_FP_BITS	16384
#define EFFECTOR_FP_BYTES	(EFFECTOR_FP_BITS / 8)
#define EFFECTOR_FP_MASK	(EFFECTOR_FP_BITS - 1)

static unsigned char fp_baseline[EFFECTOR_FP_BYTES];
static unsigned char fp_probe[EFFECTOR_FP_BYTES];

/*
 * Per-probe SIGALRM watchdog.  A syscall that blocks (or rt-prio /
 * D-state stalls) longer than this gets the probe cancelled and the
 * (arg, bit) significance left at 0.
 */
#define EFFECTOR_PROBE_TIMEOUT_SEC	1

static volatile sig_atomic_t probe_timed_out;

static void probe_alarm_handler(int sig)
{
	(void)sig;
	probe_timed_out = 1;
}

/*
 * Override setup_main_signals()'s SIG_IGN on SIGALRM so the watchdog
 * actually trips.  No SA_RESTART: a probe whose syscall blocks should
 * see EINTR and unwind, not transparently retry.
 */
static void install_probe_watchdog(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = probe_alarm_handler;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	(void)sigaction(SIGALRM, &sa, NULL);
}

/*
 * Same Murmur3 finalizer as kcov.c::pc_to_edge(), but truncated to
 * EFFECTOR_FP_BITS rather than KCOV_NUM_EDGES — the fingerprint is a
 * relative comparison, not a global coverage signal, so a smaller table
 * keeps each probe's XOR/popcount inside a couple of cachelines.
 */
static unsigned int pc_to_fp_idx(unsigned long pc)
{
	pc ^= pc >> 33;
	pc *= 0xff51afd7ed558ccdUL;
	pc ^= pc >> 33;
	pc *= 0xc4ceb9fe1a85ec53UL;
	pc ^= pc >> 33;
	return (unsigned int)(pc & EFFECTOR_FP_MASK);
}

static void fp_clear(unsigned char *fp)
{
	memset(fp, 0, EFFECTOR_FP_BYTES);
}

static void fp_capture(unsigned char *fp, struct kcov_child *kc)
{
	unsigned long count, idx;

	fp_clear(fp);
	if (!kc->active)
		return;

	count = __atomic_load_n(&kc->trace_buf[0], __ATOMIC_RELAXED);
	if (count > KCOV_TRACE_SIZE - 1)
		count = KCOV_TRACE_SIZE - 1;

	for (idx = 0; idx < count; idx++) {
		unsigned long pc = kc->trace_buf[idx + 1];
		unsigned int bit = pc_to_fp_idx(pc);

		fp[bit >> 3] |= (unsigned char)(1U << (bit & 7));
	}
}

/*
 * Popcount of fp_a XOR fp_b over EFFECTOR_FP_BYTES.  We round the
 * fingerprint size to a multiple of sizeof(unsigned long) at definition
 * time (16384 bits = 2048 bytes = 256 unsigned longs on 64-bit), so the
 * tail of the buffer is naturally aligned.
 */
static unsigned int fp_distance(const unsigned char *a, const unsigned char *b)
{
	unsigned int dist = 0;
	unsigned int i;

	for (i = 0; i < EFFECTOR_FP_BYTES; i += sizeof(unsigned long)) {
		unsigned long va, vb;

		memcpy(&va, a + i, sizeof(va));
		memcpy(&vb, b + i, sizeof(vb));
		dist += (unsigned int)__builtin_popcountl(va ^ vb);
	}
	return dist;
}

/*
 * Issue a single syscall probe under KCOV.  Returns 0 on success,
 * non-zero if the watchdog tripped (the fingerprint is still captured
 * but the caller should treat the result as untrustworthy).
 */
static int issue_probe(struct kcov_child *kc, unsigned int call,
		const unsigned long args[6], unsigned char *fp)
{
	int ret;

	probe_timed_out = 0;
	(void)alarm(EFFECTOR_PROBE_TIMEOUT_SEC);

	kcov_enable_trace(kc);
	(void)syscall(call, args[0], args[1], args[2], args[3], args[4], args[5]);
	kcov_disable(kc);

	(void)alarm(0);

	fp_capture(fp, kc);

	ret = probe_timed_out ? -1 : 0;
	probe_timed_out = 0;
	return ret;
}

/*
 * Calibratability gate.  Same exclusions the mini-corpus replay path
 * uses (heap-pointer argtypes, sanitise-bearing entries) plus a few
 * calibration-specific ones:
 *
 *   - EXTRA_FORK: those entries (execve, fork-family) replace the
 *     calling process's image; running them inline in calibration
 *     would tear the parent down mid-loop.
 *
 *   - num_args == 0: nothing to flip, no measurement to make.
 *
 *   - inactive (active_number == 0): the syscall was masked out by the
 *     architecture / group / -x setup; respect that.
 */
static bool calibratable(struct syscallentry *entry)
{
	unsigned int i;

	if (entry == NULL)
		return false;
	if (entry->active_number == 0)
		return false;
	if (entry->flags & (AVOID_SYSCALL | NI_SYSCALL | BORING | EXTRA_FORK))
		return false;
	if (entry->num_args == 0)
		return false;
	if (entry->sanitise != NULL)
		return false;

	for (i = 0; i < entry->num_args && i < EFFECTOR_NR_ARGS; i++) {
		switch (entry->argtype[i]) {
		case ARG_IOVEC:
		case ARG_PATHNAME:
		case ARG_SOCKADDR:
		case ARG_MMAP:
		case ARG_PID:
			return false;
		default:
			break;
		}
	}
	return true;
}

static void calibrate_one(unsigned int nr, struct kcov_child *kc)
{
	struct syscallrecord rec;
	struct syscallentry *entry;
	unsigned long base_args[6];
	unsigned int arg, bit, call;

	entry = get_syscall_entry(nr, false);
	if (!calibratable(entry))
		return;

	memset(&rec, 0, sizeof(rec));
	rec.nr = nr;
	rec.do32bit = false;
	rec.state = UNKNOWN;

	/* Bypass minicorpus_replay deliberately — see file-header comment.
	 * generic_sanitise zeroes the slots and refills via fill_arg(),
	 * giving us a fresh baseline that exercises the unprimed allocator
	 * paths the same way the regular fuzz loop's first call to a
	 * never-replayed syscall would. */
	generic_sanitise(&rec);

	base_args[0] = rec.a1;
	base_args[1] = rec.a2;
	base_args[2] = rec.a3;
	base_args[3] = rec.a4;
	base_args[4] = rec.a5;
	base_args[5] = rec.a6;

	call = (unsigned int)((int)nr + SYSCALL_OFFSET);

	if (issue_probe(kc, call, base_args, fp_baseline) != 0) {
		output(0, "effector-map: %s baseline timed out, skipping\n",
			entry->name);
		return;
	}

	for (arg = 0; arg < entry->num_args && arg < EFFECTOR_NR_ARGS; arg++) {
		unsigned long probe_args[6];

		for (bit = 0; bit < EFFECTOR_BITS_PER_ARG; bit++) {
			unsigned int dist;

			memcpy(probe_args, base_args, sizeof(probe_args));
			probe_args[arg] ^= (1UL << bit);

			if (issue_probe(kc, call, probe_args, fp_probe) != 0)
				continue;

			dist = fp_distance(fp_baseline, fp_probe);
			if (dist > 255)
				dist = 255;
			effector_map[nr][arg][bit] = (unsigned char)dist;
		}
	}
}

int effector_map_calibrate(void)
{
	struct kcov_child kc;
	unsigned int nr;
	unsigned int probed = 0;
	unsigned long total_significant = 0;
	unsigned int s, a, b;

	output(0, "effector-map: calibration starting (probing %u syscalls max)\n",
		max_nr_syscalls);

	install_probe_watchdog();

	/* child_id 0 — calibration is single-process; we are the only KCOV
	 * consumer in this run and won't collide with any other remote
	 * handle.  kcov_init_child does the open + INIT_TRACE + mmap and
	 * also probes for KCOV_REMOTE_ENABLE; we don't use remote mode
	 * here but the probe is harmless. */
	kcov_init_child(&kc, 0);
	if (!kc.active) {
		outputerr("effector-map: KCOV unavailable; calibration aborted\n");
		return -1;
	}

	for (nr = 0; nr < max_nr_syscalls && nr < MAX_NR_SYSCALL; nr++) {
		struct syscallentry *entry = get_syscall_entry(nr, false);

		if (!calibratable(entry))
			continue;

		calibrate_one(nr, &kc);
		probed++;

		if ((probed % 50) == 0)
			output(0, "effector-map: probed %u syscalls\n", probed);
	}

	kcov_cleanup_child(&kc);

	for (s = 0; s < MAX_NR_SYSCALL; s++) {
		for (a = 0; a < EFFECTOR_NR_ARGS; a++) {
			for (b = 0; b < EFFECTOR_BITS_PER_ARG; b++) {
				if (effector_map[s][a][b] != 0)
					total_significant++;
			}
		}
	}

	output(0, "effector-map: calibration complete (%u syscalls probed, "
		"%lu (syscall,arg,bit) tuples non-zero)\n",
		probed, total_significant);

	return 0;
}
