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
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
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
 * Process-local map.  384 KB in BSS in the parent; children inherit
 * via COW post-fork and only ever read it (calibration runs strictly
 * before the fuzz loop forks workers).
 */
static unsigned char effector_map[MAX_NR_SYSCALL]
	[EFFECTOR_NR_ARGS][EFFECTOR_BITS_PER_ARG];

unsigned char effector_map_score(unsigned int nr, unsigned int arg,
		unsigned int bit)
{
	if (nr >= MAX_NR_SYSCALL ||
	    arg >= EFFECTOR_NR_ARGS ||
	    bit >= EFFECTOR_BITS_PER_ARG)
		return 0;
	return effector_map[nr][arg][bit];
}

unsigned int effector_pick_bit(unsigned int nr, unsigned int arg)
{
	unsigned int weights[EFFECTOR_BITS_PER_ARG];
	unsigned int total = 0;
	unsigned int b, accum, r;

	if (nr >= MAX_NR_SYSCALL || arg >= EFFECTOR_NR_ARGS)
		return (unsigned int)(rand() %
				(int)EFFECTOR_BITS_PER_ARG);

	/* Floor each weight at 1 so a row that has never been calibrated
	 * (all zeros) degrades to a uniform pick — same expected behaviour
	 * as the pre-effector-map random bit-flip — and so a calibrated
	 * row still gives every bit non-zero pick probability.  Calibration
	 * is intentionally noisy (single baseline per syscall, accumulated
	 * side effects across probes); a row may have measured 0 for a bit
	 * that is in fact significant under a different baseline.  Without
	 * the floor, those bits would never be retried. */
	for (b = 0; b < EFFECTOR_BITS_PER_ARG; b++) {
		weights[b] = (unsigned int)effector_map[nr][arg][b] + 1U;
		total += weights[b];
	}

	r = (unsigned int)(rand() % (int)total);
	accum = 0;
	for (b = 0; b < EFFECTOR_BITS_PER_ARG; b++) {
		accum += weights[b];
		if (r < accum)
			return b;
	}
	return EFFECTOR_BITS_PER_ARG - 1;
}

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

	{
		const char *path = effector_map_default_path();

		if (path == NULL) {
			outputerr("effector-map: no persistence path available; map discarded\n");
		} else if (!effector_map_save_file(path)) {
			outputerr("effector-map: save to %s failed (errno=%d); map discarded\n",
				path, errno);
		} else {
			output(0, "effector-map: persisted to %s\n", path);
		}
	}

	return 0;
}

/*
 * On-disk persistence.
 *
 * File layout (little-endian, packed as written; record sizes are
 * fixed by struct definitions below):
 *
 *   offset  size  field
 *   ------  ----  ----------------------------------------------------
 *        0    4   magic   = 0x5452454D ('T','R','E','M' as bytes 54 52
 *                           45 4D in the file).  Anchor for sniffing
 *                           and a guard against accidentally loading
 *                           the corpus or any other trinity blob.
 *        4    4   version = EFFECTOR_FILE_VERSION (currently 1).  Bump
 *                           on any layout change; loader rejects
 *                           non-equal values.
 *        8    4   max_nr_syscall = MAX_NR_SYSCALL at write time.  The
 *                           on-disk byte map is dimensioned by this
 *                           value; a loader compiled with a different
 *                           MAX_NR_SYSCALL refuses the file.
 *       12    4   nr_args = EFFECTOR_NR_ARGS at write time.  Same
 *                           dimension-mismatch reject as above.
 *       16    4   bits_per_arg = EFFECTOR_BITS_PER_ARG at write time.
 *                           On 32-bit hosts this is 32; on 64-bit
 *                           hosts it is 64.  Cross-bitness map files
 *                           cannot be reused — the loader refuses.
 *       20    4   payload_crc32 = CRC32 (IEEE 802.3 polynomial,
 *                           reflected) over the byte map payload that
 *                           follows.  Header-internal fields are not
 *                           covered — the magic/version/dim checks
 *                           catch tampered headers earlier and
 *                           cheaper.
 *       24    4   reserved = 0.  Round the header to 32-byte alignment
 *                           and reserve room for a future field
 *                           without bumping the version.
 *       28   65   kernel_release = utsname.release captured at write
 *                           time, NUL-terminated, fixed-width.  The
 *                           loader compares strncmp(); a mismatch
 *                           against the running kernel rejects the
 *                           file (the calibration is only meaningful
 *                           against the kernel it was measured on).
 *       93   65   kernel_version = utsname.version captured at write
 *                           time, NUL-terminated, fixed-width.  Same
 *                           reject semantics as kernel_release; the
 *                           pair together identifies one compiled
 *                           kernel image (release alone is too
 *                           coarse — same .release with different
 *                           build timestamps will not in general
 *                           agree on edge layout).
 *      158    2   pad to round struct effector_file_header to a
 *                           multiple of 8 bytes.
 *
 *      160 onwards  payload = MAX_NR_SYSCALL * EFFECTOR_NR_ARGS *
 *                  EFFECTOR_BITS_PER_ARG bytes of significance scores,
 *                  laid out in C row-major order matching the in-memory
 *                  effector_map[nr][arg][bit] indexing.  No per-record
 *                  framing; reads are bulk into the in-memory array.
 *                  payload_crc32 is computed over exactly these bytes.
 *
 * Atomicity: the save path writes to "<path>.tmp.<pid>", fsyncs, then
 * renames into place.  The per-pid suffix prevents two concurrent
 * --effector-map runs from interleaving writes into the same .tmp; the
 * atomic rename gives readers all-or-nothing semantics.  The file
 * format is intentionally architecture-specific; callers build paths
 * under a per-arch subdirectory.
 */

#define EFFECTOR_FILE_MAGIC	0x5452454DU	/* "TREM" */
#define EFFECTOR_FILE_VERSION	1U
#define EFFECTOR_UTSNAME_LEN	65	/* matches Linux __NEW_UTS_LEN+1 */

/* Layout is naturally packed: 7 uint32_t fields followed by two
 * fixed-width char arrays and a 2-byte tail pad, summing to 160 bytes
 * with no compiler-inserted padding under the LP64 ABIs trinity
 * targets.  No __attribute__((packed)) needed — and adding one would
 * trip -Wpacked. */
struct effector_file_header {
	uint32_t magic;
	uint32_t version;
	uint32_t max_nr_syscall;
	uint32_t nr_args;
	uint32_t bits_per_arg;
	uint32_t payload_crc32;
	uint32_t reserved;
	char kernel_release[EFFECTOR_UTSNAME_LEN];
	char kernel_version[EFFECTOR_UTSNAME_LEN];
	uint8_t pad[2];
};

#define EFFECTOR_PAYLOAD_BYTES \
	((size_t)MAX_NR_SYSCALL * EFFECTOR_NR_ARGS * EFFECTOR_BITS_PER_ARG)

/* Plain CRC32 (IEEE 802.3 polynomial, reflected).  Same algorithm the
 * minicorpus persistence uses; kept local rather than refactored into
 * a shared helper so a future divergence (e.g. adding a checksum to
 * the corpus header) doesn't ripple over here. */
static uint32_t effector_crc32(const void *buf, size_t len)
{
	static uint32_t table[256];
	static bool table_built;
	const uint8_t *p = buf;
	uint32_t crc = 0xffffffffU;
	size_t i;

	if (!table_built) {
		uint32_t c;
		unsigned int n, k;

		for (n = 0; n < 256; n++) {
			c = n;
			for (k = 0; k < 8; k++)
				c = (c & 1) ? (0xedb88320U ^ (c >> 1)) : (c >> 1);
			table[n] = c;
		}
		table_built = true;
	}

	for (i = 0; i < len; i++)
		crc = table[(crc ^ p[i]) & 0xff] ^ (crc >> 8);

	return crc ^ 0xffffffffU;
}

static ssize_t write_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t left = len;

	while (left > 0) {
		ssize_t n = write(fd, p, left);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		p += n;
		left -= n;
	}
	return (ssize_t)len;
}

static ssize_t read_all(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;
	size_t left = len;

	while (left > 0) {
		ssize_t n = read(fd, p, left);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			break;
		p += n;
		left -= n;
	}
	return (ssize_t)(len - left);
}

bool effector_map_save_file(const char *path)
{
	struct effector_file_header hdr;
	struct utsname u;
	char tmppath[PATH_MAX];
	int fd;
	int ret;

	if (path == NULL)
		return false;

	if (uname(&u) != 0)
		return false;

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = EFFECTOR_FILE_MAGIC;
	hdr.version = EFFECTOR_FILE_VERSION;
	hdr.max_nr_syscall = MAX_NR_SYSCALL;
	hdr.nr_args = EFFECTOR_NR_ARGS;
	hdr.bits_per_arg = EFFECTOR_BITS_PER_ARG;
	hdr.payload_crc32 = effector_crc32(effector_map, EFFECTOR_PAYLOAD_BYTES);
	strncpy(hdr.kernel_release, u.release, sizeof(hdr.kernel_release) - 1);
	hdr.kernel_release[sizeof(hdr.kernel_release) - 1] = '\0';
	strncpy(hdr.kernel_version, u.version, sizeof(hdr.kernel_version) - 1);
	hdr.kernel_version[sizeof(hdr.kernel_version) - 1] = '\0';

	ret = snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d",
			path, (int)getpid());
	if (ret < 0 || (size_t)ret >= sizeof(tmppath))
		return false;

	fd = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return false;

	if (write_all(fd, &hdr, sizeof(hdr)) < 0)
		goto fail;
	if (write_all(fd, effector_map, EFFECTOR_PAYLOAD_BYTES) < 0)
		goto fail;

	if (fsync(fd) != 0)
		goto fail;
	if (close(fd) != 0) {
		(void)unlink(tmppath);
		return false;
	}

	if (rename(tmppath, path) != 0) {
		(void)unlink(tmppath);
		return false;
	}
	return true;

fail:
	(void)close(fd);
	(void)unlink(tmppath);
	return false;
}

bool effector_map_load_file(const char *path)
{
	struct effector_file_header hdr;
	struct utsname u;
	unsigned char tmpmap[MAX_NR_SYSCALL]
		[EFFECTOR_NR_ARGS][EFFECTOR_BITS_PER_ARG];
	uint32_t want_crc;
	int fd;

	if (path == NULL)
		return false;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return false;

	if (read_all(fd, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)) {
		(void)close(fd);
		return false;
	}

	if (hdr.magic != EFFECTOR_FILE_MAGIC ||
	    hdr.version != EFFECTOR_FILE_VERSION ||
	    hdr.max_nr_syscall != MAX_NR_SYSCALL ||
	    hdr.nr_args != EFFECTOR_NR_ARGS ||
	    hdr.bits_per_arg != EFFECTOR_BITS_PER_ARG) {
		(void)close(fd);
		return false;
	}

	if (uname(&u) != 0) {
		(void)close(fd);
		return false;
	}

	hdr.kernel_release[sizeof(hdr.kernel_release) - 1] = '\0';
	hdr.kernel_version[sizeof(hdr.kernel_version) - 1] = '\0';
	if (strncmp(hdr.kernel_release, u.release,
			sizeof(hdr.kernel_release)) != 0 ||
	    strncmp(hdr.kernel_version, u.version,
			sizeof(hdr.kernel_version)) != 0) {
		(void)close(fd);
		return false;
	}

	if (read_all(fd, tmpmap, EFFECTOR_PAYLOAD_BYTES)
			!= (ssize_t)EFFECTOR_PAYLOAD_BYTES) {
		(void)close(fd);
		return false;
	}
	(void)close(fd);

	want_crc = effector_crc32(tmpmap, EFFECTOR_PAYLOAD_BYTES);
	if (want_crc != hdr.payload_crc32)
		return false;

	memcpy(effector_map, tmpmap, EFFECTOR_PAYLOAD_BYTES);
	return true;
}

/*
 * Build a default per-arch effector-map path under
 * $XDG_CACHE_HOME/trinity/effector/ (or $HOME/.cache/...).  Parallel to
 * minicorpus_default_path's corpus/ directory; kept separate so the two
 * artifacts can be removed or copied independently.  Creates the parent
 * directory tree on demand.
 */
const char *effector_map_default_path(void)
{
	static char pathbuf[PATH_MAX];
	const char *xdg = getenv("XDG_CACHE_HOME");
	const char *home = getenv("HOME");
	char dir[PATH_MAX];
	const char *arch;
	int ret;

#if defined(__x86_64__)
	arch = "x86_64";
#elif defined(__i386__)
	arch = "i386";
#elif defined(__aarch64__)
	arch = "aarch64";
#elif defined(__arm__)
	arch = "arm";
#elif defined(__powerpc64__)
	arch = "ppc64";
#elif defined(__powerpc__)
	arch = "ppc";
#elif defined(__s390x__)
	arch = "s390x";
#elif defined(__mips__)
	arch = "mips";
#elif defined(__sparc__)
	arch = "sparc";
#elif defined(__riscv) || defined(__riscv__)
	arch = "riscv64";
#else
	arch = "unknown";
#endif

	if (xdg && xdg[0] == '/')
		ret = snprintf(dir, sizeof(dir), "%s/trinity/effector", xdg);
	else if (home && home[0] == '/')
		ret = snprintf(dir, sizeof(dir),
			"%s/.cache/trinity/effector", home);
	else
		return NULL;
	if (ret < 0 || (size_t)ret >= sizeof(dir))
		return NULL;

	{
		char *p;

		for (p = dir + 1; *p; p++) {
			if (*p == '/') {
				*p = '\0';
				if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
					*p = '/';
					return NULL;
				}
				*p = '/';
			}
		}
		if (mkdir(dir, 0755) != 0 && errno != EEXIST)
			return NULL;
	}

	ret = snprintf(pathbuf, sizeof(pathbuf), "%s/%s", dir, arch);
	if (ret < 0 || (size_t)ret >= sizeof(pathbuf))
		return NULL;
	return pathbuf;
}
