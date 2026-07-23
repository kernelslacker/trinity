/*
 * Sequence-chain corpus on-disk persistence and mid-run snapshot cadence.
 *
 * Cross-run warm-start: chain_corpus_save_file serialises every
 * occupied slot of the ring under a versioned, arch- and kernel-
 * release-tagged header and atomically renames the result into place.
 * chain_corpus_load_file refuses incompatible headers outright and
 * re-runs the same replay-safety predicate the save side uses
 * (chain_is_replay_safe, imported via chain-internal.h) so a saved
 * chain whose syscall table has since tightened cannot slip back
 * into the ring through the load path.
 *
 * chain_corpus_default_path builds an XDG-anchored, arch- and kernel-
 * release-tagged path so a saved corpus is never accidentally reused
 * across incompatible kernels.  chain_corpus_enable_snapshots plus
 * chain_corpus_maybe_snapshot wire periodic mid-run saves so a crash
 * between warm-start and clean shutdown does not lose every chain
 * admitted during the run.  The chain corpus ring itself, the
 * executor, and the resource-typing classifier live in the sibling
 * chain-corpus.c, chain-exec.c and chain-restype.c files.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "fd.h"
#include "kcov.h"
#include "minicorpus.h"
#include "params.h"
#include "persist-util.h"
#include "random.h"
#include "rnd.h"
#include "sequence.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/socket.h"

#include "chain-internal.h"

/*
 * On-disk chain corpus format.
 *
 * A tiny fixed-size header followed by a stream of length-prefixed
 * chain entries.  Each entry carries the chain length, save-reason,
 * every step's (nr, do32bit, args, retval), and a CRC32 covering the
 * entry payload -- a corrupt entry is dropped without taking down the
 * whole file.
 *
 * Format is arch-tagged and kernel-release-tagged: chain corpora built
 * for a different arch or a different compiled kernel image are
 * refused at load time, since syscall numbers and kernel behaviour
 * both change under those variables and a mismatched replay would
 * feed the kernel argument tuples from a completely different
 * dispatch table.  Same policy the per-syscall minicorpus file uses,
 * with a distinct magic so a mis-pointed path can never load one
 * carrier's image into the other's parser.
 */
#define CHAIN_CORPUS_FILE_MAGIC		0x54524e43U /* "TRNC" */
#define CHAIN_CORPUS_FILE_VERSION	1U

/* Linux utsname fields are __NEW_UTS_LEN+1 = 65 bytes including NUL. */
#define CHAIN_CORPUS_UTSNAME_LEN	65

struct chain_corpus_file_header {
	uint32_t magic;
	uint32_t version;
	uint32_t kernel_major;
	uint32_t kernel_minor;
	uint32_t max_nr_syscall;
	uint32_t max_seq_len;
	uint32_t reserved0;
	uint32_t reserved1;
	/* Full utsname.release and utsname.version strings.  release
	 * encodes the patch sublevel and any local version suffix; version
	 * encodes the build timestamp + git hash for builds that include
	 * them.  Strict equality on both means "same compiled kernel image"
	 * -- the only safe granularity for chain replay, since e.g.
	 * 7.0 vs 7.0-rc1 can differ in syscall behaviour despite matching
	 * major.minor. */
	char kernel_release[CHAIN_CORPUS_UTSNAME_LEN];
	char kernel_version[CHAIN_CORPUS_UTSNAME_LEN];
};

struct chain_corpus_file_step {
	uint32_t nr;
	uint32_t do32bit;	/* 0 or 1 -- wider slot for header stability */
	uint64_t args[6];
	uint64_t retval;
};

struct chain_corpus_file_entry {
	uint32_t len;
	uint32_t save_reason;
	struct chain_corpus_file_step steps[MAX_SEQ_LEN];
	uint32_t crc;
	uint32_t pad;
};

static bool chain_parse_kernel_version(const char *release,
				       uint32_t *major, uint32_t *minor)
{
	unsigned long maj, min;
	char *end;

	errno = 0;
	maj = strtoul(release, &end, 10);
	if (end == release || *end != '.' || errno == ERANGE)
		return false;

	release = end + 1;
	errno = 0;
	min = strtoul(release, &end, 10);
	if (end == release || errno == ERANGE)
		return false;

	*major = (uint32_t)maj;
	*minor = (uint32_t)min;
	return true;
}

static bool chain_current_kernel_version(uint32_t *major, uint32_t *minor)
{
	struct utsname u;

	if (uname(&u) != 0)
		return false;
	return chain_parse_kernel_version(u.release, major, minor);
}

bool chain_corpus_save_file(const char *path)
{
	struct chain_corpus_ring *ring = chain_corpus_shm;
	struct chain_corpus_file_header hdr;
	struct chain_entry snapshot[CHAIN_CORPUS_RING_SIZE];
	char tmppath[PATH_MAX];
	unsigned int snap_count = 0;
	unsigned int oldest = 0;
	unsigned int i;
	int fd;
	int ret;

	if (ring == NULL || path == NULL)
		return false;

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = CHAIN_CORPUS_FILE_MAGIC;
	hdr.version = CHAIN_CORPUS_FILE_VERSION;
	hdr.max_nr_syscall = MAX_NR_SYSCALL;
	hdr.max_seq_len = MAX_SEQ_LEN;
	if (!chain_current_kernel_version(&hdr.kernel_major, &hdr.kernel_minor))
		return false;
	{
		struct utsname u;

		if (uname(&u) != 0)
			return false;
		strncpy(hdr.kernel_release, u.release,
			sizeof(hdr.kernel_release) - 1);
		hdr.kernel_release[sizeof(hdr.kernel_release) - 1] = '\0';
		strncpy(hdr.kernel_version, u.version,
			sizeof(hdr.kernel_version) - 1);
		hdr.kernel_version[sizeof(hdr.kernel_version) - 1] = '\0';
	}

	/*
	 * Snapshot the whole occupied slot range under ring->lock, then
	 * release before the disk write.  The chain corpus is a single
	 * global ring rather than a per-syscall bank, so the lock hold
	 * time is bounded by one memcpy of at most CHAIN_CORPUS_RING_SIZE
	 * chain_entry slots (~74 KiB total).  Callers on the writer path
	 * only stall for that copy window; the disk I/O runs unlocked.
	 */
	lock(&ring->lock);
	snap_count = ring->count;
	if (snap_count > CHAIN_CORPUS_RING_SIZE)
		snap_count = CHAIN_CORPUS_RING_SIZE;
	if (snap_count != 0) {
		oldest = (ring->head - snap_count) % CHAIN_CORPUS_RING_SIZE;
		for (i = 0; i < snap_count; i++) {
			unsigned int slot = (oldest + i) % CHAIN_CORPUS_RING_SIZE;

			snapshot[i] = ring->slots[slot];
		}
	}
	unlock(&ring->lock);

	/* Per-pid tmp suffix so racing savers (a periodic and a shutdown
	 * save landing in the same tick, or two independent operators)
	 * cannot open the same .tmp file with O_TRUNC and interleave
	 * writes into a corrupt blob.  Atomic rename still gives the final
	 * file all-or-nothing semantics. */
	ret = snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d",
		       path, (int)getpid());
	if (ret < 0 || (size_t)ret >= sizeof(tmppath))
		return false;

	fd = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return false;

	/* Neutralise any fuzzer-installed umask so the save mode is 0644. */
	if (fchmod(fd, 0644) != 0) {
		(void)close(fd);
		(void)unlink(tmppath);
		return false;
	}

	if (write_all(fd, &hdr, sizeof(hdr)) < 0)
		goto fail;

	for (i = 0; i < snap_count; i++) {
		struct chain_corpus_file_entry ent;
		const struct chain_entry *src = &snapshot[i];
		unsigned int step;
		unsigned int j;

		/* Drop obviously-corrupt slots (torn writes, wild-write
		 * scribbles) at save time so a later load never sees a
		 * length that would walk past the file-side steps[]. */
		if (src->len == 0 || src->len > MAX_SEQ_LEN)
			continue;

		memset(&ent, 0, sizeof(ent));
		ent.len = src->len;
		ent.save_reason = src->save_reason;
		for (step = 0; step < src->len; step++) {
			ent.steps[step].nr = src->steps[step].nr;
			ent.steps[step].do32bit = src->steps[step].do32bit ? 1U : 0U;
			for (j = 0; j < 6; j++)
				ent.steps[step].args[j] =
					(uint64_t)src->steps[step].args[j];
			ent.steps[step].retval =
				(uint64_t)src->steps[step].retval;
		}

		ent.crc = crc32(&ent,
			offsetof(struct chain_corpus_file_entry, crc));

		if (write_all(fd, &ent, sizeof(ent)) < 0)
			goto fail;
	}

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

/*
 * Re-validate a chain candidate against the CURRENT syscall table
 * before admitting it to the ring.  Rejects on:
 *   (a) any step nr >= MAX_NR_SYSCALL (out of range)
 *   (b) any step whose nr does not resolve to a live syscall entry
 *       in the active table (get_syscall_entry returns NULL --
 *       covers cross-config swap where the saved file was recorded
 *       against a different active-syscall set)
 *   (c) chain_is_replay_safe returns false (any step carries an
 *       argtype that is not safe to replay -- stale heap pointers,
 *       stale pids, sanitise-stashed pointers).
 *
 * This is the same predicate the save side uses in chain_corpus_save,
 * re-run here so a saved chain whose syscall table has since changed
 * (a syscall was deactivated, a sanitise callback was added, an
 * argtype was tightened to ARG_PID) cannot slip back into the ring
 * through the load path.
 */
static bool chain_load_entry_is_admissible(const struct chain_corpus_file_entry *ent)
{
	struct chain_step steps[MAX_SEQ_LEN];
	unsigned int i, j;

	if (ent->len == 0 || ent->len > MAX_SEQ_LEN)
		return false;
	if (ent->save_reason >= CHAIN_SAVE_NR_REASONS)
		return false;

	for (i = 0; i < ent->len; i++) {
		struct syscallentry *e;
		bool do32 = ent->steps[i].do32bit != 0;

		if (ent->steps[i].nr >= MAX_NR_SYSCALL)
			return false;
		e = get_syscall_entry(ent->steps[i].nr, do32);
		if (e == NULL)
			return false;

		steps[i].nr = ent->steps[i].nr;
		steps[i].do32bit = do32;
		for (j = 0; j < 6; j++)
			steps[i].args[j] = (unsigned long)ent->steps[i].args[j];
		steps[i].retval = (unsigned long)ent->steps[i].retval;
	}

	return chain_is_replay_safe(steps, ent->len);
}

bool chain_corpus_load_file(const char *path,
			    unsigned int *loaded, unsigned int *discarded)
{
	struct chain_corpus_ring *ring = chain_corpus_shm;
	struct chain_corpus_file_header hdr;
	struct chain_corpus_file_entry ent;
	uint32_t cur_major, cur_minor;
	unsigned int nloaded = 0;
	unsigned int ndiscarded = 0;
	ssize_t hn;
	int fd;

	if (loaded)
		*loaded = 0;
	if (discarded)
		*discarded = 0;

	if (ring == NULL || path == NULL)
		return false;

	persist_sweep_stale_tmp(path);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return false;

	hn = read_all(fd, &hdr, sizeof(hdr));
	if (hn != (ssize_t)sizeof(hdr)) {
		(void)close(fd);
		return false;
	}

	/* Refuse the whole file on any header-level mismatch.  Magic /
	 * version / ring-shape drift can silently change the on-disk
	 * layout, and admitting stale entries under a new schema would
	 * feed the ring garbage. */
	if (hdr.magic != CHAIN_CORPUS_FILE_MAGIC ||
	    hdr.version != CHAIN_CORPUS_FILE_VERSION ||
	    hdr.max_nr_syscall != MAX_NR_SYSCALL ||
	    hdr.max_seq_len != MAX_SEQ_LEN) {
		(void)close(fd);
		return false;
	}

	if (!chain_current_kernel_version(&cur_major, &cur_minor) ||
	    hdr.kernel_major != cur_major ||
	    hdr.kernel_minor != cur_minor) {
		(void)close(fd);
		return false;
	}

	{
		struct utsname u;

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
	}

	for (;;) {
		struct chain_entry *dst;
		unsigned int slot;
		unsigned int step;
		unsigned int j;
		unsigned int head, count;
		uint32_t want;
		ssize_t n;

		n = read_all(fd, &ent, sizeof(ent));
		if (n == 0)
			break;
		if (n != (ssize_t)sizeof(ent)) {
			ndiscarded++;
			break;
		}

		want = crc32(&ent,
			offsetof(struct chain_corpus_file_entry, crc));
		if (want != ent.crc) {
			ndiscarded++;
			continue;
		}

		if (!chain_load_entry_is_admissible(&ent)) {
			ndiscarded++;
			continue;
		}

		lock(&ring->lock);
		head = ring->head;
		slot = head % CHAIN_CORPUS_RING_SIZE;
		dst = &ring->slots[slot];
		memset(dst, 0, sizeof(*dst));
		dst->len = ent.len;
		dst->save_reason = ent.save_reason;
		for (step = 0; step < ent.len; step++) {
			dst->steps[step].nr = ent.steps[step].nr;
			dst->steps[step].do32bit =
				ent.steps[step].do32bit != 0;
			for (j = 0; j < 6; j++)
				dst->steps[step].args[j] =
					(unsigned long)ent.steps[step].args[j];
			dst->steps[step].retval =
				(unsigned long)ent.steps[step].retval;
		}

		/* Publish head/count with release semantics so the
		 * lockless chain_corpus_pick reader, which loads them
		 * with acquire, sees the slot writes that produced this
		 * entry.  Matches chain_corpus_save's ordering. */
		__atomic_store_n(&ring->head, head + 1, __ATOMIC_RELEASE);
		count = ring->count;
		if (count < CHAIN_CORPUS_RING_SIZE)
			__atomic_store_n(&ring->count, count + 1,
					 __ATOMIC_RELEASE);
		unlock(&ring->lock);

		__atomic_fetch_add(&ring->save_count, 1UL, __ATOMIC_RELAXED);
		nloaded++;
	}

	(void)close(fd);

	if (loaded)
		*loaded = nloaded;
	if (discarded)
		*discarded = ndiscarded;
	return nloaded > 0;
}

/*
 * Build a default per-arch, per-kernel-release chain corpus path under
 * $XDG_CACHE_HOME (or $HOME/.cache).  Creates the parent directory
 * tree on demand.  The returned pointer is owned by a static buffer.
 *
 * Arch- and release-tagged rather than sharing a global filename so a
 * cross-arch or cross-kernel invocation cannot accidentally load a
 * chain corpus whose syscall numbers or kernel behaviour do not match
 * the current run -- the header re-validation above would catch the
 * mismatch and drop the file, but partitioning at the path level
 * keeps the on-disk cache trivially bisectable by an operator.
 */
const char *chain_corpus_default_path(void)
{
	static char pathbuf[PATH_MAX];
	const char *xdg = getenv("XDG_CACHE_HOME");
	const char *home = getenv("HOME");
	char dir[PATH_MAX];
	const char *arch;
	struct utsname u;
	char *r;
	int ret;

#if defined(__x86_64__)
	arch = "x86_64";
#elif defined(__i386__)
	arch = "i386";
#elif defined(__aarch64__)
	arch = "aarch64";
#elif defined(__arm__)
	arch = "arm";
#else
	arch = "unknown";
#endif

	if (uname(&u) != 0)
		return NULL;
	for (r = u.release; *r; r++) {
		if (*r == '/')
			*r = '_';
	}

	if (xdg && xdg[0] == '/') {
		ret = snprintf(dir, sizeof(dir),
			       "%s/trinity/chain-corpus", xdg);
	} else if (home && home[0] == '/') {
		ret = snprintf(dir, sizeof(dir),
			       "%s/.cache/trinity/chain-corpus", home);
	} else {
		return NULL;
	}
	if (ret < 0 || (size_t)ret >= sizeof(dir))
		return NULL;

	/* mkdir -p the leaf directory.  EEXIST is acceptable; success is
	 * defined by the final directory existing, not by which racing
	 * creator won. */
	{
		char *p;
		mode_t saved_umask = umask(0);

		for (p = dir + 1; *p; p++) {
			if (*p == '/') {
				*p = '\0';
				if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
					*p = '/';
					(void)umask(saved_umask);
					return NULL;
				}
				*p = '/';
			}
		}
		if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
			(void)umask(saved_umask);
			return NULL;
		}
		(void)umask(saved_umask);
	}

	ret = snprintf(pathbuf, sizeof(pathbuf), "%s/%s-%s",
		       dir, arch, u.release);
	if (ret < 0 || (size_t)ret >= sizeof(pathbuf))
		return NULL;
	return pathbuf;
}

/*
 * Mid-run periodic snapshot state.  Parallel to cmp_hints_snapshot_*:
 * the enabled flag gates chain_corpus_maybe_snapshot() so the periodic
 * hook is a no-op until warm-start setup has resolved a valid path.
 *
 * The save trigger is driven off ring->save_count -- the same monotonic
 * atomic that chain_corpus_save() already increments on every admit --
 * so no new generation counter is needed on the ring itself.  Reading
 * it once per stats tick with RELAXED semantics is a single unsigned-
 * long load, well below the tick budget, and matches the
 * cmp_hints_total_generation() shape used for the analogous trigger on
 * the cmp-hints pool.
 */
static char chain_corpus_snapshot_path[PATH_MAX];
static bool chain_corpus_snapshot_enabled;
static unsigned long chain_corpus_save_count_at_last_snapshot;
static time_t chain_corpus_last_snapshot_time;

void chain_corpus_enable_snapshots(const char *path)
{
	size_t len;

	if (path == NULL)
		return;
	len = strlen(path);
	if (len == 0 || len >= sizeof(chain_corpus_snapshot_path))
		return;
	memcpy(chain_corpus_snapshot_path, path, len + 1);
	chain_corpus_snapshot_enabled = true;
	chain_corpus_last_snapshot_time = (time_t)(mono_ns() / 1000000000ULL);
	if (chain_corpus_shm != NULL)
		chain_corpus_save_count_at_last_snapshot =
			__atomic_load_n(&chain_corpus_shm->save_count,
					__ATOMIC_RELAXED);
	else
		chain_corpus_save_count_at_last_snapshot = 0;
}

void chain_corpus_maybe_snapshot(void)
{
	unsigned long saves_now;
	time_t now;

	if (!chain_corpus_snapshot_enabled || chain_corpus_shm == NULL)
		return;

	saves_now = __atomic_load_n(&chain_corpus_shm->save_count,
				    __ATOMIC_RELAXED);
	now = (time_t)(mono_ns() / 1000000000ULL);

	/* Both gates must expire before a snapshot fires: enough new admits
	 * (so we don't write a near-identical payload to disk) AND enough
	 * wall time (so a burst of admits doesn't trigger one save per
	 * second).  The generation gate stays quiet once the ring saturates
	 * and the per-(reason, nr) window cap dominates the admit rate; the
	 * time gate would then be the only limiter, so both gates are
	 * required to avoid the pathological "saturated ring, high time
	 * budget, thrashing the disk" case.  Mirrors the cmp_hints gate. */
	if (saves_now < chain_corpus_save_count_at_last_snapshot
			+ CHAIN_CORPUS_SNAPSHOT_NEW ||
	    now < chain_corpus_last_snapshot_time
			+ (time_t)CHAIN_CORPUS_SNAPSHOT_INTERVAL_SEC)
		return;

	if (chain_corpus_save_file(chain_corpus_snapshot_path)) {
		chain_corpus_save_count_at_last_snapshot = saves_now;
		chain_corpus_last_snapshot_time = now;
	}
}
