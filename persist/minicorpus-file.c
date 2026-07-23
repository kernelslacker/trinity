/*
 * On-disk corpus persistence (warm-start).
 *
 * The format is a fixed header followed by a stream of fixed-size
 * entries.  Header carries a magic, a format version, the running
 * kernel's major.minor, and the syscall-number space size.  Each
 * entry carries the syscall number, num_args, six argument values,
 * and a CRC32 covering only the entry payload — a corrupt entry is
 * dropped without taking down the whole file.
 *
 * The layout is intentionally architecture-specific: callers build
 * paths under a per-arch subdirectory.  Cross-arch reuse is unsafe
 * because syscall numbers don't agree.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <unistd.h>

#include "fd.h"
#include "minicorpus.h"
#include "persist-util.h"
#include "sanitise.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"
#include "pids.h"

#include "minicorpus-internal.h"

#define CORPUS_FILE_MAGIC	0x54524E43U	/* "TRNC" */
#define CORPUS_FILE_VERSION	3U

/* Linux utsname fields are __NEW_UTS_LEN+1 = 65 bytes including NUL. */
#define CORPUS_UTSNAME_LEN	65

struct corpus_file_header {
	uint32_t magic;
	uint32_t version;
	uint32_t kernel_major;	/* parsed from utsname.release, kept for diag */
	uint32_t kernel_minor;	/* same */
	uint32_t max_nr_syscall;
	uint32_t reserved;
	/* Full utsname.release and utsname.version strings.  release encodes
	 * the patch sublevel and any local version suffix (-rcN, -localN,
	 * vendor patches), version encodes the build timestamp + git hash
	 * for kernel builds that include them.  Strict equality on both
	 * means "same compiled kernel image" — the only safe granularity
	 * for replay, since e.g. 7.0 vs 7.0-rc1 can differ in syscall
	 * behavior despite matching major.minor. */
	char kernel_release[CORPUS_UTSNAME_LEN];
	char kernel_version[CORPUS_UTSNAME_LEN];
};

struct corpus_file_entry {
	uint32_t nr;
	uint32_t num_args;
	uint64_t args[6];
	uint32_t crc;
	uint32_t pad;
};

static bool parse_kernel_version(const char *release,
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

static bool current_kernel_version(uint32_t *major, uint32_t *minor)
{
	struct utsname u;

	if (uname(&u) != 0)
		return false;
	return parse_kernel_version(u.release, major, minor);
}

/*
 * Dirty-bit proxy for minicorpus_save_file().  Compared against
 * minicorpus_shm->mutations at the top of the save path; when equal,
 * no ring has been touched since the last successful save and the on-disk
 * image is bit-for-bit identical to what we would write.  Initialised to
 * ULONG_MAX so the first save in a process always fires; advanced on
 * every successful save and seeded by the warm-start loader so the
 * load-then-immediate-exit cycle skips its end-of-run save.
 *
 * Mostly-parent-private: the maybe_snapshot path runs in children but is
 * already throttled by its own CAS gate to roughly one save per
 * MINICORPUS_SNAPSHOT_EDGES window, so the worst case for a CAS-elected
 * child whose stale process-local baseline misses a true short-circuit
 * is bounded by that outer gate.  The redundant-save scenario this
 * commit targets is the parent end-of-run save, which is fully covered.
 */
static unsigned long minicorpus_mutations_at_last_save = ULONG_MAX;

bool minicorpus_save_file(const char *path)
{
	struct corpus_file_header hdr;
	struct corpus_file_entry ent;
	struct corpus_entry snapshot[CORPUS_RING_SIZE];
	char tmppath[PATH_MAX];
	unsigned long mutations_now;
	int fd;
	unsigned int nr;
	int ret;

	if (minicorpus_shm == NULL || path == NULL)
		return false;

	mutations_now = __atomic_load_n(&minicorpus_shm->mutations,
					__ATOMIC_RELAXED);
	if (mutations_now == minicorpus_mutations_at_last_save) {
		output(0, "minicorpus: snapshot skipped, no ring changes since last save\n");
		return true;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = CORPUS_FILE_MAGIC;
	hdr.version = CORPUS_FILE_VERSION;
	hdr.max_nr_syscall = MAX_NR_SYSCALL;
	if (!current_kernel_version(&hdr.kernel_major, &hdr.kernel_minor))
		return false;
	{
		struct utsname u;
		if (uname(&u) != 0)
			return false;
		strncpy(hdr.kernel_release, u.release, sizeof(hdr.kernel_release) - 1);
		hdr.kernel_release[sizeof(hdr.kernel_release) - 1] = '\0';
		strncpy(hdr.kernel_version, u.version, sizeof(hdr.kernel_version) - 1);
		hdr.kernel_version[sizeof(hdr.kernel_version) - 1] = '\0';
	}

	/* Per-pid tmp suffix so a periodic save and the on-shutdown save
	 * can't open the same .tmp file with O_TRUNC and interleave their
	 * writes into a corrupt blob.  The atomic rename still gives the
	 * final on-disk file all-or-nothing semantics. */
	ret = snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d", path, (int)mypid());
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

	for (nr = 0; nr < MAX_NR_SYSCALL; nr++) {
		struct corpus_ring *ring = &minicorpus_shm->rings[nr];
		unsigned int snap_count, oldest, i;

		/* Lock briefly to copy the ring out into a local buffer, then
		 * release before the disk write.  Mid-run snapshots run while
		 * children are actively appending to rings; without the lock,
		 * head/count and entries[] can be read in inconsistent
		 * combinations.  Hold time is bounded by a memcpy of at most
		 * CORPUS_RING_SIZE entries (~1.8 KB), so per-ring writer stall
		 * is microseconds even under heavy contention. */
		minicorpus_ring_lock(ring);
		snap_count = ring->count;
		if (snap_count > CORPUS_RING_SIZE)
			snap_count = CORPUS_RING_SIZE;
		if (snap_count == 0) {
			minicorpus_ring_unlock(ring);
			continue;
		}
		oldest = (ring->head - snap_count) % CORPUS_RING_SIZE;
		for (i = 0; i < snap_count; i++) {
			unsigned int slot = (oldest + i) % CORPUS_RING_SIZE;
			snapshot[i] = ring->entries[slot];
		}
		minicorpus_ring_unlock(ring);

		for (i = 0; i < snap_count; i++) {
			struct corpus_entry *src = &snapshot[i];
			unsigned int j;

			memset(&ent, 0, sizeof(ent));
			ent.nr = nr;
			ent.num_args = src->num_args;
			for (j = 0; j < 6; j++)
				ent.args[j] = (uint64_t)src->args[j];

			ent.crc = crc32(&ent,
				offsetof(struct corpus_file_entry, crc));

			if (write_all(fd, &ent, sizeof(ent)) < 0)
				goto fail;
		}
	}

	if (fsync(fd) != 0)
		goto fail;
	if (close(fd) != 0) {
		unlink(tmppath);
		return false;
	}

	if (rename(tmppath, path) != 0) {
		unlink(tmppath);
		return false;
	}
	minicorpus_mutations_at_last_save = mutations_now;
	return true;

fail:
	close(fd);
	unlink(tmppath);
	return false;
}

bool minicorpus_load_file(const char *path,
		unsigned int *loaded, unsigned int *discarded)
{
	struct corpus_file_header hdr;
	struct corpus_file_entry ent;
	uint32_t cur_major, cur_minor;
	unsigned int nloaded = 0;
	unsigned int ndiscarded = 0;
	ssize_t hn;
	int fd;

	if (loaded)
		*loaded = 0;
	if (discarded)
		*discarded = 0;

	if (minicorpus_shm == NULL || path == NULL)
		return false;

	persist_sweep_stale_tmp(path);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			output(0, "minicorpus: no persisted state at %s -- cold start\n",
			       path);
		else
			output(0, "minicorpus: open(%s) failed: %s -- cold start\n",
			       path, strerror(errno));
		return false;
	}

	hn = read_all(fd, &hdr, sizeof(hdr));
	if (hn != (ssize_t)sizeof(hdr)) {
		output(0, "minicorpus: header truncated at %s (got %zd, want %zu) -- cold start\n",
		       path, hn, sizeof(hdr));
		close(fd);
		return false;
	}

	if (hdr.magic != CORPUS_FILE_MAGIC ||
	    hdr.version != CORPUS_FILE_VERSION ||
	    hdr.max_nr_syscall != MAX_NR_SYSCALL) {
		close(fd);
		return false;
	}

	if (!current_kernel_version(&cur_major, &cur_minor) ||
	    hdr.kernel_major != cur_major ||
	    hdr.kernel_minor != cur_minor) {
		close(fd);
		return false;
	}

	{
		struct utsname u;
		if (uname(&u) != 0) {
			close(fd);
			return false;
		}
		/* Force NUL termination on the on-disk strings before strncmp,
		 * defensive against truncated/corrupt headers. */
		hdr.kernel_release[sizeof(hdr.kernel_release) - 1] = '\0';
		hdr.kernel_version[sizeof(hdr.kernel_version) - 1] = '\0';
		if (strncmp(hdr.kernel_release, u.release,
			    sizeof(hdr.kernel_release)) != 0 ||
		    strncmp(hdr.kernel_version, u.version,
			    sizeof(hdr.kernel_version)) != 0) {
			close(fd);
			return false;
		}
	}

	for (;;) {
		struct corpus_ring *ring;
		struct corpus_entry *dst;
		struct syscallentry *xe;
		uint32_t want;
		ssize_t n;
		unsigned int j;
		unsigned int cur_count;

		n = read_all(fd, &ent, sizeof(ent));
		if (n == 0)
			break;
		if (n != (ssize_t)sizeof(ent)) {
			ndiscarded++;
			break;
		}

		want = crc32(&ent,
			offsetof(struct corpus_file_entry, crc));
		if (want != ent.crc || ent.nr >= MAX_NR_SYSCALL ||
		    ent.num_args < 1 || ent.num_args > 6) {
			ndiscarded++;
			continue;
		}

		/* Drop entries whose argtype set is no longer replay-safe.
		 * Catches stale-on-disk corpora pre-dating the ARG_PID guard,
		 * cross-config swap of a saved file (different syscall set
		 * for the same nr), and any future syscall whose argtype
		 * changes to ARG_PID without invalidating cached corpora.
		 * Bumps ndiscarded so operators see a corpus-quality signal
		 * rather than silently absorbing the entry.  do32bit isn't
		 * encoded on disk; the 64-bit table is the canonical view
		 * and on biarch any pointer/pid argtype is shared between
		 * both tables for a given nr. */
		xe = get_syscall_entry(ent.nr, false);
		if (xe != NULL && !corpus_args_replayable(xe)) {
			ndiscarded++;
			continue;
		}

		/* Mirror the save-side defence: zero out fd and address slots
		 * before they reach the ring.  Two cases the save-side can't
		 * cover: (a) on-disk corpora written by an older binary that
		 * predated the save-side zeroing, and (b) argtypes that have
		 * been tightened since the entry was saved (e.g. ARG_UNDEFINED
		 * → ARG_FD), where the saved literal is a stale fd from the
		 * recording run.  Predicate set matches the save-side loop so
		 * both ends agree on what counts as stale. */
		if (xe != NULL) {
			for (j = 0; j < ent.num_args && j < 6; j++) {
				if (is_fdarg(xe->argtype[j]) ||
				    xe->argtype[j] == ARG_ADDRESS ||
				    xe->argtype[j] == ARG_NON_NULL_ADDRESS)
					ent.args[j] = 0;
			}
		}

		ring = &minicorpus_shm->rings[ent.nr];
		minicorpus_ring_lock(ring);
		dst = &ring->entries[ring->head % CORPUS_RING_SIZE];
		for (j = 0; j < 6; j++)
			dst->args[j] = (unsigned long)ent.args[j];
		dst->num_args = ent.num_args;
		/* novel_replay_hits is volatile per-process baseline state,
		 * not persisted on disk.  Zero it explicitly when overwriting
		 * a recycled slot so an entry whose previous occupant had
		 * accumulated baseline doesn't inherit stale credit. */
		dst->novel_replay_hits = 0;
		/* Count-before-head release publish; see comment on the
		 * matching publish in minicorpus_save_with_reason(). */
		cur_count = ring->count;
		if (cur_count < CORPUS_RING_SIZE)
			__atomic_store_n(&ring->count, cur_count + 1,
					 __ATOMIC_RELEASE);
		__atomic_store_n(&ring->head, ring->head + 1,
				 __ATOMIC_RELEASE);
		minicorpus_ring_unlock(ring);
		__atomic_fetch_add(&minicorpus_shm->mutations, 1UL,
				   __ATOMIC_RELAXED);
		nloaded++;
	}

	close(fd);

	/* Seed the dirty-bit baseline so a load-then-immediate-exit cycle
	 * skips the redundant end-of-run save.  The load loop already bumped
	 * minicorpus_shm->mutations once per admitted entry, so the current
	 * counter exactly reflects the just-loaded state. */
	minicorpus_mutations_at_last_save =
		__atomic_load_n(&minicorpus_shm->mutations, __ATOMIC_RELAXED);

	if (loaded)
		*loaded = nloaded;
	if (discarded)
		*discarded = ndiscarded;
	return nloaded > 0;
}

/*
 * Build a default per-arch corpus path under $XDG_CACHE_HOME (or
 * $HOME/.cache).  Creates the parent directory tree on demand.  The
 * returned pointer is owned by a static buffer.
 */
const char *minicorpus_default_path(void)
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
		ret = snprintf(dir, sizeof(dir), "%s/trinity/corpus", xdg);
	} else if (home && home[0] == '/') {
		ret = snprintf(dir, sizeof(dir),
			"%s/.cache/trinity/corpus", home);
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

	ret = snprintf(pathbuf, sizeof(pathbuf), "%s/%s-%s", dir, arch, u.release);
	if (ret < 0 || (size_t)ret >= sizeof(pathbuf))
		return NULL;
	return pathbuf;
}
