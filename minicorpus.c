/*
 * Coverage-guided argument retention (mini-corpus).
 *
 * Stores syscall argument snapshots that discovered new KCOV edges.
 * During future arg generation for the same syscall, a stored
 * snapshot may be replayed with per-argument mutations to explore
 * nearby input space.
 *
 * Syscalls with sanitise callbacks or with arg types that carry
 * heap pointers (ARG_IOVEC, ARG_PATHNAME, ARG_SOCKADDR, ARG_MMAP)
 * are excluded — those pointers become stale after deferred-free
 * eviction, causing UAF on replay.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "fd.h"
#include "kcov.h"
#include "minicorpus.h"
#include "random.h"
#include "sanitise.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

struct minicorpus_shared *minicorpus_shm = NULL;

void minicorpus_init(void)
{
	if (kcov_shm == NULL)
		return;

	minicorpus_shm = alloc_shared(sizeof(struct minicorpus_shared));
	memset(minicorpus_shm, 0, sizeof(struct minicorpus_shared));
	output(0, "KCOV: mini-corpus allocated (%lu KB, %d entries/syscall)\n",
		(unsigned long) sizeof(struct minicorpus_shared) / 1024,
		CORPUS_RING_SIZE);
}

static void ring_lock(struct corpus_ring *ring)
{
	lock(&ring->lock);
}

static void ring_unlock(struct corpus_ring *ring)
{
	unlock(&ring->lock);
}

void minicorpus_save(struct syscallrecord *rec)
{
	struct corpus_ring *ring;
	struct corpus_entry *ent;
	struct syscallentry *entry;
	unsigned int nr = rec->nr;
	unsigned int i;

	if (minicorpus_shm == NULL || nr >= MAX_NR_SYSCALL)
		return;

	entry = get_syscall_entry(nr, rec->do32bit);
	if (entry == NULL)
		return;

	/* Reject syscalls whose args carry heap pointers allocated by
	 * generic_sanitise().  After deferred-free eviction those pointers
	 * go stale, and replaying them feeds freed memory to the kernel. */
	for (i = 0; i < entry->num_args && i < 6; i++) {
		switch (entry->argtype[i]) {
		case ARG_IOVEC:
		case ARG_PATHNAME:
		case ARG_SOCKADDR:
		case ARG_MMAP:
			return;
		default:
			break;
		}
	}

	ring = &minicorpus_shm->rings[nr];

	ring_lock(ring);

	ent = &ring->entries[ring->head % CORPUS_RING_SIZE];
	ent->args[0] = rec->a1;
	ent->args[1] = rec->a2;
	ent->args[2] = rec->a3;
	ent->args[3] = rec->a4;
	ent->args[4] = rec->a5;
	ent->args[5] = rec->a6;
	ent->num_args = entry->num_args;

	/* Saved fd numbers are stale on replay — zero them out so mutate_arg
	 * gets a fresh fd rather than trying to reuse a closed one. */
	for (i = 0; i < entry->num_args && i < 6; i++) {
		if (is_fdarg(entry->argtype[i]))
			ent->args[i] = 0;
	}

	ring->head++;
	if (ring->count < CORPUS_RING_SIZE)
		ring->count++;

	ring_unlock(ring);
}

/*
 * Apply a small mutation to a single argument value.
 * The mutations are designed to explore nearby input space:
 *   - bit flip: toggle a single random bit
 *   - add/sub:  adjust by a small delta (1..16)
 *   - boundary: replace with a boundary value (0, -1, page_size, etc.)
 */
static unsigned long mutate_arg(unsigned long val)
{
	switch (rand() % 6) {
	case 0:
		/* flip a random bit */
		val ^= 1UL << (rand() % (sizeof(unsigned long) * 8));
		break;
	case 1: {
		/* add small delta, saturate at ULONG_MAX */
		unsigned long delta = 1 + (unsigned long)(rand() % 16);
		val = ((unsigned long)-1 - val < delta) ? (unsigned long)-1 : val + delta;
		break;
	}
	case 2: {
		/* subtract small delta, saturate at 0 */
		unsigned long delta = 1 + (unsigned long)(rand() % 16);
		val = (val < delta) ? 0 : val - delta;
		break;
	}
	case 3:
		/* replace with boundary */
		val = get_boundary_value();
		break;
	case 4:
		/* byte-level shuffle: randomize one byte */
		{
			unsigned int byte_pos = rand() % sizeof(unsigned long);
			unsigned long mask = 0xffUL << (byte_pos * 8);
			val = (val & ~mask) | ((unsigned long) RAND_BYTE() << (byte_pos * 8));
		}
		break;
	case 5:
		/* keep original — sometimes the saved value is good as-is */
		break;
	}
	return val;
}

bool minicorpus_replay(struct syscallrecord *rec)
{
	struct corpus_ring *ring;
	struct corpus_entry snapshot;
	struct syscallentry *entry;
	unsigned int nr = rec->nr;
	unsigned int slot;
	unsigned int i;

	if (minicorpus_shm == NULL || nr >= MAX_NR_SYSCALL)
		return false;

	ring = &minicorpus_shm->rings[nr];

	/* No saved entries yet. */
	if (ring->count == 0)
		return false;

	/* ~25% chance to replay, 75% fresh generation. */
	if (!ONE_IN(4))
		return false;

	ring_lock(ring);

	if (ring->count == 0) {
		ring_unlock(ring);
		return false;
	}

	/* Pick a random entry from the ring. */
	slot = rand() % ring->count;
	/* The ring is written at head and wraps, so the oldest valid
	 * entry starts at (head - count) mod CORPUS_RING_SIZE. */
	slot = (ring->head - ring->count + slot) % CORPUS_RING_SIZE;
	snapshot = ring->entries[slot];

	ring_unlock(ring);

	entry = get_syscall_entry(nr, rec->do32bit);
	if (entry == NULL)
		return false;

	/* Don't replay into syscalls with pointer-bearing arg types.
	 * Same rationale as minicorpus_save(). */
	for (i = 0; i < entry->num_args && i < 6; i++) {
		switch (entry->argtype[i]) {
		case ARG_IOVEC:
		case ARG_PATHNAME:
		case ARG_SOCKADDR:
		case ARG_MMAP:
			return false;
		default:
			break;
		}
	}

	/* Apply the snapshot with per-argument mutations. */
	for (i = 0; i < entry->num_args && i < 6; i++) {
		unsigned long val = snapshot.args[i];

		/* ~25% chance to mutate each arg. */
		if (ONE_IN(4))
			val = mutate_arg(val);

		/* Don't let fd args land on stdin/stdout/stderr. */
		if (is_fdarg(entry->argtype[i]) && val <= 2)
			val = (unsigned long) get_random_fd();

		switch (i) {
		case 0: rec->a1 = val; break;
		case 1: rec->a2 = val; break;
		case 2: rec->a3 = val; break;
		case 3: rec->a4 = val; break;
		case 4: rec->a5 = val; break;
		case 5: rec->a6 = val; break;
		}
	}

	return true;
}

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

#define CORPUS_FILE_MAGIC	0x54524E43U	/* "TRNC" */
#define CORPUS_FILE_VERSION	2U

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
	 * the patch sublevel and any local version suffix (-rcN, -fbkN,
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

/* Plain CRC32 (IEEE 802.3 polynomial, reflected).  Small, no deps. */
static uint32_t corpus_crc32(const void *buf, size_t len)
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

bool minicorpus_save_file(const char *path)
{
	struct corpus_file_header hdr;
	struct corpus_file_entry ent;
	char tmppath[PATH_MAX];
	int fd;
	unsigned int nr;
	int ret;

	if (minicorpus_shm == NULL || path == NULL)
		return false;

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

	ret = snprintf(tmppath, sizeof(tmppath), "%s.tmp", path);
	if (ret < 0 || (size_t)ret >= sizeof(tmppath))
		return false;

	fd = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return false;

	if (write_all(fd, &hdr, sizeof(hdr)) < 0)
		goto fail;

	for (nr = 0; nr < MAX_NR_SYSCALL; nr++) {
		struct corpus_ring *ring = &minicorpus_shm->rings[nr];
		unsigned int oldest, i;

		if (ring->count == 0)
			continue;

		oldest = (ring->head - ring->count) % CORPUS_RING_SIZE;

		for (i = 0; i < ring->count; i++) {
			struct corpus_entry *src;
			unsigned int slot = (oldest + i) % CORPUS_RING_SIZE;
			unsigned int j;

			src = &ring->entries[slot];

			memset(&ent, 0, sizeof(ent));
			ent.nr = nr;
			ent.num_args = src->num_args;
			for (j = 0; j < 6; j++)
				ent.args[j] = (uint64_t)src->args[j];

			ent.crc = corpus_crc32(&ent,
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
	int fd;

	if (loaded)
		*loaded = 0;
	if (discarded)
		*discarded = 0;

	if (minicorpus_shm == NULL || path == NULL)
		return false;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return false;

	if (read_all(fd, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)) {
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
		uint32_t want;
		ssize_t n;
		unsigned int j;

		n = read_all(fd, &ent, sizeof(ent));
		if (n == 0)
			break;
		if (n != (ssize_t)sizeof(ent)) {
			ndiscarded++;
			break;
		}

		want = corpus_crc32(&ent,
			offsetof(struct corpus_file_entry, crc));
		if (want != ent.crc || ent.nr >= MAX_NR_SYSCALL ||
		    ent.num_args > 6) {
			ndiscarded++;
			continue;
		}

		ring = &minicorpus_shm->rings[ent.nr];
		ring_lock(ring);
		dst = &ring->entries[ring->head % CORPUS_RING_SIZE];
		for (j = 0; j < 6; j++)
			dst->args[j] = (unsigned long)ent.args[j];
		dst->num_args = ent.num_args;
		ring->head++;
		if (ring->count < CORPUS_RING_SIZE)
			ring->count++;
		ring_unlock(ring);
		nloaded++;
	}

	close(fd);

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

	/* mkdir -p the leaf directory.  We don't care about race losses
	 * (EEXIST is fine), only about the final dir actually existing. */
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
