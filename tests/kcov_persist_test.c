/*
 * Self-check for the kcov bitmap warm-start loader (kcov/persist.c).  A priors
 * or diag block the loader skips (another MAX_NR_SYSCALL, a failed scratch
 * alloc) must not shift the block behind it, and the log must name the real
 * cause of any block it refuses.  A file the loader turns down and a save that
 * cannot finish each close their one fd exactly once and leave nothing behind.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "exit.h"		/* EXIT_SHM_CORRUPTION, STILL_RUNNING */
#include "fake_parent.h"	/* fake_output_log */
#include "fd.h"			/* read_all */
#include "kcov.h"
#include "persist-envelope.h"
#include "shm.h"
#include "strategy.h"		/* NR_STRATEGIES */
#include "syscall.h"		/* MAX_NR_SYSCALL */
#include "utils.h"		/* ARRAY_SIZE */

/* Owned by kcov/lifecycle.c in production. */
uint64_t kcov_kaslr_base;

/* The on-disk header, as kcov/persist.c writes it: the layout is the
 * contract for the external cache-stats reader.  v5 and v6 files stop
 * at 88 B, before strat_crc32. */
struct file_header {
	uint32_t magic;
	uint32_t version;
	uint32_t num_edges;
	uint32_t num_buckets;
	uint64_t edges_found;
	uint64_t distinct_edges;
	uint32_t payload_crc32;
	uint32_t diag_crc32;
	uint8_t  kallsyms_sha256[32];
	uint32_t max_nr_syscall;
	uint32_t priors_crc32;
	uint64_t kaslr_base;
	uint32_t strat_crc32;
	uint32_t pad2;
};

#define HDR_V6_SIZE	88U

_Static_assert(sizeof(struct file_header) == 96,
	       "the v7 header is 96 B on disk");
_Static_assert(offsetof(struct file_header, strat_crc32) == HDR_V6_SIZE,
	       "the v5/v6 header ends before strat_crc32");

/* Block sizes for a writer with @max syscall slots, and where each
 * block sits in the file kcov_bitmap_save_file() writes: envelope,
 * header, bitmap, priors (two u64 arrays), diag (16 B per slot and ABI),
 * strat (calls, then counts, per strategy). */
#define PRIORS_SIZE(max)	((size_t)(max) * 2 * sizeof(unsigned long))
#define DIAG_SIZE(max)		((size_t)(max) * 2 * 16)
#define STRAT_SIZE		(2 * NR_STRATEGIES * sizeof(uint64_t))

#define ENVELOPE_SIZE	sizeof(struct trinity_persist_envelope)
#define BITMAP_OFF	(ENVELOPE_SIZE + sizeof(struct file_header))
#define PRIORS_OFF	(BITMAP_OFF + KCOV_NUM_EDGES)
#define DIAG_OFF	(PRIORS_OFF + PRIORS_SIZE(MAX_NR_SYSCALL))
#define STRAT_OFF	(DIAG_OFF + DIAG_SIZE(MAX_NR_SYSCALL))
#define FILE_SIZE	(STRAT_OFF + STRAT_SIZE)

/* Counters saved into each block, and the bitmap they ride on: three
 * bytes holding four edges. */
#define SAMPLE_EDGES	4UL
#define SAMPLE_DISTINCT	3UL
#define EDGES_OF(nr)		(100UL + (nr))
#define CALLS_OF(nr)		(200UL + (nr))
#define BITS_OF(nr, dim)	(300UL + (nr) * 2 + (dim))
#define PCS_OF(nr, dim)		(400UL + (nr) * 2 + (dim))
#define STRAT_CALLS(s)		(1000UL + (s))
#define STRAT_COUNT(s)		(2000UL + (s))

/* The last slot is there so a block read short by one record shows. */
static const unsigned int sample_nr[] = { 7, MAX_NR_SYSCALL - 1 };

struct scenario {
	const char *name;
	uint32_t version;	/* version the file carries */
	uint32_t file_max;	/* syscall slots its header claims */
	bool header_only;	/* the blocks stay as saved, not sized by file_max */
	bool corrupt_strat;	/* damage the strat block's bytes */
	size_t cut;		/* keep only this many bytes of the file; 0: all */
	size_t flip;		/* damage the byte at this offset; 0: none */
	bool refused;		/* the load returns false and publishes nothing */
	size_t fail_malloc;	/* scratch size whose malloc fails; 0: none */
	unsigned int fail_lseek;	/* the Nth lseek of the load fails; 0: none */
	bool priors, diag, strat;	/* blocks the load must restore */
	const char *log_has;	/* line that names what happened */
	const char *log_or;	/* or this one: the host decides which; NULL: none */
};

static const struct scenario scenarios[] = {
	{ .name = "same table", .version = 7, .file_max = MAX_NR_SYSCALL,
	  .priors = true, .diag = true, .strat = true,
	  .log_has = "loaded v7 strat block" },
	/* Priors and diag are skipped; strat is still where the writer
	 * put it. */
	{ .name = "writer had fewer slots", .version = 7,
	  .file_max = MAX_NR_SYSCALL / 2, .strat = true,
	  .log_has = "priors disabled" },
	{ .name = "writer had more slots", .version = 7,
	  .file_max = MAX_NR_SYSCALL * 2, .strat = true,
	  .log_has = "diag disabled" },
	/* The most slots a header can claim put strat far past the end of
	 * the file: refused as truncated, or as a failed seek on a tmp
	 * filesystem too small to take it.  Either way nothing is read from
	 * elsewhere, and strat does not load. */
	{ .name = "header claims 2^32-1 slots", .version = 7,
	  .file_max = UINT32_MAX, .header_only = true,
	  .log_has = "strat truncated", .log_or = "strat seek to" },
	{ .name = "priors scratch alloc fails", .version = 7,
	  .file_max = MAX_NR_SYSCALL, .fail_malloc = PRIORS_SIZE(MAX_NR_SYSCALL),
	  .diag = true, .strat = true,
	  .log_has = "priors scratch alloc fail" },
	{ .name = "diag scratch alloc fails", .version = 7,
	  .file_max = MAX_NR_SYSCALL, .fail_malloc = DIAG_SIZE(MAX_NR_SYSCALL),
	  .priors = true, .strat = true,
	  .log_has = "diag scratch alloc fail" },
	/* A v7 load seeks twice: to diag, then to strat. */
	{ .name = "diag seek fails", .version = 7, .file_max = MAX_NR_SYSCALL,
	  .fail_lseek = 1, .priors = true, .strat = true,
	  .log_has = "Illegal seek -- diag skipped" },
	{ .name = "strat seek fails", .version = 7, .file_max = MAX_NR_SYSCALL,
	  .fail_lseek = 2, .priors = true, .diag = true,
	  .log_has = "Illegal seek -- strat skipped" },
	/* A strat block that is itself bad is still refused, and named. */
	{ .name = "corrupt strat block", .version = 7,
	  .file_max = MAX_NR_SYSCALL, .corrupt_strat = true,
	  .priors = true, .diag = true, .log_has = "strat CRC mismatch" },
	/* Older headers are 88 B, which moves every block, and older files
	 * end before the blocks they predate. */
	{ .name = "v6 file", .version = 6, .file_max = MAX_NR_SYSCALL,
	  .priors = true, .diag = true, .log_has = "loaded v6 diag block" },
	{ .name = "v5 file", .version = 5, .file_max = MAX_NR_SYSCALL,
	  .priors = true, .log_has = "loaded 4 edges" },
	/* Files the loader turns down outright.  Each of them returns
	 * false, has closed the fd it opened exactly once and has
	 * published nothing. */
	{ .name = "truncated envelope", .version = 7, .file_max = MAX_NR_SYSCALL,
	  .refused = true, .cut = ENVELOPE_SIZE / 2,
	  .log_has = "envelope truncated" },
	{ .name = "truncated header", .version = 7, .file_max = MAX_NR_SYSCALL,
	  .refused = true, .cut = ENVELOPE_SIZE + 40,
	  .log_has = "header truncated" },
	{ .name = "truncated bitmap", .version = 7, .file_max = MAX_NR_SYSCALL,
	  .refused = true, .cut = BITMAP_OFF + KCOV_NUM_EDGES / 2,
	  .log_has = "payload truncated" },
	{ .name = "bad magic", .version = 7, .file_max = MAX_NR_SYSCALL,
	  .refused = true,
	  .flip = ENVELOPE_SIZE + offsetof(struct file_header, magic),
	  .log_has = "file magic" },
	/* The last byte of the fingerprint: a compare that stopped short of
	 * the 32 bytes would let this file through. */
	{ .name = "kernel fingerprint", .version = 7, .file_max = MAX_NR_SYSCALL,
	  .refused = true,
	  .flip = ENVELOPE_SIZE + offsetof(struct file_header, kallsyms_sha256) + 31,
	  .log_has = "kernel fingerprint mismatch" },
	{ .name = "payload CRC mismatch", .version = 7, .file_max = MAX_NR_SYSCALL,
	  .refused = true, .flip = BITMAP_OFF + 100,
	  .log_has = "CRC mismatch" },
	{ .name = "bitmap scratch alloc fails", .version = 7,
	  .file_max = MAX_NR_SYSCALL, .refused = true,
	  .fail_malloc = KCOV_NUM_EDGES,
	  .log_has = "kcov-bitmap: scratch alloc fail" },
};

/* What a block read from the wrong place shows up as.  A scenario that
 * expects one of them names it in log_has. */
static const char *const complaints[] = { "CRC mismatch", "truncated" };

/* Size of the next malloc() to fail, once; 0 for none. */
static size_t malloc_fail_size;

void *__real_malloc(size_t size);
void *__wrap_malloc(size_t size);
void *__wrap_malloc(size_t size)
{
	if (malloc_fail_size != 0 && size == malloc_fail_size) {
		malloc_fail_size = 0;
		return NULL;
	}
	return __real_malloc(size);
}

/* The Nth lseek() from here fails with ESPIPE, as on a non-seekable
 * input; 0 for none. */
static unsigned int lseek_fail_nth;

off_t __real_lseek(int fd, off_t offset, int whence);
off_t __wrap_lseek(int fd, off_t offset, int whence);
off_t __wrap_lseek(int fd, off_t offset, int whence)
{
	if (lseek_fail_nth != 0 && --lseek_fail_nth == 0) {
		errno = ESPIPE;
		return (off_t) -1;
	}
	return __real_lseek(fd, offset, whence);
}

/* close() calls since the counter was last cleared: a load or a save
 * closes the one fd it opened exactly once, whether or not it succeeds. */
static unsigned int close_calls;

int __real_close(int fd);
int __wrap_close(int fd);
int __wrap_close(int fd)
{
	close_calls++;
	return __real_close(fd);
}

static unsigned int failures;

static void expect(bool ok, const char *name, const char *what)
{
	if (ok)
		return;
	fprintf(stderr, "\n    kcov persist: %s: %s", name, what);
	failures++;
}

/* A zeroed kcov_shm and strategy counters, as a fresh run has. */
static void reset_state(void)
{
	free(kcov_shm);
	kcov_shm = calloc(1, sizeof(*kcov_shm));
	if (kcov_shm == NULL)
		BUG("kcov persist: calloc failed");
	memset(shm->pc_edge_calls_by_strategy, 0,
	       sizeof(shm->pc_edge_calls_by_strategy));
	memset(shm->pc_edge_count_by_strategy, 0,
	       sizeof(shm->pc_edge_count_by_strategy));
}

static void fill_state(void)
{
	unsigned int i, dim, s;

	kcov_shm->bucket_seen[100] = 0x01;
	kcov_shm->bucket_seen[200000] = 0x81;
	kcov_shm->bucket_seen[KCOV_NUM_EDGES - 1] = 0x10;
	kcov_shm->coverage.edges_found = SAMPLE_EDGES;
	kcov_shm->coverage.distinct_edges = SAMPLE_DISTINCT;

	for (i = 0; i < ARRAY_SIZE(sample_nr); i++) {
		unsigned int nr = sample_nr[i];

		kcov_shm->per_syscall.per_syscall_edges[nr][0][0] = EDGES_OF(nr);
		kcov_shm->per_syscall.per_syscall_calls[nr][0][0] = CALLS_OF(nr);
		for (dim = 0; dim < 2; dim++) {
			struct kcov_per_syscall_diag *d =
				&kcov_shm->per_syscall_cmp.per_syscall_diag[nr][dim];

			d->bucket_bits_real = BITS_OF(nr, dim);
			d->distinct_pcs = PCS_OF(nr, dim);
		}
	}
	for (s = 0; s < NR_STRATEGIES; s++) {
		shm->pc_edge_calls_by_strategy[s] = STRAT_CALLS(s);
		shm->pc_edge_count_by_strategy[s] = STRAT_COUNT(s);
	}
}

/* Open fds, not counting the one the scan itself holds. */
static unsigned int count_open_fds(void)
{
	struct dirent *de;
	unsigned int n = 0;
	DIR *d;

	d = opendir("/proc/self/fd");
	if (d == NULL)
		BUG("kcov persist: cannot list /proc/self/fd");
	while ((de = readdir(d)) != NULL)
		if (de->d_name[0] != '.')
			n++;
	closedir(d);
	return n - 1;
}

/* Remove the tmp files a save left in @dir, and say how many there were. */
static unsigned int remove_tmp_files(const char *dir)
{
	char path[PATH_MAX];
	struct dirent *de;
	unsigned int n = 0;
	DIR *d;

	d = opendir(dir);
	if (d == NULL)
		BUG("kcov persist: cannot list the test directory");
	while ((de = readdir(d)) != NULL) {
		if (strstr(de->d_name, ".tmp.") == NULL)
			continue;
		snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
		unlink(path);
		n++;
	}
	closedir(d);
	return n;
}

static void flip_byte(const char *path, size_t off)
{
	unsigned char b;
	int fd;

	fd = open(path, O_RDWR);
	if (fd < 0 || pread(fd, &b, 1, (off_t) off) != 1)
		BUG("kcov persist: cannot read a test file byte");
	b ^= 0xff;
	if (pwrite(fd, &b, 1, (off_t) off) != 1)
		BUG("kcov persist: cannot damage a test file");
	close(fd);
}

/* CRC and length of a whole file, to tell that a failed save left the
 * cache it was replacing alone. */
static uint32_t file_crc(const char *path, size_t *len)
{
	unsigned char *buf;
	uint32_t crc;
	ssize_t n;
	int fd;

	buf = malloc(FILE_SIZE + 1);
	fd = open(path, O_RDONLY);
	if (buf == NULL || fd < 0)
		BUG("kcov persist: cannot read a cache back");
	n = read_all(fd, buf, FILE_SIZE + 1);
	close(fd);
	if (n < 0)
		BUG("kcov persist: cannot read a cache back");
	crc = crc32(buf, (size_t) n);
	*len = (size_t) n;
	free(buf);
	return crc;
}

/* Rewrite the saved file @img as a writer with @sc's version and slot
 * count would have laid it out.  The blocks of another slot count are
 * filler: a loader that reads them is told so by the CRC.  A header-only
 * scenario keeps the saved blocks and changes just the count the header
 * claims. */
static void write_variant(const char *path, const unsigned char *img,
			  const struct scenario *sc)
{
	const uint32_t slots = sc->header_only ? MAX_NR_SYSCALL : sc->file_max;
	const unsigned char *priors = img + PRIORS_OFF;
	const unsigned char *diag = img + DIAG_OFF;
	unsigned char strat[STRAT_SIZE];
	unsigned char *filler = NULL;
	struct file_header hdr;
	struct iovec iov[7];
	size_t total = 0;
	unsigned int n = 0, i;
	int fd;

	memcpy(&hdr, img + ENVELOPE_SIZE, sizeof(hdr));
	hdr.version = sc->version;
	hdr.max_nr_syscall = sc->file_max;
	if (sc->version < 6)
		hdr.diag_crc32 = 0;

	memcpy(strat, img + STRAT_OFF, sizeof(strat));
	if (sc->corrupt_strat)
		strat[0] ^= 0xff;

	if (slots != MAX_NR_SYSCALL) {
		filler = malloc(PRIORS_SIZE(slots) + DIAG_SIZE(slots));
		if (filler == NULL)
			BUG("kcov persist: malloc failed");
		memset(filler, 0xa5, PRIORS_SIZE(slots) + DIAG_SIZE(slots));
		priors = filler;
		diag = filler + PRIORS_SIZE(slots);
	}

	iov[n++] = (struct iovec){ (void *) img, ENVELOPE_SIZE };
	iov[n++] = (struct iovec){ &hdr,
				   sc->version >= 7 ? sizeof(hdr) : HDR_V6_SIZE };
	iov[n++] = (struct iovec){ (void *) (img + BITMAP_OFF), KCOV_NUM_EDGES };
	iov[n++] = (struct iovec){ (void *) priors, PRIORS_SIZE(slots) };
	if (sc->version >= 6)
		iov[n++] = (struct iovec){ (void *) diag, DIAG_SIZE(slots) };
	if (sc->version >= 7)
		iov[n++] = (struct iovec){ strat, sizeof(strat) };
	for (i = 0; i < n; i++)
		total += iov[i].iov_len;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0 || writev(fd, iov, n) != (ssize_t) total)
		BUG("kcov persist: cannot write a test file");
	close(fd);
	free(filler);

	if (sc->cut != 0 && truncate(path, (off_t) sc->cut) != 0)
		BUG("kcov persist: cannot cut a test file");
	if (sc->flip != 0)
		flip_byte(path, sc->flip);
}

/* Each block is back whole or not at all, as the scenario says. */
static void check_blocks(const struct scenario *sc)
{
	bool priors_ok = true, diag_ok = true, strat_ok = true;
	unsigned int i, dim, s;

	for (i = 0; i < ARRAY_SIZE(sample_nr); i++) {
		unsigned int nr = sample_nr[i];

		if (kcov_shm->per_syscall.per_syscall_edges_prior[nr][0] !=
			    (sc->priors ? EDGES_OF(nr) : 0) ||
		    kcov_shm->per_syscall.per_syscall_calls_prior[nr][0] !=
			    (sc->priors ? CALLS_OF(nr) : 0))
			priors_ok = false;
		for (dim = 0; dim < 2; dim++) {
			struct kcov_per_syscall_diag *d =
				&kcov_shm->per_syscall_cmp.per_syscall_diag[nr][dim];

			if (d->bucket_bits_real !=
				    (sc->diag ? BITS_OF(nr, dim) : 0) ||
			    d->distinct_pcs !=
				    (sc->diag ? PCS_OF(nr, dim) : 0))
				diag_ok = false;
		}
	}
	for (s = 0; s < NR_STRATEGIES; s++) {
		if (shm->pc_edge_calls_by_strategy[s] !=
			    (sc->strat ? STRAT_CALLS(s) : 0) ||
		    shm->pc_edge_count_by_strategy[s] !=
			    (sc->strat ? STRAT_COUNT(s) : 0))
			strat_ok = false;
	}

	expect(priors_ok, sc->name, sc->priors ? "priors block not restored" :
					   "priors block restored, not skipped");
	expect(diag_ok, sc->name, sc->diag ? "diag block not restored" :
				       "diag block restored, not skipped");
	expect(strat_ok, sc->name, sc->strat ? "strat block not restored" :
					 "strat block restored, not refused");
}

static void run_scenario(const struct scenario *sc, const unsigned char *img,
			 const char *path)
{
	unsigned int before = failures;
	unsigned int fds;
	unsigned int i;
	bool loaded;

	write_variant(path, img, sc);
	reset_state();
	fake_output_log[0] = '\0';
	malloc_fail_size = sc->fail_malloc;
	lseek_fail_nth = sc->fail_lseek;
	fds = count_open_fds();
	close_calls = 0;
	loaded = kcov_bitmap_load_file(path);
	/* A failure the loader never reached would leave the scenario
	 * testing nothing. */
	expect(malloc_fail_size == 0 && lseek_fail_nth == 0, sc->name,
	       "the armed failure never happened");
	malloc_fail_size = 0;
	lseek_fail_nth = 0;

	/* The loader opened one fd, and closed it whatever came of the file. */
	expect(close_calls == 1, sc->name,
	       "the loader did not close its fd exactly once");
	expect(count_open_fds() == fds, sc->name, "the loader left an fd open");

	if (sc->refused) {
		/* Nothing is published until the whole bitmap checks out. */
		expect(!loaded && kcov_shm->coverage.edges_found == 0 &&
		       kcov_shm->bucket_seen[100] == 0 &&
		       kcov_shm->bucket_seen[200000] == 0 &&
		       kcov_shm->bucket_seen[KCOV_NUM_EDGES - 1] == 0,
		       sc->name, "a refused file was loaded");
	} else {
		/* The bitmap is committed before any soft block is looked at. */
		expect(loaded && kcov_shm->coverage.edges_found == SAMPLE_EDGES &&
		       kcov_shm->coverage.distinct_edges == SAMPLE_DISTINCT,
		       sc->name, "bitmap not loaded");
	}
	check_blocks(sc);
	expect(strstr(fake_output_log, sc->log_has) != NULL ||
	       (sc->log_or != NULL &&
		strstr(fake_output_log, sc->log_or) != NULL), sc->name,
	       "the log does not name what happened");
	for (i = 0; i < ARRAY_SIZE(complaints); i++)
		expect(strstr(sc->log_has, complaints[i]) != NULL ||
		       strstr(fake_output_log, complaints[i]) == NULL,
		       sc->name, "the log blames a block that was fine");
	if (failures != before)
		fprintf(stderr, "\n    loader log:\n%s", fake_output_log);
}

/* What can be wrong with a save that was meant to fail, as bits so a
 * forked child can report them in its exit status. */
#define SAVE_RETURNED_TRUE	(1u << 0)
#define SAVE_CLOSE_COUNT	(1u << 1)
#define SAVE_FD_LEAK		(1u << 2)
#define SAVE_TMP_LEFT		(1u << 3)
#define SAVE_NO_LIMIT		(1u << 4)

/* Save to @path from a fresh state, which must fail having closed its tmp
 * fd @closes times (none when the tmp file never opened), leaked no fd
 * and left no tmp file in @dir. */
static unsigned int save_problems(const char *dir, const char *path,
				  unsigned int closes)
{
	unsigned int problems = 0;
	unsigned int fds;
	bool saved;

	reset_state();
	fill_state();
	kcov_shm->coverage.edges_found = SAMPLE_EDGES + 1;
	fds = count_open_fds();
	close_calls = 0;
	saved = kcov_bitmap_save_file(path);
	if (saved)
		problems |= SAVE_RETURNED_TRUE;
	if (close_calls != closes)
		problems |= SAVE_CLOSE_COUNT;
	if (count_open_fds() != fds)
		problems |= SAVE_FD_LEAK;
	if (remove_tmp_files(dir) != 0)
		problems |= SAVE_TMP_LEFT;
	return problems;
}

static void expect_save_failed(unsigned int problems, const char *name)
{
	expect(!(problems & SAVE_RETURNED_TRUE), name, "the save returned true");
	expect(!(problems & SAVE_CLOSE_COUNT), name,
	       "the save did not close its tmp fd the expected number of times");
	expect(!(problems & SAVE_FD_LEAK), name, "the save left an fd open");
	expect(!(problems & SAVE_TMP_LEFT), name,
	       "the save left a tmp file behind");
	expect(!(problems & SAVE_NO_LIMIT), name,
	       "the child could not lower RLIMIT_FSIZE");
}

static void check_save_failures(const char *dir)
{
	char path[PATH_MAX];
	size_t len, len_after;
	uint32_t crc;
	int status;
	pid_t pid;

	/* The tmp file cannot be opened: there is no fd to close. */
	snprintf(path, sizeof(path), "%s/nodir/cache", dir);
	expect_save_failed(save_problems(dir, path, 0),
			   "save into a missing directory");

	/* The rename onto a directory fails after the tmp fd closed. */
	snprintf(path, sizeof(path), "%s/cache", dir);
	if (mkdir(path, 0700) != 0)
		BUG("kcov persist: cannot make a directory to save over");
	expect_save_failed(save_problems(dir, path, 1),
			   "save over a directory");
	if (rmdir(path) != 0)
		BUG("kcov persist: cannot remove the directory to save over");

	/* A write that runs into RLIMIT_FSIZE fails.  Lower the limit in a
	 * child, so it stays out of this process, and save over a cache
	 * that is already there: it must come through as it was. */
	snprintf(path, sizeof(path), "%s/kept", dir);
	reset_state();
	fill_state();
	kcov_shm->coverage.edges_found = SAMPLE_EDGES + 2;
	if (!kcov_bitmap_save_file(path))
		BUG("kcov persist: cannot write a cache to keep");
	crc = file_crc(path, &len);

	pid = fork();
	if (pid < 0)
		BUG("kcov persist: fork failed");
	if (pid == 0) {
		struct rlimit rl = { .rlim_cur = 4096, .rlim_max = 4096 };

		/* The write that crosses the limit raises SIGXFSZ unless it
		 * is ignored, and then fails with EFBIG. */
		signal(SIGXFSZ, SIG_IGN);
		if (setrlimit(RLIMIT_FSIZE, &rl) != 0)
			_exit(SAVE_NO_LIMIT);
		_exit(save_problems(dir, path, 1));
	}
	if (waitpid_eintr(pid, &status, 0) != pid || !WIFEXITED(status))
		BUG("kcov persist: the limited save did not exit");
	expect_save_failed(WEXITSTATUS(status), "save past RLIMIT_FSIZE");
	expect(file_crc(path, &len_after) == crc && len_after == len,
	       "save past RLIMIT_FSIZE",
	       "the failed save changed the cache it was replacing");
	if (unlink(path) != 0)
		BUG("kcov persist: cannot remove the kept cache");
}

/* edges_found values a refused or good snapshot is driven with.  The fill
 * state's bitmap holds SAMPLE_EDGES set bits, so anything this far above
 * that is a deficit the save refuses; a value just above it saves. */
static unsigned long snap_edges;
static unsigned long good_edges = SAMPLE_EDGES + 3;

static bool exit_requested(void)
{
	return __atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) ==
	       EXIT_SHM_CORRUPTION;
}

/* A snapshot tick with enough new edges to be due, over a bitmap that
 * holds far fewer bits than edges_found claims. */
static void refused_snapshot_tick(void)
{
	snap_edges += KCOV_BITMAP_SNAPSHOT_EDGES;
	kcov_shm->coverage.edges_found = snap_edges;
	kcov_bitmap_maybe_snapshot();
}

/* A save that goes through, which clears the refusal count. */
static void good_save(const char *path)
{
	kcov_shm->coverage.edges_found = good_edges++;
	if (!kcov_bitmap_save_file(path))
		BUG("kcov persist: a save of a consistent bitmap failed");
}

static void check_refusal_pacing(const char *dir)
{
	char path[PATH_MAX];
	unsigned int i;

	snprintf(path, sizeof(path), "%s/paced", dir);
	reset_state();
	fill_state();
	kcov_bitmap_enable_snapshots(path);
	__atomic_store_n(&shm->exit_reason, STILL_RUNNING, __ATOMIC_RELAXED);

	/* The count is of refusals in a row: a good save between two
	 * refusals starts it again, so they never reach the cap together. */
	good_save(path);
	for (i = 0; i < KCOV_BITMAP_PERSIST_REFUSAL_EXIT_CAP - 1; i++)
		refused_snapshot_tick();
	good_save(path);
	refused_snapshot_tick();
	expect(!exit_requested(), "refusal cap",
	       "refusals either side of a good save were counted together");

	/* A refused snapshot is not retried on every tick: ticks with no new
	 * edges and no elapsed interval must not reach the save again, or
	 * the cap is spent in a moment. */
	good_save(path);
	refused_snapshot_tick();
	for (i = 0; i < 2 * KCOV_BITMAP_PERSIST_REFUSAL_EXIT_CAP; i++)
		kcov_bitmap_maybe_snapshot();
	expect(!exit_requested(), "refusal pacing",
	       "ticks with no new edges re-ran a refused snapshot");

	/* Refusals that are each due do reach the cap and stop the run. */
	for (i = 2; i < KCOV_BITMAP_PERSIST_REFUSAL_EXIT_CAP; i++)
		refused_snapshot_tick();
	expect(!exit_requested(), "refusal cap",
	       "the run stopped before the cap of refused snapshots");
	refused_snapshot_tick();
	expect(exit_requested(), "refusal cap",
	       "the run did not stop at the cap of refused snapshots");

	if (unlink(path) != 0)
		BUG("kcov persist: cannot remove the paced cache");
}

void kcov_persist_self_check(void);
void kcov_persist_self_check(void)
{
	char dir[] = "/tmp/trinity-kcov-persist-test.XXXXXX";
	char base[sizeof(dir) + sizeof("/base")];
	char variant[sizeof(dir) + sizeof("/variant")];
	unsigned char *img;
	struct stat st;
	uint8_t fp[32];
	unsigned int fds;
	unsigned int i;
	int fd;

	/* Without a kernel fingerprint the loader refuses every file, so
	 * there is nothing to test. */
	if (!kcov_get_kernel_fp(fp)) {
		printf("(SKIP: no /proc/kallsyms to fingerprint the kernel, "
		       "the loader scenarios did not run) ");
		return;
	}
	if (mkdtemp(dir) == NULL)
		BUG("kcov persist: mkdtemp failed");
	snprintf(base, sizeof(base), "%s/base", dir);
	snprintf(variant, sizeof(variant), "%s/variant", dir);

	reset_state();
	fill_state();
	fds = count_open_fds();
	close_calls = 0;
	if (!kcov_bitmap_save_file(base))
		BUG("kcov persist: saving the bitmap failed");
	expect(close_calls == 1 && count_open_fds() == fds &&
	       remove_tmp_files(dir) == 0, "save",
	       "a good save must close its tmp fd once and leave no tmp file");

	fd = open(base, O_RDONLY);
	if (fd < 0 || fstat(fd, &st) != 0 || st.st_size != (off_t) FILE_SIZE)
		BUG("kcov persist: the saved file is not laid out as expected");
	img = malloc(FILE_SIZE);
	if (img == NULL || read_all(fd, img, FILE_SIZE) != (ssize_t) FILE_SIZE)
		BUG("kcov persist: cannot read the saved file");
	close(fd);

	for (i = 0; i < ARRAY_SIZE(scenarios); i++)
		run_scenario(&scenarios[i], img, variant);
	check_save_failures(dir);
	check_refusal_pacing(dir);

	free(img);
	free(kcov_shm);
	kcov_shm = NULL;
	/* Leave the strategy counters zero for the tests after this one. */
	memset(shm->pc_edge_calls_by_strategy, 0,
	       sizeof(shm->pc_edge_calls_by_strategy));
	memset(shm->pc_edge_count_by_strategy, 0,
	       sizeof(shm->pc_edge_count_by_strategy));
	if (unlink(variant) != 0 || unlink(base) != 0 || rmdir(dir) != 0)
		BUG("kcov persist: cleanup failed");
	if (failures != 0)
		BUG("kcov persist: the loader misread a block layout");
}
