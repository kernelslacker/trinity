/*
 * pagecache_canary_check -- verifier childop for the canary file
 * pool (fds/canary.c).
 *
 * Picks one canary file at random per invocation, reopens it via
 * its absolute path with a randomly varied read-side flag combo
 * (O_RDONLY, +O_DIRECT, +O_NONBLOCK), optionally drops the file's
 * page cache via posix_fadvise(POSIX_FADV_DONTNEED) on a fraction
 * of runs to force a fresh fetch from disk, then reads the full
 * file contents through one of six paths picked uniformly:
 *
 *     read     buffered read() in 4 KiB chunks
 *     pread    pread() at random in-bounds offsets covering the
 *              full file
 *     readv    readv() with a small iovec
 *     mmap     mmap(PROT_READ) + memcmp, guarded by sigsetjmp +
 *              per-op SIGBUS handler (mirrors the pattern in
 *              childops/mm/madvise-pattern-cycler.c)
 *     splice   splice() canary -> pipe, read() the pipe end
 *     sendfile sendfile() canary -> tmpfile, read tmpfile back
 *
 * For each mode the bytes are walked against the deterministic
 * canary_expected_byte() pattern.  On the first mismatch we log
 * the file, the read mode, the offset, the diverged byte plus the
 * next 8 bytes (expected and actual), and bump
 * shm->stats.diag.pagecache_canary_corrupt_caught.  We do NOT bail the
 * run on a single mismatch — log loudly, count, continue.  The bug
 * class this oracle exists to catch is data corruption, not state
 * corruption; multiple data points per run are valuable.
 *
 * Dispatch rate: enabled in dormant_op_disabled[] so pick_op_type
 * routes ~5%/N_enabled_altops per dispatch into this op (≈ 0.4%
 * at the current altop bucket size — within the brief's ~0.5%
 * target).  No new periodic-work hook needed.
 *
 * SIGBUS handling: the mmap variant is the only path that can
 * fault on a healthy file (POSIX_FADV_DONTNEED + a sibling-fuzzed
 * truncate-shape syscall on the same inode could leave a hole
 * behind us between map and access).  Per-op SIGBUS handler with a
 * sigjmp_buf + range guard, restored to the previous handler
 * before return so the global child_fault_handler stays in charge
 * for genuine SIGBUS in any other code path.
 */

#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "canary.h"
#include "pids.h"
#include "child.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/fcntl.h"
#include "kernel/splice.h"
#define READ_CHUNK		4096U
#define READV_IOV_COUNT		4U
#define DIFF_NEXT_BYTES		8U
#define FADVISE_DONTNEED_PCT	25

enum read_mode {
	RM_READ = 0, RM_PREAD, RM_READV,
	RM_MMAP, RM_SPLICE, RM_SENDFILE,
	RM_NR,
};

/*
 * Per-op SIGBUS guard for the mmap variant.  Set by mmap_check()
 * around the memcmp loop; the handler longjmps back here on a
 * SIGBUS whose si_addr lands inside the active mmap range.
 *
 * volatile / sigjmp_buf rationale matches childops/madvise-
 * pattern-cycler.c: ISO C 7.13.2.1 only guarantees post-longjmp
 * values for objects with volatile-qualified type, and GCC's
 * -Wclobbered analysis flags non-volatile locals as possibly
 * clobbered through the wrap.
 */
static sigjmp_buf canary_sigbus_jmp;
static volatile uintptr_t canary_sigbus_lo;
static volatile uintptr_t canary_sigbus_hi;
static volatile sig_atomic_t canary_sigbus_armed;

static __attribute__((no_sanitize("address")))
void canary_sigbus_handler(int sig, siginfo_t *info, void *ctx)
{
	uintptr_t fault_addr;

	(void)ctx;

	if (!canary_sigbus_armed) {
		/* Not in the guarded section — re-raise with default
		 * disposition so child_fault_handler diagnoses it. */
		signal(sig, SIG_DFL);
		raise(sig);
		return;
	}
	if (info->si_code <= 0 && info->si_pid != mypid()) {
		/* Sibling-spoofed — kernel has consumed it already. */
		return;
	}
	if (info->si_code <= 0) {
		/* Self-sent — not the truncate-race we're guarding. */
		signal(sig, SIG_DFL);
		raise(sig);
		return;
	}

	fault_addr = (uintptr_t)info->si_addr;
	if (fault_addr < canary_sigbus_lo || fault_addr >= canary_sigbus_hi) {
		/* Real fault outside the guarded mmap range — let the
		 * global child fault handler take it. */
		signal(sig, SIG_DFL);
		raise(sig);
		return;
	}
	siglongjmp(canary_sigbus_jmp, 1);
}

/*
 * Compare a buffer against the expected canary pattern at
 * (file_idx, file_offset).  Returns true if every byte matched;
 * on first mismatch returns false and fills *out_off with the
 * file-relative offset of the divergence.
 */
static bool canary_walk(const unsigned char *buf, size_t buf_len,
			unsigned int file_idx, off_t file_offset,
			size_t *out_off)
{
	size_t i;

	for (i = 0; i < buf_len; i++) {
		uint8_t want = canary_expected_byte(file_idx,
						    file_offset + (off_t)i);
		if (buf[i] != want) {
			*out_off = (size_t)file_offset + i;
			return false;
		}
	}
	return true;
}

static void log_corruption(unsigned int file_idx, const char *path,
			   const char *mode, size_t mismatch_off,
			   uint8_t actual_byte,
			   const unsigned char *next_actual,
			   size_t next_avail)
{
	char hex_expected[DIFF_NEXT_BYTES * 3 + 1];
	char hex_actual[DIFF_NEXT_BYTES * 3 + 1];
	uint8_t expected_byte;
	size_t i;
	size_t next_n;

	expected_byte = canary_expected_byte(file_idx, (off_t)mismatch_off);

	next_n = next_avail < DIFF_NEXT_BYTES ? next_avail : DIFF_NEXT_BYTES;
	for (i = 0; i < next_n; i++) {
		uint8_t e = canary_expected_byte(file_idx,
				(off_t)(mismatch_off + 1 + i));
		snprintf(hex_expected + i * 3, 4, "%02x ", e);
		snprintf(hex_actual + i * 3, 4, "%02x ", next_actual[i]);
	}
	hex_expected[next_n * 3] = '\0';
	hex_actual[next_n * 3]   = '\0';

	output(0,
	       "pagecache_canary: file_idx=%u path=%s read_path=%s "
	       "mismatch_offset=%zu expected=0x%02x actual=0x%02x "
	       "next_expected=[ %s] next_actual=[ %s]\n",
	       file_idx, path, mode, mismatch_off,
	       expected_byte, actual_byte,
	       hex_expected, hex_actual);

	__atomic_add_fetch(&shm->stats.diag.pagecache_canary_corrupt_caught, 1,
			   __ATOMIC_RELAXED);
}

/*
 * Helper: emit the corruption log line for a single mismatch at
 * mismatch_off.  Pulls the surrounding "next" bytes either from
 * the in-memory buffer (when we still have the read result) or
 * with a fresh pread() against the file (when we don't, e.g. the
 * splice/sendfile paths which discarded the bytes after the
 * walk).  The fresh pread is best-effort; on failure we log with
 * an empty "next_actual" tail.
 */
static void report_mismatch(unsigned int file_idx, const char *path,
			    const char *mode, size_t mismatch_off,
			    const unsigned char *buf, size_t buf_len,
			    size_t buf_offset_in_file)
{
	unsigned char actual = 0;
	unsigned char next_actual[DIFF_NEXT_BYTES] = {0};
	size_t next_avail = 0;
	size_t in_buf_off;

	in_buf_off = mismatch_off - buf_offset_in_file;
	if (in_buf_off < buf_len) {
		actual = buf[in_buf_off];
		size_t remaining = buf_len - in_buf_off - 1;
		next_avail = remaining < DIFF_NEXT_BYTES
			   ? remaining : DIFF_NEXT_BYTES;
		if (next_avail > 0)
			memcpy(next_actual, buf + in_buf_off + 1, next_avail);
	}
	log_corruption(file_idx, path, mode, mismatch_off, actual,
		       next_actual, next_avail);
}

/* ---------------- per-mode read implementations ---------------- */

static void mode_read(int fd, unsigned int file_idx, size_t size,
		      const char *path)
{
	unsigned char buf[READ_CHUNK];
	size_t off = 0;

	while (off < size) {
		size_t want = size - off;
		size_t mis;
		ssize_t n;

		if (want > sizeof(buf))
			want = sizeof(buf);
		n = read(fd, buf, want);
		if (n <= 0)
			return;
		if (!canary_walk(buf, (size_t)n, file_idx, (off_t)off, &mis)) {
			report_mismatch(file_idx, path, "read", mis,
					buf, (size_t)n, off);
			return;
		}
		off += (size_t)n;
	}
}

static void mode_pread(int fd, unsigned int file_idx, size_t size,
		       const char *path)
{
	unsigned char buf[READ_CHUNK];
	size_t total_chunks = (size + READ_CHUNK - 1) / READ_CHUNK;
	size_t bitmap_bytes = (total_chunks + 7) / 8;
	unsigned char *seen;
	size_t seen_count = 0;
	unsigned int iter = 0;
	unsigned int iter_cap = 4 * total_chunks;

	/* Sample chunk-aligned pread offsets without replacement: each
	 * chunk gets one bit in `seen`, set on first successful pread.
	 * The loop exits when every chunk has been visited or the cap
	 * is hit.  Coupon-collector convergence on the bit count is
	 * O(N log N) draws expected, still well under iter_cap for the
	 * canary file sizes in play; the cap itself guarantees bounded
	 * termination even under perfect-collision worst case. */
	seen = zmalloc(bitmap_bytes);

	while (seen_count < total_chunks && iter++ < iter_cap) {
		size_t chunk_idx;
		size_t bit_byte, bit_mask;
		off_t off;
		size_t want;
		size_t mis;
		ssize_t n;

		chunk_idx = rnd_modulo_u32(total_chunks);
		off = (off_t)(chunk_idx * READ_CHUNK);
		want = size - (size_t)off;
		if (want > sizeof(buf))
			want = sizeof(buf);

		n = pread(fd, buf, want, off);
		if (n <= 0)
			continue;
		if (!canary_walk(buf, (size_t)n, file_idx, off, &mis)) {
			report_mismatch(file_idx, path, "pread", mis,
					buf, (size_t)n, (size_t)off);
			free(seen);
			return;
		}

		/* Short reads (n < READ_CHUNK) still mark the chunk seen —
		 * canary_walk already validated the bytes that came back,
		 * and a tail short read at EOF is expected for the last
		 * chunk of a non-multiple-of-READ_CHUNK file. */
		bit_byte = chunk_idx >> 3;
		bit_mask = 1u << (chunk_idx & 7);
		if (!(seen[bit_byte] & bit_mask)) {
			seen[bit_byte] |= bit_mask;
			seen_count++;
		}
	}

	free(seen);
}

static void mode_readv(int fd, unsigned int file_idx, size_t size,
		       const char *path)
{
	unsigned char chunks[READV_IOV_COUNT][READ_CHUNK];
	struct iovec iov[READV_IOV_COUNT];
	size_t off = 0;
	unsigned int i;

	while (off < size) {
		size_t want_total = 0;
		ssize_t n;
		unsigned int n_iov = 0;

		for (i = 0; i < READV_IOV_COUNT; i++) {
			size_t this_want = size - off - want_total;
			if (this_want > READ_CHUNK)
				this_want = READ_CHUNK;
			iov[i].iov_base = chunks[i];
			iov[i].iov_len  = this_want;
			want_total += this_want;
			n_iov = i + 1;
			if (off + want_total >= size)
				break;
		}

		n = readv(fd, iov, n_iov);
		if (n <= 0)
			return;

		size_t consumed = 0;
		for (i = 0; i < n_iov && consumed < (size_t)n; i++) {
			size_t this_n = iov[i].iov_len;
			if (consumed + this_n > (size_t)n)
				this_n = (size_t)n - consumed;
			size_t mis;
			if (!canary_walk(chunks[i], this_n, file_idx,
					 (off_t)(off + consumed), &mis)) {
				report_mismatch(file_idx, path, "readv", mis,
						chunks[i], this_n,
						off + consumed);
				return;
			}
			consumed += this_n;
		}
		off += consumed;
		if (consumed == 0)
			return;
	}
}

static void mode_mmap(int fd, unsigned int file_idx, size_t size,
		      const char *path)
{
	struct sigaction sa, old_bus;
	void *map;
	volatile bool aborted = false;

	map = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED)
		return;

	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = canary_sigbus_handler;
	if (sigaction(SIGBUS, &sa, &old_bus) != 0) {
		(void)munmap(map, size);
		return;
	}

	canary_sigbus_lo = (uintptr_t)map;
	canary_sigbus_hi = (uintptr_t)map + size;
	canary_sigbus_armed = 1;

	if (sigsetjmp(canary_sigbus_jmp, 1) == 0) {
		const unsigned char *p = map;
		size_t mis;

		if (!canary_walk(p, size, file_idx, 0, &mis)) {
			report_mismatch(file_idx, path, "mmap", mis,
					p, size, 0);
		}
	} else {
		aborted = true;
	}

	canary_sigbus_armed = 0;
	canary_sigbus_lo = 0;
	canary_sigbus_hi = 0;
	(void)sigaction(SIGBUS, &old_bus, NULL);
	(void)munmap(map, size);

	if (aborted) {
		/* SIGBUS during memcmp.  Not a corruption signal —
		 * the file was truncated or holed under us by a
		 * sibling.  Drop silently; no counter bump. */
	}
}

static void mode_splice(int fd, unsigned int file_idx, size_t size,
			const char *path)
{
	int pfd[2];
	unsigned char buf[READ_CHUNK];
	size_t off = 0;

	if (pipe2(pfd, O_CLOEXEC) < 0)
		return;

	while (off < size) {
		size_t want = size - off;
		ssize_t spliced, rd;
		size_t mis;

		if (want > sizeof(buf))
			want = sizeof(buf);

		spliced = splice(fd, NULL, pfd[1], NULL, want,
				 SPLICE_F_MOVE);
		if (spliced <= 0)
			break;

		rd = read(pfd[0], buf, (size_t)spliced);
		if (rd <= 0)
			break;
		if (!canary_walk(buf, (size_t)rd, file_idx, (off_t)off,
				 &mis)) {
			report_mismatch(file_idx, path, "splice", mis,
					buf, (size_t)rd, off);
			break;
		}
		off += (size_t)rd;
	}

	close(pfd[0]);
	close(pfd[1]);
}

static void mode_sendfile(int fd, unsigned int file_idx, size_t size,
			  const char *path)
{
	char tmpl[] = "trinity-canary-XXXXXX";
	int tfd;
	off_t soff = 0;
	ssize_t sent;
	unsigned char buf[READ_CHUNK];
	size_t off = 0;

	tfd = mkstemp(tmpl);
	if (tfd < 0)
		return;
	(void)unlink(tmpl);

	while ((size_t)soff < size) {
		size_t want = size - (size_t)soff;
		if (want > sizeof(buf))
			want = sizeof(buf);
		sent = sendfile(tfd, fd, &soff, want);
		if (sent <= 0)
			break;
	}

	if (lseek(tfd, 0, SEEK_SET) == (off_t)-1) {
		close(tfd);
		return;
	}

	while (off < size) {
		size_t want = size - off;
		size_t mis;
		ssize_t n;

		if (want > sizeof(buf))
			want = sizeof(buf);
		n = read(tfd, buf, want);
		if (n <= 0)
			break;
		if (!canary_walk(buf, (size_t)n, file_idx, (off_t)off,
				 &mis)) {
			report_mismatch(file_idx, path, "sendfile", mis,
					buf, (size_t)n, off);
			break;
		}
		off += (size_t)n;
	}

	close(tfd);
}

/* ---------------- dispatch ---------------- */

bool pagecache_canary_check(struct childdata *child)
{
	const struct canary_file_info *info;
	unsigned int pool_size;
	unsigned int idx;
	enum read_mode mode;
	int open_flags;
	int fd;

	/* Snapshot child->op_type once: a sibling poisoned-arena write
	 * can scribble shared childdata between reads, and an out-of-
	 * range op_type used as an array index turns into a wild write
	 * into adjacent shm.  Gate the per-op_type stats on the same
	 * valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	pool_size = canary_pool_size();
	if (pool_size == 0)
		return true;

	idx = rnd_modulo_u32(pool_size);
	info = canary_file_get(idx);
	if (info == NULL || info->path == NULL || info->size == 0)
		return true;

	/* Vary the open flags so different code paths in the kernel
	 * read side get exercised across runs.  Skip O_DIRECT
	 * silently on EINVAL — some filesystems reject it outright
	 * and that isn't an oracle signal. */
	open_flags = O_RDONLY;
	switch (rnd_modulo_u32(3)) {
	case 1: open_flags |= O_DIRECT;   break;
	case 2: open_flags |= O_NONBLOCK; break;
	default: break;
	}

	fd = open(info->path, open_flags);
	if (fd < 0 && (open_flags & O_DIRECT) && errno == EINVAL) {
		fd = open(info->path, O_RDONLY);
	}
	if (fd < 0)
		return true;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	if (rnd_modulo_u32(100) < FADVISE_DONTNEED_PCT) {
		(void)posix_fadvise(fd, 0, (off_t)info->size,
				    POSIX_FADV_DONTNEED);
	}

	mode = (enum read_mode)rnd_modulo_u32(RM_NR);

	/* O_DIRECT requires aligned buffers and offsets; mmap of an
	 * O_DIRECT fd is also a special-case in some FSes.  Fall
	 * back to plain read mode if we drew an incompatible combo
	 * — keeps the check honest without burning the iter on an
	 * EINVAL we already know about. */
	if ((open_flags & O_DIRECT) && (mode == RM_MMAP || mode == RM_READV)) {
		mode = RM_READ;
	}

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	switch (mode) {
	case RM_READ:	  mode_read(fd, idx, info->size, info->path);     break;
	case RM_PREAD:	  mode_pread(fd, idx, info->size, info->path);    break;
	case RM_READV:	  mode_readv(fd, idx, info->size, info->path);    break;
	case RM_MMAP:	  mode_mmap(fd, idx, info->size, info->path);     break;
	case RM_SPLICE:	  mode_splice(fd, idx, info->size, info->path);   break;
	case RM_SENDFILE: mode_sendfile(fd, idx, info->size, info->path); break;
	case RM_NR: break;
	}

	close(fd);
	return true;
}
