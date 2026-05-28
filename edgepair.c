/*
 * Edge-pair tracking: (prev_syscall, curr_syscall) -> coverage data.
 *
 * Open-addressed hash table.  Post-retrofit the canonical lives in
 * parent-private struct edgepair_aggregate (parent_edgepair in
 * edgepair-ring.c), fed by per-child SPSC observation rings drained
 * each main_loop iteration.  Children publish their (prev, curr,
 * new_edges) observations into their own edgepair_ring; the parent
 * applies them serially under single-writer discipline, no CAS, no
 * packed-key layout pin.
 *
 * Child-side readers (edgepair_state / edgepair_is_cold on the
 * syscall-selection biasing path, edgepair_get_stats on the
 * never-seen-pair accept and bandit reward dampening paths) consult
 * the parent-published mirror page (edgepair_published), refreshed at
 * every drain.  Parent-side consumers (dump, stats display) read the
 * canonical aggregate directly.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "arch.h"
#include "child.h"
#include "edgepair.h"
#include "edgepair_ring.h"
#include "kcov.h"
#include "trinity.h"

static bool edgepair_enabled;

bool edgepair_is_enabled(void)
{
	return edgepair_enabled;
}

void edgepair_init_global(void)
{
	edgepair_enabled = true;

	output(0, "KCOV: edge-pair tracking enabled (%lu KB canonical, %u slots)\n",
		sizeof(parent_edgepair.table) / 1024,
		EDGEPAIR_TABLE_SIZE);
}

void edgepair_record(struct childdata *child,
		     unsigned int prev_nr, unsigned int curr_nr,
		     bool found_new)
{
	if (!edgepair_enabled)
		return;

	if (child == NULL || child->edgepair_ring == NULL)
		return;

	if (prev_nr >= MAX_NR_SYSCALL || curr_nr >= MAX_NR_SYSCALL)
		return;

	/* Drop on ring overflow: parent_edgepair.ring_overflow_total
	 * already conveys "we lost samples".  Blocking a child on an
	 * observer enqueue is the wrong tradeoff for a syscall-prior
	 * bias; at worst the cold-pair detector takes one more drain to
	 * notice a productive pair just went cold. */
	(void)edgepair_ring_enqueue(child->edgepair_ring,
				    prev_nr, curr_nr, found_new);
}

enum edgepair_pair_state edgepair_state(unsigned int prev_nr,
					unsigned int curr_nr)
{
	unsigned int idx;
	unsigned int probe;

	if (!edgepair_enabled || edgepair_published == NULL)
		return EDGEPAIR_STATE_UNSEEN;

	idx = edgepair_pair_hash(prev_nr, curr_nr);
	for (probe = 0; probe < EDGEPAIR_MAX_PROBE; probe++) {
		const struct edgepair_published_slot *e =
			&edgepair_published->slots[idx];
		unsigned long total, last;

		if (e->prev_nr == EDGEPAIR_EMPTY)
			return EDGEPAIR_STATE_UNSEEN;
		if (e->prev_nr != prev_nr || e->curr_nr != curr_nr) {
			idx = (idx + 1) & EDGEPAIR_TABLE_MASK;
			continue;
		}

		/* Present in the mirror -- pair was inserted, so it has
		 * been executed at least once.  Branch on whether it ever
		 * produced a new edge and, if so, how long ago. */
		if (e->new_edge_count == 0)
			return EDGEPAIR_STATE_SEEN_UNPRODUCTIVE;

		/* Acquire-load pairs with the release-store in
		 * edgepair_publish_locked() so the subsequent last_new_at
		 * read sees the matching slot update for this publish
		 * window.  Plain MOV on x86-64. */
		total = __atomic_load_n(&edgepair_published->total_pair_calls,
					__ATOMIC_ACQUIRE);
		last = e->last_new_at;
		/* A publisher racing us can update this slot's last_new_at
		 * to the NEXT total *after* our acquire-load above, so
		 * last > total is possible and means the pair just
		 * produced new edges -- treat as fresh.  Without this
		 * guard, total - last underflows and falsely trips cold. */
		if (last >= total)
			return EDGEPAIR_STATE_PRODUCTIVE_FRESH;
		if ((total - last) > EDGEPAIR_COLD_THRESHOLD)
			return EDGEPAIR_STATE_PRODUCTIVE_COLD;
		return EDGEPAIR_STATE_PRODUCTIVE_FRESH;
	}

	return EDGEPAIR_STATE_UNSEEN;
}

bool edgepair_is_cold(unsigned int prev_nr, unsigned int curr_nr)
{
	return edgepair_state(prev_nr, curr_nr) == EDGEPAIR_STATE_PRODUCTIVE_COLD;
}

bool edgepair_entry_is_cold_parent(const struct edgepair_entry *e)
{
	unsigned long total, last;

	if (!edgepair_enabled || e == NULL)
		return false;

	/* Never found new edges -- not cold, just unproductive. */
	if (e->new_edge_count == 0)
		return false;

	/* Parent-canonical cold predicate: walk the same math as
	 * edgepair_is_cold() but read parent_edgepair.table[] /
	 * parent_edgepair.total_pair_calls directly rather than the
	 * child-RO published mirror.  Parent is the sole writer of both
	 * (see include/edgepair_ring.h aggregate comment) so plain reads
	 * are safe; the stats walkers that consult this predicate are
	 * already iterating parent_edgepair.table[] entries, and the
	 * mirror can lag or briefly disagree with the canonical entry
	 * the surrounding stats code is about to print. */
	total = parent_edgepair.total_pair_calls;
	last = e->last_new_at;
	if (last >= total)
		return false;
	return (total - last) > EDGEPAIR_COLD_THRESHOLD;
}

/*
 * Read the (new_edges, total) counters for a (prev, curr) pair from
 * the child-RO published mirror.  Safe to call from child context: the
 * mirror is the parent's published snapshot, refreshed by
 * edgepair_publish_locked() at every drain, so children see the
 * parent's current aggregate instead of the fork-time / warm-start
 * COW copy of parent_edgepair.table[] that lives frozen in their
 * address space.
 *
 * Staleness: the returned counters lag the parent's canonical
 * aggregate by at most one publish interval (publish-driven, not
 * per-call) -- a strict improvement over the fork-time / warm-start
 * staleness the canonical-read path leaves in child address space.
 *
 * Returns the {0, 0} sentinel on disabled, out-of-range, mirror not
 * yet populated, or pair absent.  No parent-side caller exists today;
 * a future parent-side reader that needs the canonical (non-published)
 * counters can walk parent_edgepair.table[] directly the way
 * edgepair_lookup() does.
 */
struct edgepair_stats edgepair_get_stats(unsigned int prev_nr,
					 unsigned int curr_nr)
{
	struct edgepair_stats s = { 0, 0 };
	unsigned int idx;
	unsigned int probe;

	if (!edgepair_enabled || edgepair_published == NULL)
		return s;

	if (prev_nr >= MAX_NR_SYSCALL || curr_nr >= MAX_NR_SYSCALL)
		return s;

	idx = edgepair_pair_hash(prev_nr, curr_nr);
	for (probe = 0; probe < EDGEPAIR_MAX_PROBE; probe++) {
		const struct edgepair_published_slot *e =
			&edgepair_published->slots[idx];

		if (e->prev_nr == EDGEPAIR_EMPTY)
			return s;
		if (e->prev_nr == prev_nr && e->curr_nr == curr_nr) {
			s.new_edges = e->new_edge_count;
			s.total     = e->total_count;
			return s;
		}
		idx = (idx + 1) & EDGEPAIR_TABLE_MASK;
	}

	return s;
}

bool edgepair_lookup(unsigned int prev_nr, unsigned int curr_nr,
		     struct edgepair_snapshot *out)
{
	unsigned int idx;
	unsigned int probe;

	if (out == NULL)
		return false;

	out->new_edges	= 0;
	out->total	= 0;
	out->last_new_at = 0;
	out->state	= EDGEPAIR_STATE_UNSEEN;
	out->present	= false;

	if (!edgepair_enabled)
		return false;
	if (prev_nr >= MAX_NR_SYSCALL || curr_nr >= MAX_NR_SYSCALL)
		return false;

	/* Counters come from the parent-canonical aggregate (total_count
	 * is not carried in the child-RO mirror).  State is then derived
	 * via edgepair_state() which consults the mirror; the two views
	 * can disagree across a publish window but the lag is bounded by
	 * one drain iteration and is acceptable for the consumers this
	 * snapshot feeds. */
	idx = edgepair_pair_hash(prev_nr, curr_nr);
	for (probe = 0; probe < EDGEPAIR_MAX_PROBE; probe++) {
		const struct edgepair_entry *e = &parent_edgepair.table[idx];

		if (e->prev_nr == EDGEPAIR_EMPTY)
			return false;
		if (e->prev_nr == prev_nr && e->curr_nr == curr_nr) {
			out->new_edges	 = e->new_edge_count;
			out->total	 = e->total_count;
			out->last_new_at = e->last_new_at;
			out->present	 = true;
			out->state	 = edgepair_state(prev_nr, curr_nr);
			return true;
		}
		idx = (idx + 1) & EDGEPAIR_TABLE_MASK;
	}

	return false;
}

unsigned int edgepair_for_each_parent_entry(edgepair_iter_fn cb,
					    void *ctx)
{
	unsigned int i;
	unsigned int visited = 0;

	if (!edgepair_enabled || cb == NULL)
		return 0;

	for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
		const struct edgepair_entry *e = &parent_edgepair.table[i];

		if (e->prev_nr == EDGEPAIR_EMPTY)
			continue;
		visited++;
		if (!cb(e, ctx))
			break;
	}
	return visited;
}

/*
 * First-cut score weights.  Picked for shape (rank order across
 * states), not for any measured-productivity tuning.  Once the
 * sequence-chain picker and frontier strategy arm land they will tune
 * these against real run data; treating the numbers as a stable API
 * surface would be a mistake.
 */
unsigned int edgepair_score(unsigned int prev_nr, unsigned int curr_nr,
			    enum edgepair_score_mode mode)
{
	enum edgepair_pair_state state = edgepair_state(prev_nr, curr_nr);

	switch (mode) {
	case EDGEPAIR_SCORE_EXPLORATION:
		switch (state) {
		case EDGEPAIR_STATE_UNSEEN:		return 1024;
		case EDGEPAIR_STATE_PRODUCTIVE_FRESH:	return 256;
		case EDGEPAIR_STATE_PRODUCTIVE_COLD:	return 128;
		case EDGEPAIR_STATE_SEEN_UNPRODUCTIVE:	return 32;
		}
		break;
	case EDGEPAIR_SCORE_EXPLOITATION:
		switch (state) {
		case EDGEPAIR_STATE_PRODUCTIVE_FRESH:	return 1024;
		case EDGEPAIR_STATE_PRODUCTIVE_COLD:	return 256;
		case EDGEPAIR_STATE_UNSEEN:		return 128;
		case EDGEPAIR_STATE_SEEN_UNPRODUCTIVE:	return 16;
		}
		break;
	case EDGEPAIR_SCORE_COLD_PENALTY:
		switch (state) {
		case EDGEPAIR_STATE_PRODUCTIVE_FRESH:	return 1024;
		case EDGEPAIR_STATE_UNSEEN:		return 1024;
		case EDGEPAIR_STATE_PRODUCTIVE_COLD:	return 256;
		case EDGEPAIR_STATE_SEEN_UNPRODUCTIVE:	return 64;
		}
		break;
	}
	return 0;
}

void edgepair_dump_to_file(const char *path)
{
	struct edgepair_dump_header hdr;
	FILE *f;

	if (!edgepair_enabled)
		return;

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic		= EDGEPAIR_DUMP_MAGIC;
	hdr.version		= EDGEPAIR_DUMP_VERSION;
	hdr.table_size		= EDGEPAIR_TABLE_SIZE;
	hdr.payload_crc32	= kcov_bitmap_crc32(parent_edgepair.table,
						    sizeof(parent_edgepair.table));
	hdr.total_pair_calls	= parent_edgepair.total_pair_calls;
	hdr.pairs_tracked	= parent_edgepair.pairs_tracked;
	hdr.pairs_dropped	= parent_edgepair.pairs_dropped;

	if (!kcov_get_kernel_fp(hdr.kallsyms_sha256)) {
		output(0,
			"edgepair: cannot fingerprint kernel (/proc/kallsyms unavailable) -- skipping dump to %s\n",
			path);
		return;
	}
	hdr.max_nr_syscall = MAX_NR_SYSCALL;
	hdr.biarch_mode    = biarch ? 1U : 0U;
	(void)kcov_get_syscall_table_digest(hdr.syscall_table_digest);

	f = fopen(path, "wb");
	if (f == NULL) {
		perror("edgepair: failed to open dump file");
		return;
	}

	/* On-disk layout: fixed-size header (magic, version, table_size,
	 * payload_crc32, counters), then the canonical table.  The CRC
	 * covers the table bytes only -- the counters ride inside the
	 * header so a header read alone is enough to spot truncation. */
	if (fwrite(&hdr, sizeof(hdr), 1, f) != 1 ||
	    fwrite(parent_edgepair.table,
		   sizeof(parent_edgepair.table), 1, f) != 1) {
		perror("edgepair: failed to write dump file");
		fclose(f);
		return;
	}

	/* Flush libc's userspace buffer into the kernel and ask the
	 * kernel to push everything to durable storage before the
	 * fclose() releases the fd.  Without this, the dump is just a
	 * pagecache write -- a crash between fclose() return and the
	 * next writeback truncates the file to whatever happened to be
	 * page-aligned at the time, and edge_analyzer / the warm-start
	 * loader reject the partial result on magic / size / CRC
	 * mismatch.  fflush failures still drop into the close path so
	 * the fd is always released. */
	if (fflush(f) != 0)
		perror("edgepair: fflush before close failed");
	else if (fsync(fileno(f)) != 0 && errno != EINVAL)
		perror("edgepair: fsync before close failed");

	if (fclose(f) != 0) {
		perror("edgepair: failed to close dump file");
		return;
	}
	output(0, "KCOV: edge-pair data dumped to %s\n", path);
}

static ssize_t edgepair_read_all(int fd, void *buf, size_t len)
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

bool edgepair_load_from_file(const char *path)
{
	struct edgepair_dump_header hdr;
	unsigned char *scratch;
	uint32_t want_crc;
	ssize_t n;
	int fd;

	if (path == NULL || !edgepair_enabled)
		return false;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			output(0, "edgepair: no persisted state at %s -- cold start\n",
			       path);
		else
			output(0, "edgepair: open(%s) failed: %s -- cold start\n",
			       path, strerror(errno));
		return false;
	}

	n = edgepair_read_all(fd, &hdr, sizeof(hdr));
	if (n != (ssize_t)sizeof(hdr)) {
		output(0, "edgepair: header truncated at %s (got %zd, want %zu) -- cold start\n",
		       path, n, sizeof(hdr));
		(void)close(fd);
		return false;
	}

	if (hdr.magic != EDGEPAIR_DUMP_MAGIC) {
		output(0, "edgepair: file magic 0x%08x != expected 0x%08x at %s -- cold start\n",
		       hdr.magic, EDGEPAIR_DUMP_MAGIC, path);
		(void)close(fd);
		return false;
	}
	if (hdr.version != EDGEPAIR_DUMP_VERSION) {
		output(0, "edgepair: file version %u != expected %u at %s -- cold start\n",
		       hdr.version, EDGEPAIR_DUMP_VERSION, path);
		(void)close(fd);
		return false;
	}
	if (hdr.table_size != EDGEPAIR_TABLE_SIZE) {
		output(0, "edgepair: table_size %u != expected %u at %s (file built with a different EDGEPAIR_TABLE_SIZE) -- cold start\n",
		       hdr.table_size, EDGEPAIR_TABLE_SIZE, path);
		(void)close(fd);
		return false;
	}

	{
		uint8_t cur_fp[32];

		if (!kcov_get_kernel_fp(cur_fp)) {
			output(0,
				"edgepair: cannot fingerprint kernel (/proc/kallsyms unavailable) -- cold start, ignoring %s\n",
				path);
			(void)close(fd);
			return false;
		}
		if (memcmp(hdr.kallsyms_sha256, cur_fp,
			   sizeof(cur_fp)) != 0) {
			output(0,
				"edgepair: kernel fingerprint mismatch at %s (kallsyms content differs from when the file was written) -- cold start\n",
				path);
			(void)close(fd);
			return false;
		}
	}
	if (hdr.max_nr_syscall != MAX_NR_SYSCALL) {
		output(0,
			"edgepair: max_nr_syscall %u != expected %u at %s (file built with a different syscall table shape) -- cold start\n",
			hdr.max_nr_syscall, MAX_NR_SYSCALL, path);
		(void)close(fd);
		return false;
	}
	{
		uint32_t want_biarch = biarch ? 1U : 0U;

		if (hdr.biarch_mode != want_biarch) {
			output(0,
				"edgepair: biarch_mode %u != expected %u at %s (biarch flag differs from when the file was written) -- cold start\n",
				hdr.biarch_mode, want_biarch, path);
			(void)close(fd);
			return false;
		}
	}
	{
		uint8_t cur_digest[32];

		(void)kcov_get_syscall_table_digest(cur_digest);
		if (memcmp(hdr.syscall_table_digest, cur_digest,
			   sizeof(cur_digest)) != 0) {
			output(0,
				"edgepair.dump: syscall-table digest mismatch, ignoring stale dump (%s)\n",
				path);
			(void)close(fd);
			return false;
		}
	}

	/* Stage into a scratch buffer so a CRC failure doesn't leave the
	 * canonical table half-overwritten with garbage. */
	scratch = malloc(sizeof(parent_edgepair.table));
	if (scratch == NULL) {
		output(0, "edgepair: scratch alloc fail (%zu bytes) -- cold start\n",
		       sizeof(parent_edgepair.table));
		(void)close(fd);
		return false;
	}
	n = edgepair_read_all(fd, scratch, sizeof(parent_edgepair.table));
	if (n != (ssize_t)sizeof(parent_edgepair.table)) {
		output(0, "edgepair: payload truncated at %s (got %zd, want %zu) -- cold start\n",
		       path, n, sizeof(parent_edgepair.table));
		free(scratch);
		(void)close(fd);
		return false;
	}
	(void)close(fd);

	want_crc = kcov_bitmap_crc32(scratch, sizeof(parent_edgepair.table));
	if (want_crc != hdr.payload_crc32) {
		output(0, "edgepair: skipping warm-start of %s -- CRC mismatch\n",
		       path);
		free(scratch);
		return false;
	}

	memcpy(parent_edgepair.table, scratch, sizeof(parent_edgepair.table));
	free(scratch);
	parent_edgepair.total_pair_calls	= hdr.total_pair_calls;
	parent_edgepair.pairs_tracked		= hdr.pairs_tracked;
	parent_edgepair.pairs_dropped		= hdr.pairs_dropped;

	output(0, "edgepair: loaded %lu pairs (%lu pair-calls) from %s\n",
	       (unsigned long)hdr.pairs_tracked,
	       (unsigned long)hdr.total_pair_calls, path);
	return true;
}
