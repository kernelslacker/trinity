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
 * The one child-side reader (edgepair_is_cold on the syscall-selection
 * biasing path) consults the parent-published mirror page
 * (edgepair_published), refreshed in full at every drain.  Parent-side
 * consumers (edgepair_get_stats, dump, stats display) read the
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

static unsigned int pair_hash(unsigned int prev, unsigned int curr)
{
	/* Simple but effective: mix both syscall numbers. */
	unsigned int h = prev * 31 + curr;
	h ^= h >> 16;
	h *= 0x45d9f3b;
	h ^= h >> 16;
	return h & EDGEPAIR_TABLE_MASK;
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

bool edgepair_is_cold(unsigned int prev_nr, unsigned int curr_nr)
{
	unsigned int idx;
	unsigned int probe;

	if (edgepair_published == NULL)
		return false;

	idx = pair_hash(prev_nr, curr_nr);
	for (probe = 0; probe < EDGEPAIR_MAX_PROBE; probe++) {
		const struct edgepair_published_slot *e =
			&edgepair_published->slots[idx];

		if (e->prev_nr == EDGEPAIR_EMPTY)
			return false;
		if (e->prev_nr == prev_nr && e->curr_nr == curr_nr) {
			unsigned long total, last;

			/* Never found new edges -- not cold, just unproductive. */
			if (e->new_edge_count == 0)
				return false;

			/* Acquire-load pairs with the release-store in
			 * edgepair_publish_locked() so the subsequent
			 * last_new_at read sees the matching slot update
			 * for this publish window.  Plain MOV on x86-64. */
			total = __atomic_load_n(&edgepair_published->total_pair_calls,
						__ATOMIC_ACQUIRE);
			last = e->last_new_at;
			/* A publisher racing us can update this slot's
			 * last_new_at to the NEXT total *after* our acquire-
			 * load above, so last > total is possible and means
			 * the pair just produced new edges -- not cold.
			 * Without this guard, total - last underflows to a
			 * huge value and falsely trips the cold predicate. */
			if (last >= total)
				return false;
			return (total - last) > EDGEPAIR_COLD_THRESHOLD;
		}
		idx = (idx + 1) & EDGEPAIR_TABLE_MASK;
	}

	return false;
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

struct edgepair_stats edgepair_get_stats(unsigned int prev_nr,
					 unsigned int curr_nr)
{
	struct edgepair_stats s = { 0, 0 };
	unsigned int idx;
	unsigned int probe;

	if (!edgepair_enabled)
		return s;

	if (prev_nr >= MAX_NR_SYSCALL || curr_nr >= MAX_NR_SYSCALL)
		return s;

	idx = pair_hash(prev_nr, curr_nr);
	for (probe = 0; probe < EDGEPAIR_MAX_PROBE; probe++) {
		const struct edgepair_entry *e = &parent_edgepair.table[idx];

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
