/*
 * CONFIG_GUARD_SHARED diagnostics for the shared-region registry: the
 * from-scratch overlap oracle range_overlaps_shared() is audited against,
 * the per-child ring of their disagreements, and the kcov-buffer checks
 * the internal mprotect sites and the on-fault diagnostic call.
 */

#ifdef CONFIG_GUARD_SHARED

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "trinity.h"
#include "utils.h"
#include "utils-internal.h"

#include "kernel/fcntl.h"

/*
 * Pure linear scan over shared_regions[] + overflow tail.  Returns true
 * iff [addr, addr+len) overlaps at least one tracked region; ignores the
 * bitmap and size-bucket accelerators entirely.  This is a deliberate
 * answers-the-truth oracle for the audit wrapper below: if the fast
 * path disagrees with this verdict on the same input, the accelerator
 * is desynced from the authoritative registry and the audit logs both
 * sides so the source of the divergence can be pinned to a single mm
 * sanitiser callsite.
 *
 * @entry_addr / @entry_size / @entry_origin are filled with the first
 * matching region's fields when non-NULL.  origin is the tag set by
 * track_shared_region_tagged() ("kcov-pc" / "kcov-cmp" for the buffers
 * the kcov investigation is chasing), or NULL for untagged registrants.
 */
bool range_overlaps_shared_slow(unsigned long addr, unsigned long len,
				unsigned long *entry_addr,
				unsigned long *entry_size,
				const char **entry_origin)
{
	const struct shared_region_entry *r;
	unsigned long end;
	unsigned int i;

	if (len != 0 && addr > ULONG_MAX - len)
		return true;
	end = addr + len;

	for_each_shared_region(i, r) {
		unsigned long rstart = r->addr;
		unsigned long rsize = r->size;
		unsigned long rend;

		if (rsize == 0)
			continue;
		rend = rstart + rsize;
		if (len == 0 ? (addr >= rstart && addr < rend)
			     : (addr < rend && rstart < end)) {
			if (entry_addr)   *entry_addr = rstart;
			if (entry_size)   *entry_size = rsize;
			if (entry_origin) *entry_origin = r->origin;
			return true;
		}
	}
	return false;
}

/*
 * Per-child rolling log of the most recent fast-vs-slow audit
 * disagreements emitted by range_overlaps_shared_audited().  Sized to
 * comfortably exceed the on-fault diagnostic's "last ~16 lines"
 * recall.  Each slot stores a printf-style line already rendered to
 * text; readers (kcov_dump_audit_ring()) snprintf the slots out, no
 * extra formatting needed in signal context.
 *
 * COW-inherited into every forked child; never touched by the parent
 * once children are spawned.  Plain file-scope statics rather than
 * __thread because trinity children are single-threaded.
 */
#define KCOV_AUDIT_RING_SIZE	32U
#define KCOV_AUDIT_LINE_MAX	256U
static char kcov_audit_ring[KCOV_AUDIT_RING_SIZE][KCOV_AUDIT_LINE_MAX];
static unsigned int kcov_audit_ring_head;
static unsigned long kcov_audit_ring_writes;

static void kcov_audit_ring_push(const char *line)
{
	unsigned int slot = kcov_audit_ring_head % KCOV_AUDIT_RING_SIZE;
	size_t n = strlen(line);

	if (n >= KCOV_AUDIT_LINE_MAX)
		n = KCOV_AUDIT_LINE_MAX - 1;
	memcpy(kcov_audit_ring[slot], line, n);
	kcov_audit_ring[slot][n] = '\0';
	kcov_audit_ring_head = (slot + 1) % KCOV_AUDIT_RING_SIZE;
	kcov_audit_ring_writes++;
}

/*
 * Dump up to the last KCOV_AUDIT_RING_SIZE audit disagreements via
 * outputerr().  Called from the kcov_enable_trace on-fault path so the
 * accelerator-vs-truth disagreement history that preceded the SEGV is
 * visible alongside the fault diagnostic.  Best-effort -- safe to call
 * from a SIGSEGV/SIGBUS handler context because outputerr() is the
 * existing fault-path output channel and the ring slots are plain
 * pre-rendered character arrays.
 */
void kcov_audit_ring_dump(const char *prefix)
{
	unsigned int n = (kcov_audit_ring_writes < KCOV_AUDIT_RING_SIZE)
		? (unsigned int) kcov_audit_ring_writes : KCOV_AUDIT_RING_SIZE;
	unsigned int i;

	if (n == 0) {
		outputerr("%s: audit ring empty (no fast-vs-slow disagreements seen)\n",
			  prefix);
		return;
	}
	outputerr("%s: last %u audit disagreement(s) (oldest first):\n",
		  prefix, n);
	for (i = 0; i < n; i++) {
		unsigned int slot =
			(kcov_audit_ring_head + KCOV_AUDIT_RING_SIZE - n + i)
			% KCOV_AUDIT_RING_SIZE;
		outputerr("  %s\n", kcov_audit_ring[slot]);
	}
}

bool range_overlaps_shared_audited(const char *site,
				   unsigned long addr, unsigned long len)
{
	bool fast = range_overlaps_shared(addr, len);
	unsigned long e_addr = 0, e_size = 0;
	const char *e_origin = NULL;
	bool slow = range_overlaps_shared_slow(addr, len,
					       &e_addr, &e_size, &e_origin);
	char line[KCOV_AUDIT_LINE_MAX];

	if (fast == slow)
		return fast;

	/* Verdicts differ -- accelerator desync.  Render a single line
	 * to the per-child audit ring for later in-handler recall, and
	 * emit it via outputerr() so live runs surface the divergence
	 * immediately.  Format keeps the site / query / both verdicts /
	 * matching entry visible at a glance. */
	snprintf(line, sizeof(line),
		 "range_overlaps_shared_audit: site=%s query=0x%lx+0x%lx "
		 "fast=%s slow=%s overlap=0x%lx+0x%lx origin=%s",
		 site ? site : "?", addr, len,
		 fast ? "true" : "false",
		 slow ? "true" : "false",
		 slow ? e_addr : 0UL,
		 slow ? e_size : 0UL,
		 (slow && e_origin) ? e_origin : "(untagged)");
	kcov_audit_ring_push(line);
	outputerr("%s\n", line);
	return fast;
}

/*
 * Walk shared_regions[] for entries carrying the kcov-pc / kcov-cmp
 * origin tag and warn loudly if [addr, addr+len) overlaps any of them.
 * Called from the internal mprotect sites (freeze_sibling_childdata,
 * init_child's pids[] freeze, get_writable_address's own mprotect)
 * before the syscall fires -- an internal-mprotect overlap on a kcov
 * buffer is a distinct mechanism for the trace_buf write-fault we are
 * trying to localise from the externally-fuzzed mm-sanitiser path.
 *
 * @who   : short site tag for the log line ("freeze_sibling_childdata",
 *          "init_child:pids", "get_writable_address").
 * @prot  : the requested protection bits, rendered as the trailing
 *          "prot=0x%x" field so the log explicitly names whether a
 *          PROT_READ/PROT_NONE strip is in play.
 */
void internal_mprotect_audit_kcov(const char *who, unsigned long addr,
				  unsigned long len, int prot)
{
	const struct shared_region_entry *r;
	unsigned long end;
	unsigned int i;

	if (len == 0)
		return;
	if (addr > ULONG_MAX - len)
		return;
	end = addr + len;

	for_each_shared_region(i, r) {
		const char *origin = r->origin;
		unsigned long rstart, rsize, rend;

		if (origin == NULL)
			continue;
		if (strncmp(origin, "kcov-", 5) != 0)
			continue;
		rstart = r->addr;
		rsize  = r->size;
		if (rsize == 0)
			continue;
		rend = rstart + rsize;
		if (addr < rend && rstart < end) {
			outputerr("internal_mprotect_audit: %s mprotect "
				  "[0x%lx+0x%lx) prot=0x%x overlaps "
				  "%s region [0x%lx+0x%lx)%s\n",
				  who, addr, len, (unsigned int) prot,
				  origin, rstart, rsize,
				  i >= nr_shared_regions ? " (overflow)" : "");
		}
	}
}

/*
 * Scan /proc/self/maps for the entry covering @addr and report its
 * tracked-shared-region match status alongside the live VMA
 * protection bits.  Used both at registration time (to catch a setup-
 * side mistake where the buffer is already non-writable when we
 * register it) and from the on-fault diagnostic (to catch the
 * runtime-strip the SEGV is the symptom of).  Output goes to
 * outputerr() -- the existing fault-path channel; no new logging
 * mechanism.
 *
 * @who : short site tag.  @addr : the buffer address.  @size : the
 * length we expect the entry to span.
 */
void log_buffer_prot_from_proc_maps(const char *who, unsigned long addr,
				    unsigned long size)
{
	int fd;
	char buf[8192];
	ssize_t n;
	bool found = false;

	fd = TEMP_FAILURE_RETRY(open("/proc/self/maps", O_RDONLY | O_CLOEXEC));
	if (fd < 0) {
		outputerr("%s: open(/proc/self/maps) failed: errno=%d "
			  "addr=0x%lx size=0x%lx\n",
			  who, errno, addr, size);
		return;
	}

	/* Best-effort streaming scan: read into a fixed buffer, split on
	 * newlines, parse the leading "%lx-%lx %4s" of each line.  We do
	 * not need to scan the whole map -- the first line whose range
	 * covers @addr is the answer.  Tail-truncation across buffer
	 * boundaries is acceptable for a diagnostic that only needs the
	 * matching line. */
	while ((n = TEMP_FAILURE_RETRY(read(fd, buf, sizeof(buf) - 1))) > 0) {
		char *p = buf;
		char *end_p = buf + n;
		*end_p = '\0';

		while (p < end_p) {
			char *nl = memchr(p, '\n', (size_t)(end_p - p));
			unsigned long lo = 0, hi = 0;
			char perms[5] = {0};

			if (nl) *nl = '\0';

			if (sscanf(p, "%lx-%lx %4s", &lo, &hi, perms) == 3 &&
			    addr >= lo && addr < hi) {
				outputerr("%s: addr=0x%lx size=0x%lx "
					  "/proc/self/maps prot=%s "
					  "vma=[0x%lx-0x%lx)\n",
					  who, addr, size, perms, lo, hi);
				found = true;
				goto out;
			}
			if (!nl)
				break;
			p = nl + 1;
		}
	}

out:
	if (!found)
		outputerr("%s: addr=0x%lx size=0x%lx no /proc/self/maps entry "
			  "covers this address\n", who, addr, size);
	close(fd);
}

/*
 * Look up whether [addr, addr+size) still matches a registered shared
 * region with the given origin tag.  Used by the on-fault diagnostic
 * to answer "is the kcov-pc registration still present at the addr
 * the child just faulted on?" without re-deriving the slot from the
 * caller context.  Returns true on exact-match (addr + size + origin
 * all line up), false otherwise.
 */
bool kcov_registration_still_present(unsigned long addr, unsigned long size,
				     const char *origin)
{
	unsigned int i;

	if (origin == NULL)
		return false;
	for (i = 0; i < nr_shared_regions; i++) {
		if (shared_regions[i].addr != addr ||
		    shared_regions[i].size != size)
			continue;
		if (shared_regions[i].origin == NULL)
			continue;
		if (strcmp(shared_regions[i].origin, origin) == 0)
			return true;
	}
	for (i = 0; i < nr_shared_regions_overflow; i++) {
		if (shared_regions_overflow[i].addr != addr ||
		    shared_regions_overflow[i].size != size)
			continue;
		if (shared_regions_overflow[i].origin == NULL)
			continue;
		if (strcmp(shared_regions_overflow[i].origin, origin) == 0)
			return true;
	}
	return false;
}
#endif	/* CONFIG_GUARD_SHARED */
