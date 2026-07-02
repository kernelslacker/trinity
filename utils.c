#include <stdbool.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "breadcrumb_ring.h"
#include "child.h"
#include "debug.h"
#include "deferred-free.h"
#include "locks.h"
#include "objects.h"
#include "params.h"
#include "pc_format.h"
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "signals.h"	// asb_copy_recover / asb_copy_active snapshot-copy guard
#include "stats.h"
#include "stats_ring.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"
#include "utils-internal.h"



void sizeunit(unsigned long size, char *buf, size_t buflen)
{
	/* non kilobyte aligned size? */
	if (size < 1024) {
		snprintf(buf, buflen, "%lu bytes", size);
		return;
	}

	/* < 1MB ? */
	if (size < (1024 * 1024)) {
		snprintf(buf, buflen, "%luKB", size / 1024);
		return;
	}

	/* < 1GB ? */
	if (size < (1024 * 1024 * 1024)) {
		snprintf(buf, buflen, "%luMB", (size / 1024) / 1024);
		return;
	}

	snprintf(buf, buflen, "%luGB", ((size / 1024) / 1024) / 1024);
}

void kill_pid(pid_t pid)
{
	int ret;
	int childno;

	if (pid == -1) {
		show_backtrace();
		syslogf("kill_pid tried to kill -1!\n");
		return;
	}
	if (pid == 0) {
		show_backtrace();
		syslogf("tried to kill_pid 0!\n");
		return;
	}

	/*
	 * Refuse to SIGKILL ourselves.  A wrapper run was observed dying
	 * with mainpid SIGKILL'ing mainpid; bpftrace on signal_generate
	 * confirmed the kill syscall came from main itself.  The path is
	 * shm corruption scribbling mainpid into a pids[] slot, then a
	 * reap/kill loop walking pids[] and feeding that value back in
	 * here.  pid_is_valid() accepts mainpid as in-range, so without
	 * this guard main commits suicide.
	 *
	 * Scan pids[] first so the diagnostic line names the scribbled
	 * slot, then dump childnos + the pids page state so we can tell
	 * whether this was a single wild write or a page-level event.
	 */
	if (pid == mainpid) {
		unsigned int i;
		int corrupt_slot = -1;

		for_each_child(i) {
			pid_t slot = __atomic_load_n(&pids[i], __ATOMIC_RELAXED);
			if (slot == mainpid) {
				corrupt_slot = i;
				break;
			}
		}

		if (corrupt_slot == -1)
			syslogf("kill_pid refused: pid=%d == mainpid=%d, pids[] slot=none\n",
				pid, mainpid);
		else
			syslogf("kill_pid refused: pid=%d == mainpid=%d, pids[] slot=%d\n",
				pid, mainpid, corrupt_slot);

		show_backtrace();
		dump_childnos();
		dump_pids_page_state();
		return;
	}

	childno = find_childno(pid);
	if (childno != CHILD_NOT_FOUND) {
		if (children[childno]->dontkillme == true)
			return;
	}

	ret = kill(pid, SIGKILL);
	if (ret != 0)
		debugf("couldn't kill pid %d [%s]\n", pid, strerror(errno));
}

/*
 * looks_like_corrupted_ptr - heuristic test for "this slot used to hold
 * a pointer we malloc'd, but somebody scribbled a non-pointer over it".
 *
 * Cluster-1 / cluster-2 / cluster-3 crash signature (residual-cores
 * triage 2026-05-02): si_addr in the killing siginfo equals si_pid (e.g.
 * si_addr=0x378a02 against pid 0x378a02).  The shape comes from a fuzzed
 * value-result syscall in some sibling child landing in trinity-internal
 * memory -- rec->aN, a struct field reachable from rec->aN, or a slot in
 * the deferred-free ring -- and overwriting a pointer that a post handler
 * was about to deref or pass to free(), with the kernel-issued tid/pid
 * value.  The deferred-free ring already mprotects between ticks so a
 * scribble there now SIGSEGVs in copy_from_user, but the rec-> path is
 * unprotected by construction (the kernel must be able to write into
 * rec->aN -- that's the whole point).
 *
 * Three rejection bands, all heuristic:
 *
 *   - v < 0x10000:  cannot be a real heap pointer.  PIDs (pid_max is
 *     typically 4 million on Linux) and small ints land here.  This is
 *     the same gate deferred_free_tick() uses as a belt-and-braces
 *     check at free time; we want to reject earlier so the ring slot
 *     never holds a bogus value at all.
 *
 *   - v >= (1UL << 47):  above the x86_64 user canonical limit.  glibc
 *     malloc / mmap / brk hand out addresses well below this; a value
 *     here is either a kernel pointer leaked back (bug regardless of
 *     post-handler state) or a tornadic write of a high-bit pattern.
 *
 *   - v & 0x7:  misaligned for an 8-byte pointer.  Every trinity heap
 *     allocator (zmalloc, alloc_iovec, get_writable_*, alloc_object)
 *     hands back >= 8-byte aligned memory.  A misaligned value in a
 *     slot we expect to free is almost certainly a partial overwrite.
 *
 * False positive cost: a legitimate-but-weird pointer would be dropped
 * (memory leak), not freed.  A leak in a post handler is benign --
 * children turn over fast and the heap evaporates at exit.  The
 * alternative (false negative) is the cluster-1/2/3 SIGSEGV class we
 * are trying to kill, so we err strict.  Audited against current post
 * handlers (deferred_freeptr, deferred_free_enqueue callers, direct
 * free() on rec->aN): every pointer those receive is heap-allocated
 * via 8-byte aligned routines, so the misalign band is safe at all
 * present call sites.  If a future caller is shown to legitimately
 * pass an unaligned value, drop the alignment check rather than
 * dropping the others.
 *
 * Returns true if the pointer looks scribbled and the caller should
 * drop it instead of dereferencing or freeing.
 */
/*
 * Update this child's per-handler attribution shard for a
 * post_handler_corrupt_ptr rejection.  Linear scan of the 32-entry shard:
 * if @nr is already present we bump its count; otherwise the lowest-count
 * slot is evicted in favour of the new key.  Eviction stays child-local,
 * so global LRU ordering across the fleet is lost on the long tail; the
 * parent merges every child's shard at dump time and the hot handlers
 * still surface in the top rows because they land in every shard.
 *
 * Each child is the sole writer of its own shard, so no lock is needed.
 * The parent is the sole reader and only at periodic-dump time -- torn
 * reads on the dump side may shave a count by one off a single shard
 * slot, which is in the noise once 32 shards are merged.
 *
 * this_child()==NULL callers (parent post-mortem paths, deferred-free
 * tick on the main process) have no shard to bump and drop the record.
 */
static void corrupt_ptr_attr_record(unsigned int nr, bool do32bit)
{
	struct childdata *child = this_child();
	struct corrupt_ptr_attr_entry *ring;
	unsigned int i, victim;
	unsigned long victim_count;

	if (child == NULL)
		return;

	ring = child->local_corrupt_ptr_attr;

	for (i = 0; i < CORRUPT_PTR_ATTR_SLOTS; i++) {
		if (ring[i].count != 0 &&
		    ring[i].nr == nr && ring[i].do32bit == do32bit) {
			ring[i].count++;
			return;
		}
	}

	victim = 0;
	victim_count = ring[0].count;
	for (i = 1; i < CORRUPT_PTR_ATTR_SLOTS; i++) {
		if (ring[i].count < victim_count) {
			victim = i;
			victim_count = ring[i].count;
		}
		if (victim_count == 0)
			break;
	}

	ring[victim].nr = nr;
	ring[victim].do32bit = do32bit;
	ring[victim].count = victim_count + 1;
}

/*
 * Record a (nr, do32bit, pc) triple into this child's per-callsite
 * sub-attribution shard.  Same eviction policy as corrupt_ptr_attr_record:
 * bump the matching slot if present, otherwise displace the lowest-count
 * slot.  No lock for the same reason -- the owning child is the sole
 * writer.  Skipped when pc==NULL (defensive -- a caller without a usable
 * return address has no useful PC to record) or when this_child() returns
 * NULL (no shard to bump).
 */
static void corrupt_ptr_pc_record(unsigned int nr, bool do32bit, void *pc,
				  const char *site)
{
	struct childdata *child = this_child();
	struct corrupt_ptr_pc_entry *ring;
	unsigned int i, victim;
	unsigned long victim_count;

	if (pc == NULL || child == NULL)
		return;

	ring = child->local_corrupt_ptr_pc;

	for (i = 0; i < CORRUPT_PTR_PC_SLOTS; i++) {
		if (ring[i].count != 0 &&
		    ring[i].nr == nr && ring[i].do32bit == do32bit &&
		    ring[i].pc == pc) {
			ring[i].count++;
			/* Late-arriving site tag for an existing entry — fill
			 * it in so the dump can disambiguate even when the
			 * first bump for this PC came through a tagless caller
			 * (e.g. the legacy macro wrapper with site=NULL). */
			if (ring[i].site == NULL && site != NULL)
				ring[i].site = site;
			return;
		}
	}

	victim = 0;
	victim_count = ring[0].count;
	for (i = 1; i < CORRUPT_PTR_PC_SLOTS; i++) {
		if (ring[i].count < victim_count) {
			victim = i;
			victim_count = ring[i].count;
		}
		if (victim_count == 0)
			break;
	}

	ring[victim].nr = nr;
	ring[victim].do32bit = do32bit;
	ring[victim].pc = pc;
	ring[victim].site = site;
	ring[victim].count = victim_count + 1;
}

void post_handler_corrupt_ptr_bump_full(struct syscallrecord *rec,
					void *caller_pc, const char *site,
					unsigned int arg_idx,
					unsigned long bad_ptr)
{
	struct childdata *child;
	unsigned int nr;
	bool do32bit;

	/* Headline aggregate routes through the per-child stats_ring on
	 * the child path (parent drain accumulates into parent_stats).
	 * Parent-context callers (post-mortem paths, deferred-free tick
	 * on the main process) bump parent_stats directly since the
	 * parent is the sole writer in that case. */
	child = this_child();
	if (child != NULL && child->stats_ring != NULL)
		stats_ring_enqueue(child->stats_ring,
				   STATS_FIELD_POST_HANDLER_CORRUPT_PTR, 0, 1);
	else
		parent_stats.post_handler_corrupt_ptr++;

	/* Per-child shadow of the same event, scored by the storm-rate
	 * check in child_process.  Stays per-child (not in shm) -- the
	 * storm check reads it directly off childdata. */
	if (child != NULL)
		child->local_post_handler_corrupt_ptr++;

	if (rec != NULL) {
		nr = rec->nr;
		do32bit = rec->do32bit;
	} else {
		nr = CORRUPT_PTR_ATTR_NR_NONE;
		do32bit = false;
	}
	corrupt_ptr_pc_record(nr, do32bit, caller_pc, site);
	corrupt_ptr_attr_record(nr, do32bit);

	/* Per-fire breadcrumb with the scribbled pointer value, the arg
	 * slot the caller attributed it to (or NO_ARG), and the site tag.
	 * Drops silently when this_child() is NULL -- per-child storage. */
	corrupt_ptr_breadcrumb_push(rec, arg_idx, bad_ptr, site);
}

void post_handler_corrupt_ptr_bump_site(struct syscallrecord *rec,
					void *caller_pc, const char *site)
{
	post_handler_corrupt_ptr_bump_full(rec, caller_pc, site,
					   CORRUPT_PTR_BREADCRUMB_NO_ARG,
					   CORRUPT_PTR_BREADCRUMB_BAD_UNKNOWN);
}

/*
 * TRINITY_CORRUPT_ATTRIB measurement path.  Off by default; enabled at
 * runtime by exporting TRINITY_CORRUPT_ATTRIB=1 before fork.  Latched
 * on first query so the hot path pays one cached-bool branch when the
 * gate is off.
 *
 * The mprotect-armor probe (corruption probe #1) proved that the
 * syscallrecord itself is not wild-written (0 trap fires, rec_canary=0)
 * yet the post_handler_corrupt_ptr headline keeps spiking ~40k/60s.
 * This counter must therefore be conflating distinct rejection paths
 * -- structural validators (validate_arg_coupling, enforce_count_bound)
 * that bump on perfectly-fine-but-rejected kernel results AND the
 * shape-heuristic firing on genuine scribbles into rec->aN AND the
 * per-handler oracle bumps (mq_notify / getitimer / timer_gettime /
 * timerfd_gettime).  Per-site attribution disambiguates: if the spike
 * is dominated by validator_rejected the headline tells us nothing
 * about real corruption; if a residual "post_generic" bucket remains
 * non-trivial, that's the next call-site sweep target.
 */
_Static_assert(sizeof(((struct stats_s *)0)->corrupt_ptr_site_count) ==
	       sizeof(unsigned long) * CORRUPT_PTR_SITE__COUNT,
	       "corrupt_ptr_site_count array size out of sync with enum");

const char *const corrupt_ptr_site_names[CORRUPT_PTR_SITE__COUNT] = {
	[CORRUPT_PTR_SITE_VALIDATOR_REJECTED]    = "validator_rejected",
	[CORRUPT_PTR_SITE_ENFORCE_COUNT_BOUND]   = "enforce_count_bound",
	[CORRUPT_PTR_SITE_RETFD_INVALID]         = "retfd_invalid",
	[CORRUPT_PTR_SITE_CLAIM_OWNED_NOT_OWNED] = "claim_owned_not_owned",
	[CORRUPT_PTR_SITE_CLAIM_OWNED_BAD_MAGIC] = "claim_owned_bad_magic",
	[CORRUPT_PTR_SITE_SHAPE_HEURISTIC]       = "shape_heuristic",
	[CORRUPT_PTR_SITE_MQ_NOTIFY]             = "mq_notify",
	[CORRUPT_PTR_SITE_GETITIMER]             = "getitimer",
	[CORRUPT_PTR_SITE_TIMER_GETTIME]         = "timer_gettime",
	[CORRUPT_PTR_SITE_TIMERFD_GETTIME]       = "timerfd_gettime",
};

static bool corrupt_attrib_inited;
static bool corrupt_attrib_enabled;

bool corrupt_ptr_attrib_active(void)
{
	if (!corrupt_attrib_inited) {
		const char *v = getenv("TRINITY_CORRUPT_ATTRIB");

		corrupt_attrib_enabled =
			(v != NULL && v[0] == '1' && v[1] == '\0');
		corrupt_attrib_inited = true;
	}
	return corrupt_attrib_enabled;
}

void corrupt_ptr_site_record(enum corrupt_ptr_site site)
{
	if (!corrupt_ptr_attrib_active())
		return;
	if ((unsigned int) site >= CORRUPT_PTR_SITE__COUNT)
		return;
	__atomic_add_fetch(&shm->stats.corrupt_ptr_site_count[site], 1,
			   __ATOMIC_RELAXED);
}

void post_handler_corrupt_ptr_bump_at(struct syscallrecord *rec,
				      void *caller_pc,
				      enum corrupt_ptr_site site)
{
	const char *tag = NULL;

	if ((unsigned int) site < CORRUPT_PTR_SITE__COUNT)
		tag = corrupt_ptr_site_names[site];
	corrupt_ptr_site_record(site);
	post_handler_corrupt_ptr_bump_site(rec, caller_pc, tag);
}

/*
 * Record a caller PC into this child's deferred_free_reject sub-attribution
 * shard.  Same eviction policy and ownership model as corrupt_ptr_pc_record
 * -- the owning child is the sole writer of its own shard, so no lock is
 * needed; the parent merges every child's shard at dump time.  Skipped when
 * pc==NULL (defensive -- a caller without a usable return address has no
 * useful PC to record) or when this_child() returns NULL (parent post-mortem
 * path, deferred-free tick on the main process -- no shard to bump).
 * Slimmer key than corrupt_ptr_pc_record because every bump originates from
 * rec==NULL deferred_free_enqueue calls so (nr, do32bit) carry no
 * information.
 */
static void deferred_free_reject_pc_record(void *pc)
{
	struct childdata *child = this_child();
	struct deferred_free_reject_pc_entry *ring;
	unsigned int i, victim;
	unsigned long victim_count;

	if (pc == NULL || child == NULL)
		return;

	ring = child->local_deferred_free_reject_pc;

	for (i = 0; i < CORRUPT_PTR_PC_SLOTS; i++) {
		if (ring[i].count != 0 && ring[i].pc == pc) {
			ring[i].count++;
			return;
		}
	}

	victim = 0;
	victim_count = ring[0].count;
	for (i = 1; i < CORRUPT_PTR_PC_SLOTS; i++) {
		if (ring[i].count < victim_count) {
			victim = i;
			victim_count = ring[i].count;
		}
		if (victim_count == 0)
			break;
	}

	ring[victim].pc = pc;
	ring[victim].count = victim_count + 1;
}

void deferred_free_reject_bump(void *caller_pc)
{
	struct childdata *child = this_child();
	enum stats_field shard;

	switch (deferred_free_get_cleanup_argtype()) {
	case ARG_PATHNAME:
		shard = STATS_FIELD_DEFERRED_FREE_REJECT_PATHNAME;
		break;
	case ARG_IOVEC:
	case ARG_IOVEC_IN:
		shard = STATS_FIELD_DEFERRED_FREE_REJECT_IOVEC;
		break;
	case ARG_SOCKADDR:
		shard = STATS_FIELD_DEFERRED_FREE_REJECT_SOCKADDR;
		break;
	default:
		shard = STATS_FIELD_DEFERRED_FREE_REJECT_OTHER;
		break;
	}

	if (child != NULL && child->stats_ring != NULL) {
		stats_ring_enqueue(child->stats_ring,
				   STATS_FIELD_DEFERRED_FREE_REJECT, 0, 1);
		stats_ring_enqueue(child->stats_ring, shard, 0, 1);
	} else {
		parent_stats.deferred_free_reject++;
		switch (shard) {
		case STATS_FIELD_DEFERRED_FREE_REJECT_PATHNAME:
			parent_stats.deferred_free_reject_pathname++;
			break;
		case STATS_FIELD_DEFERRED_FREE_REJECT_IOVEC:
			parent_stats.deferred_free_reject_iovec++;
			break;
		case STATS_FIELD_DEFERRED_FREE_REJECT_SOCKADDR:
			parent_stats.deferred_free_reject_sockaddr++;
			break;
		default:
			parent_stats.deferred_free_reject_other++;
			break;
		}
	}
	deferred_free_reject_pc_record(caller_pc);
}

__attribute__((noinline))
void post_handler_corrupt_ptr_bump_retfd(struct syscallrecord *rec)
{
	corrupt_ptr_site_record(CORRUPT_PTR_SITE_RETFD_INVALID);
	post_handler_corrupt_ptr_bump_site(rec, __builtin_return_address(0),
					   "handle_syscall_ret:retfd_invalid");
}

/*
 * Out-of-line tripwire for get_arg_snapshot() mismatches.  Called only
 * when an opted-in slot's shadow disagrees with the live rec->aN at the
 * post handler's read site, i.e. a sibling scribbled the slot after the
 * dispatch-time snapshot in __do_syscall() (taken from the local a1..a6
 * just before the syscall is issued) and before the post handler ran.
 * The narrower window is intentional: a stomp earlier than dispatch
 * was seen by the kernel directly and isn't a post-handler bound
 * fabrication, so it does not belong in this counter.
 * Routes through the per-child stats_ring on the child path (parent
 * drain accumulates into parent_stats.arg_shadow_stomp) and through
 * parent_stats directly on the rare no-child path.  No per-syscall
 * shard for now -- the MVP opted-in set is small enough that aggregate
 * tells us "is this signal real" without sub-attribution; when the
 * opt-in set grows past a handful of handlers we can teach this helper
 * the corrupt_ptr_attr_record per-(nr,do32bit) routing.
 */
void arg_shadow_stomp_bump(struct syscallrecord *rec, unsigned int argnum,
			   unsigned long shadow, unsigned long current)
{
	struct childdata *child = this_child();

	if (child != NULL && child->stats_ring != NULL)
		stats_ring_enqueue(child->stats_ring,
				   STATS_FIELD_ARG_SHADOW_STOMP, 0, 1);
	else
		parent_stats.arg_shadow_stomp++;

	output(0, "arg_shadow_stomp: syscall nr %u arg %u shadow 0x%lx live 0x%lx\n",
	       rec != NULL ? rec->nr : 0, argnum, shadow, current);
}

/*
 * Categorise a rejected pointer value into one of four heuristic bands
 * so the sample log line tells us at a glance whether the rejection is
 * obvious noise (NULL-ish, pid-shaped, kernel-VA leak) or whether the
 * value sits in the heap-shape range and the shape heuristic itself is
 * the false positive.  The pid_max ceiling of 4194304 (the kernel
 * default for 64-bit boots) is used for the pid-shaped band so a stray
 * tid lands here even though it would also satisfy v >= 0x10000.
 */
const char *corrupt_ptr_label(unsigned long v)
{
	if (v < 0x10000)
		return "NULL-ish";
	if (v < 4194304)
		return "pid-shaped";
	if (v >= 0x800000000000UL)
		return "kernel-VA";
	return "heap-shaped";
}

/*
 * Sample-rate for the per-rejection log line.  At the observed sustained
 * rate of ~900 rejections/min a 1-in-100 sample emits roughly nine lines
 * per minute -- enough to characterise the value distribution without
 * flooding the log faster than the operator can read it.
 */
#define CORRUPT_PTR_SAMPLE_INTERVAL	100

bool looks_like_corrupted_ptr_pc(struct syscallrecord *rec, const void *p,
				 void *caller_pc)
{
	unsigned long v = (unsigned long) p;
	unsigned long n;

	if (!is_corrupt_ptr_shape(p))
		return false;

	corrupt_ptr_site_record(CORRUPT_PTR_SITE_SHAPE_HEURISTIC);
	post_handler_corrupt_ptr_bump_full(rec, caller_pc, "shape-heuristic",
					   CORRUPT_PTR_BREADCRUMB_NO_ARG, v);

	/*
	 * Sample every CORRUPT_PTR_SAMPLE_INTERVALth rejection.  Counter
	 * is shm-resident so the sample cadence is fleet-global rather than
	 * per-child -- a host with 32 children would otherwise emit 32x the
	 * sample volume.  RELAXED ordering: the sample is opportunistic;
	 * losing one to a torn read between siblings does not matter.
	 */
	n = __atomic_add_fetch(&shm->stats.corrupt_ptr_sample_seq, 1,
			       __ATOMIC_RELAXED);
	if ((n % CORRUPT_PTR_SAMPLE_INTERVAL) == 1) {
		const char *name;
		char pcbuf[128];

		if (rec != NULL)
			name = print_syscall_name(rec->nr, rec->do32bit);
		else
			name = "<deferred-free>";

		output(0, "corrupt-ptr reject sample: syscall=%s value=0x%lx "
			  "label=%s caller=%s\n",
			  name, v, corrupt_ptr_label(v),
			  pc_to_string(__builtin_return_address(0),
				       pcbuf, sizeof(pcbuf)));
	}
	return true;
}

bool inner_ptr_ok_to_free(struct syscallrecord *rec, const void *p,
			  const char *site)
{
	unsigned long v = (unsigned long) p;

	if (p == NULL)
		return false;

	if (!looks_like_corrupted_ptr(rec, p))
		return true;

	/*
	 * Heap-shaped but misaligned -- the exact band that bypasses the
	 * outer-ptr alignment guard (because the outer ptr passes) but
	 * trips libasan's PoisonShadow CHECK once the inner field reaches
	 * free().  Surface it explicitly so log scanners can correlate the
	 * interception with the asan_poisoning.cpp:37 crash signature; the
	 * per-handler attribution ring already names the syscall via rec.
	 */
	if (v >= 0x10000 && (v & 0x7) != 0)
		outputerr("%s: rejected misaligned heap-shaped inner ptr=0x%lx "
			  "(libasan PoisonShadow trigger; scribbled?)\n",
			  site, v);
	return false;
}

/*
 * Cached extent of the brk()-managed glibc arena, captured once at
 * init time from /proc/self/maps.  COW-shared into every forked
 * child, so a single pre-fork parse seeds the whole fleet.  heap_start
 * is stable for the lifetime of the process (the brk base doesn't
 * move), but heap_end is only a snapshot -- a child that extends brk
 * post-fork (millions of iterations of getline in /proc parsers,
 * libasan shadow growth, heavy zmalloc traffic) sails past it, so
 * consumers also consult sbrk(0) for the current break.  Zero start
 * means we never found a [heap] line; in that case is_in_glibc_heap()
 * falls back to "always true" so we don't reject legitimate frees on
 * platforms or builds where glibc has chosen an mmap-only allocation
 * strategy and the brk arena is empty.
 */
static unsigned long heap_start;
static unsigned long heap_end;

/*
 * Per-child cached snapshot of sbrk(0), refreshed at heap_bounds_init()
 * time and then on every BRK_REFRESH_INTERVAL alloc_object() call via
 * heap_brk_maybe_refresh().  Used by is_in_glibc_heap() and
 * range_overlaps_libc_heap() instead of a per-call sbrk(0) -- those
 * gates fire on every deferred-free check and every random-address
 * generation, and the syscall-per-call was showing up in profiles.
 *
 * Staleness is bounded by the refresh cadence: in the worst case a
 * brk grow that happens between refreshes is invisible until the next
 * refresh fires, so a fuzzed pointer that lands in the extension is
 * not detected as heap-internal during that window.  brk grows in
 * page-or-larger chunks at a much lower rate than alloc_object() is
 * called (most allocations are served from the existing arena), so
 * the window is small in absolute address space.  Refresh tied to
 * alloc_object() means a brk grow caused by an allocation gets caught
 * by the next refresh that fires, and refresh-on-zero ensures
 * pre-init callers see "unknown extent" rather than a stale value.
 */
#define BRK_REFRESH_INTERVAL 64
static unsigned long cached_brk_end;
static unsigned int brk_refresh_counter;

/*
 * Upper VA at which the self-correcting brk re-test in
 * is_in_glibc_heap() and range_overlaps_libc_heap() stops paying
 * one sbrk(0) to resample the live break.  Any addr that sits at or
 * above the cached upper bound AND below this ceiling is plausibly
 * inside a brk extension that the cache hasn't caught up with;
 * addr >= ceiling is unambiguously not-heap (kernel VA, non-canonical)
 * and skips the syscall.
 *
 * Prior revisions capped the re-test with a fixed 256 MiB slack above
 * cached_brk_end.  That ceiling was tight enough that non-alloc_object()
 * traffic -- cmp-hint / RedQueen pool inflation, sequence record growth
 * -- could extend live brk past cached_brk_end + 256 MiB between
 * BRK_REFRESH_INTERVAL ticks, opening a window where a fuzzed
 * mmap(MAP_FIXED, PROT_READ) landing in the live-brk extension sailed
 * past the guard and stamped a read-only page on brk arena bookkeeping.
 * The downstream get_writable_address() upgrade then stored
 * map->known_rw=true on the now-RO page and the child took SEGV_ACCERR.
 *
 * The new ceiling is the user/kernel split (0x800000000000UL on
 * x86_64): below it, an address is canonical userspace and the
 * resample is cheap insurance against the staleness window; at or
 * above it, the address is kernel-VA or non-canonical and no sbrk(0)
 * will ever vouch for it.  The resampled live_brk back-fills
 * cached_brk_end so a workload that keeps hammering similar addresses
 * benefits from the freshly-refreshed cache on subsequent calls.
 */
#define HEAP_BRK_RETEST_CEILING		0x800000000000UL

static void heap_brk_refresh(void)
{
	unsigned long cur = (unsigned long) sbrk(0);

	if (cur != (unsigned long) -1)
		cached_brk_end = cur;
}

void heap_brk_maybe_refresh(void)
{
	if (++brk_refresh_counter < BRK_REFRESH_INTERVAL)
		return;
	brk_refresh_counter = 0;
	heap_brk_refresh();
}

/*
 * Cached extents of non-brk allocator arenas, captured alongside the
 * [heap] line at heap_bounds_init() time.  glibc's mmap'd arenas, the
 * sanitiser-runtime allocator reservations (libasan primary/secondary
 * at 0x511000000000+, the shadow region, ...), scudo / jemalloc /
 * tcmalloc -- every well-behaved allocator labels its anonymous
 * mappings via prctl(PR_SET_VMA_ANON_NAME), which shows up in
 * /proc/self/maps as "[anon:NAME]" after the inode column.  Trinity
 * itself does not label any of its scratch mappings, so an
 * "[anon:*]" tag in the pre-fork snapshot identifies a region whose
 * contents must not be overwritten by a fuzzed kernel-write
 * argument (the alternative is a write into glibc / libasan chunk
 * metadata, surfacing later as an arena-corruption abort or an
 * ASAN bad-free).
 *
 * 16 entries comfortably covers the regions seen on a libasan-built
 * trinity under glibc 2.39 (one [heap], two glibc mmap arenas, four
 * libasan shadow / allocator regions); an overflow logs once and
 * leaves the trailing regions unprotected -- the wrong direction for
 * safety, so the cap exists to be hit and bumped if a future libsan
 * layout adds more regions.
 */
#define MAX_EXTRA_HEAP_REGIONS	16
struct heap_region {
	unsigned long start;
	unsigned long end;
};
static struct heap_region extra_heap_regions[MAX_EXTRA_HEAP_REGIONS];
static unsigned int nr_extra_heap_regions;

/*
 * Bounding box (min start, max end) over extra_heap_regions[],
 * recomputed atomically in heap_bounds_init() alongside the slot
 * snapshot.  Used by range_overlaps_libc_heap() as a coarse
 * "looks heap-shaped" signal: a query that falls inside the bbox
 * but matches no specific slot is the canonical staleness shape --
 * a post-init secondary mmap (large malloc one-VMA-per-alloc) that
 * landed between the captured slots and is therefore not in the
 * snapshot.  Bbox is empty (end <= start) when no extras have been
 * captured, in which case the predicate degenerates to "never".
 */
static unsigned long extra_heap_regions_bbox_start;
static unsigned long extra_heap_regions_bbox_end;

/*
 * Threshold of "looks heap-shaped but missed all slots" observations
 * before range_overlaps_libc_heap() pays for one /proc/self/maps
 * re-parse and rebuilds extra_heap_regions[].  Set high enough that
 * the common cache-hit path stays at its existing cost (a few
 * compares), low enough that a real post-init secondary mmap is
 * picked up within a small bounded number of misses.  Per-child
 * static -- a child whose own allocator just spawned a new arena
 * refreshes once and then stops missing.
 */
#define HEAP_OUTSIDE_CACHE_REFRESH_THRESHOLD 64

/*
 * Parse a /proc/self/maps line just enough to extract the
 * [start, end), the perms field, and the trailing path/label.  Returns
 * true on success.  The label pointer (which may be NULL or point at
 * the empty string) is written into *label_out; it points into @line,
 * which the caller owns.
 *
 * A line looks like:
 *   55a1b3c00000-55a1b3c21000 rw-p 00000000 00:00 0   [heap]
 *   7f2c1b400000-7f2c1b421000 rw-p 00000000 00:00 0   [anon:libc_malloc]
 *   55a1b3a00000-55a1b3a21000 rw-p 00000000 00:00 0
 * i.e. start-end perms offset major:minor inode optional-label.
 */
static bool parse_maps_line(char *line, unsigned long *start_out,
			    unsigned long *end_out, char perms_out[5],
			    const char **label_out)
{
	unsigned long start, end;
	char perms[8];
	int label_off = -1;
	const char *label;
	char *nl;

	nl = strchr(line, '\n');
	if (nl != NULL)
		*nl = '\0';

	if (sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*u %n",
		   &start, &end, perms, &label_off) < 3)
		return false;
	if (end <= start)
		return false;

	if (label_off < 0 || (size_t) label_off > strlen(line))
		label = "";
	else
		label = line + label_off;

	*start_out = start;
	*end_out = end;
	memcpy(perms_out, perms, 4);
	perms_out[4] = '\0';
	*label_out = label;
	return true;
}

/*
 * Parse /proc/self/maps and stash the brk arena plus every labeled
 * non-brk allocator region.  Called once pre-fork by the parent and
 * once per child from init_child() (after all the post-fork startup
 * mmap traffic has settled) so glibc mmap arenas that the child's
 * own allocator storm spawned after fork are captured -- without the
 * per-child re-parse, those arenas live outside the inherited
 * snapshot and a wild pointer landing in one slips past the overlap
 * gate, letting the kernel scribble glibc chunk metadata and
 * surfacing later as an arena-corruption abort with no proximate
 * reproducer.
 *
 * The parse is committed atomically into module state on success.
 * A failed open (vanishingly rare for /proc/self/maps on our own
 * pid) preserves whatever snapshot was previously in place: the
 * child's COW-inherited parent snapshot stays valid as a fallback
 * rather than collapsing to an empty validator that lets every
 * address through.
 *
 * If the [heap] line is missing (rare: glibc tuned to
 * MALLOC_MMAP_THRESHOLD_=0 or the binary somehow hasn't grown brk
 * yet), heap_start stays 0 and is_in_glibc_heap() falls back to
 * "always true" -- we'd rather permit a marginal free than reject
 * every malloc result on a misconfigured host.
 */
void heap_bounds_init(void)
{
	FILE *f;
	char line[512];
	unsigned long new_heap_start = 0, new_heap_end = 0;
	struct heap_region new_regions[MAX_EXTRA_HEAP_REGIONS];
	unsigned int new_nr = 0;

	f = fopen("/proc/self/maps", "r");
	if (f == NULL) {
		outputerr("heap_bounds_init: open /proc/self/maps failed: %s\n",
			  strerror(errno));
		return;
	}

	while (fgets(line, sizeof(line), f) != NULL) {
		unsigned long start, end;
		char perms[5];
		const char *label;

		if (!parse_maps_line(line, &start, &end, perms, &label))
			continue;

		/*
		 * Only writable private mappings can hold allocator
		 * metadata that the kernel scribbling would corrupt.
		 * Read-only and shared mappings either can't be written
		 * by the kernel (r-- / r-x) or are trinity-controlled
		 * (MAP_SHARED via alloc_shared / track_shared_region,
		 * handled separately by range_overlaps_shared()).
		 */
		if (perms[1] != 'w' || perms[3] != 'p')
			continue;

		if (strncmp(label, "[heap]", 6) == 0 &&
		    (label[6] == '\0' || label[6] == ' ')) {
			new_heap_start = start;
			new_heap_end = end;
			continue;
		}

		/*
		 * "[anon:NAME]" labels come from
		 * prctl(PR_SET_VMA_ANON_NAME) -- glibc malloc tags its
		 * mmap'd arenas, libasan tags its primary / secondary
		 * allocator and shadow reservations, similarly for
		 * scudo / jemalloc / tcmalloc.  Trinity never labels
		 * its own anonymous mappings, so any "[anon:*]" line
		 * in the snapshot belongs to a non-trinity allocator.
		 * Trinity's BSS, stack, vdso, vvar, file-backed
		 * mappings and unlabeled scratch regions are filtered
		 * out by the perms / label tests above.
		 */
		if (strncmp(label, "[anon:", 6) != 0)
			continue;

		if (new_nr >= MAX_EXTRA_HEAP_REGIONS) {
			static bool warned;

			/*
			 * The outputerr fires once per process so the log
			 * doesn't blow up when many regions overflow; the
			 * counter advances on every dropped region so the
			 * post-mortem reader sees the deficit size rather
			 * than just "deficit existed".
			 */
			__atomic_add_fetch(
				&shm->stats.heap_extra_regions_overflow, 1,
				__ATOMIC_RELAXED);

			if (!warned) {
				warned = true;
				outputerr("heap_bounds_init: "
					"MAX_EXTRA_HEAP_REGIONS (%d) reached "
					"-- '%s' and any subsequent allocator "
					"regions are unprotected; raise the "
					"cap\n",
					MAX_EXTRA_HEAP_REGIONS, label);
			}
			continue;
		}

		new_regions[new_nr].start = start;
		new_regions[new_nr].end = end;
		new_nr++;
	}

	fclose(f);

	/*
	 * Commit the freshly-parsed snapshot in one shot.  On the
	 * child-side refresh path this rewrites the COW-inherited
	 * parent snapshot in the child's now-private BSS pages; the
	 * parent's copy and any sibling's copy are unaffected.
	 */
	heap_start = new_heap_start;
	heap_end = new_heap_end;
	memcpy(extra_heap_regions, new_regions,
	       new_nr * sizeof(new_regions[0]));
	nr_extra_heap_regions = new_nr;

	/*
	 * Recompute the extras bbox alongside the slot snapshot.  An
	 * empty snapshot leaves the bbox closed (start=end=0) so the
	 * "looks heap-shaped" predicate in range_overlaps_libc_heap()
	 * cannot fire spuriously when extras are not yet populated.
	 */
	if (new_nr > 0) {
		unsigned long bbox_lo = new_regions[0].start;
		unsigned long bbox_hi = new_regions[0].end;
		unsigned int i;

		for (i = 1; i < new_nr; i++) {
			if (new_regions[i].start < bbox_lo)
				bbox_lo = new_regions[i].start;
			if (new_regions[i].end > bbox_hi)
				bbox_hi = new_regions[i].end;
		}
		extra_heap_regions_bbox_start = bbox_lo;
		extra_heap_regions_bbox_end = bbox_hi;
	} else {
		extra_heap_regions_bbox_start = 0;
		extra_heap_regions_bbox_end = 0;
	}

	/*
	 * Prime the brk cache so the first is_in_glibc_heap() /
	 * range_overlaps_libc_heap() doesn't see 0.
	 */
	heap_brk_refresh();
}

/*
 * Bounds check: is @p inside any captured glibc-managed allocator
 * region?  Accepts the cached brk arena AND the labeled non-brk
 * allocator regions stashed by heap_bounds_init() (glibc mmap arenas,
 * libasan primary/secondary/shadow, scudo / jemalloc / tcmalloc
 * tagged regions -- see extra_heap_regions[]).  Returns true if no
 * allocator extent is known at all (init found neither a [heap] line
 * nor any [anon:NAME] regions) so the caller treats the validator as
 * permissive in that case.
 *
 * Earlier revisions only checked the brk arena, which silently
 * rejected legitimate frees of two important pointer classes:
 *   - allocations above MMAP_THRESHOLD (default 128 KiB), which glibc
 *     services from mmap'd arenas rather than brk, and
 *   - every allocation under ASAN, whose libasan-runtime allocator
 *     hands back chunks from its shadow-mapped pools outside brk.
 * The high deferred_free_reject rate seen in ASAN runs was this gate
 * dropping valid zmalloc() results.
 *
 * Backstop for the bad-free class where a sibling stomp scribbles a
 * snapshot/arg slot with a value that defeats both the pointer-shape
 * heuristic (looks_like_corrupted_ptr) and -- in the worst case --
 * coincidentally matches a tracked malloc result still resident in
 * the alloc-track ring.  An attacker-controlled or wildly-stomped
 * value that lands outside every allocator region (stack, shared
 * region, mmap'd library, executable mapping) is rejected here even
 * if the upstream guards let it through.
 */
bool is_in_glibc_heap(const void *p)
{
	unsigned long v = (unsigned long) p;
	unsigned long end, cur;
	unsigned int i;

	if (heap_start == 0 && nr_extra_heap_regions == 0)
		return true;

	if (heap_start != 0) {
		/*
		 * heap_end is a pre-fork snapshot.  A long-running child
		 * can extend brk past it, so the cached_brk_end snapshot
		 * (refreshed periodically off alloc_object() via
		 * heap_brk_maybe_refresh()) is the live upper bound; brk
		 * only grows in the steady state, so the larger of the two
		 * is the safe outer edge.  cached_brk_end is 0 before its
		 * first refresh and after a sbrk(0) failure -- the max()
		 * falls back to the pre-fork heap_end in that case.
		 */
		end = heap_end;
		cur = cached_brk_end;
		if (cur > end)
			end = cur;

		if (v >= heap_start && v < end)
			return true;

		/*
		 * Mirror of the self-correcting brk re-test in
		 * range_overlaps_libc_heap().  The cached snapshot just
		 * judged this pointer not-heap, but brk may have grown past
		 * cached_brk_end since the last heap_brk_maybe_refresh()
		 * tick (heavy non-alloc_object() allocator traffic outruns
		 * the alloc-driven refresh cadence).  Without the re-test, a
		 * deferred-free backstop that lands in [cached_brk_end,
		 * live_brk) marks a real heap chunk as not-heap and silently
		 * drops the free.  Pay one sbrk(0) when the pointer sits at
		 * or above the cached bound but below the user/kernel split
		 * (HEAP_BRK_RETEST_CEILING -- wild-high / kernel-VA / non-
		 * canonical pointers skip the syscall), refresh the cache,
		 * and re-check; return true if it now falls in the live
		 * arena.  The fixed 256 MiB slack the prior revision used
		 * was tight enough that cmp-hint / RedQueen traffic could
		 * outrun it between refreshes -- see HEAP_BRK_RETEST_CEILING.
		 */
		if (v >= end && v < HEAP_BRK_RETEST_CEILING) {
			unsigned long live_brk = (unsigned long) sbrk(0);

			if (live_brk != (unsigned long) -1) {
				if (live_brk > cached_brk_end)
					cached_brk_end = live_brk;
				if (live_brk > end)
					end = live_brk;
				if (v >= heap_start && v < end) {
					struct childdata *c = this_child();

					if (c != NULL && c->stats_ring != NULL)
						stats_ring_enqueue(c->stats_ring,
								   STATS_FIELD_HEAP_BRK_STALE_WINDOW_HIT,
								   0, 1);
					else
						parent_stats.heap_brk_stale_window_hit++;
					return true;
				}
			}
		}
	}

	for (i = 0; i < nr_extra_heap_regions; i++) {
		if (v >= extra_heap_regions[i].start &&
		    v < extra_heap_regions[i].end)
			return true;
	}

	return false;
}

/*
 * Range-overlap variant of is_in_glibc_heap() with the opposite
 * unknown-bounds polarity: returns true when [addr, addr+len)
 * intersects the cached brk arena or any captured non-brk allocator
 * region (glibc mmap arenas, libasan primary / secondary / shadow,
 * scudo / jemalloc / tcmalloc tagged regions -- see
 * extra_heap_regions[] above).  Used by avoid_shared_buffer() to
 * redirect output-buffer syscall args away from any allocator-managed
 * memory: a fuzzed pointer pointing there lets the kernel scribble
 * chunk metadata, and the next malloc anywhere in trinity finds the
 * corruption and aborts (the cluster from the overnight asan-self-
 * kill triage).  Mirrors range_overlaps_shared() semantics: a single
 * byte of overlap is enough to redirect, and a fully unknown layout
 * (no [heap] line and no captured allocator regions) is treated as
 * no-overlap so we don't redirect every legitimate write.
 */
bool range_overlaps_libc_heap(unsigned long addr, unsigned long len)
{
	unsigned long end, hend, cur;
	unsigned int i;

	/* Treat wrapped ranges as overlapping so callers reject them. */
	if (len != 0 && addr > ULONG_MAX - len)
		return true;

	end = addr + len;
	if (end == addr)
		end = addr + 1;

	if (heap_start != 0) {
		/*
		 * Same brk-grew-past-snapshot story as
		 * is_in_glibc_heap(), with the same cached_brk_end
		 * snapshot for the live upper bound.  Missing the
		 * redirect here is the safety-critical failure mode: a
		 * fuzzed pointer landing in the brk extension above the
		 * cached heap_end gets through avoid_shared_buffer(), the
		 * kernel scribbles glibc chunk metadata in the extension,
		 * and the next malloc in the child aborts.  The cache
		 * staleness window (one BRK_REFRESH_INTERVAL of
		 * alloc_object() calls) is bounded by the refresh cadence
		 * driven off the alloc path -- a brk grow caused by an
		 * allocation gets picked up within INTERVAL allocations.
		 */
		hend = heap_end;
		cur = cached_brk_end;
		if (cur > hend)
			hend = cur;

		if (addr < hend && end > heap_start)
			return true;

		/*
		 * Self-correcting brk re-test.  The cached snapshot just
		 * judged this address not-heap, but brk may have grown past
		 * cached_brk_end since the last heap_brk_maybe_refresh()
		 * tick.  Heavy non-alloc_object() allocator traffic
		 * (cmp-hint / RedQueen tables, sequence record growth)
		 * extends the real brk without ticking the alloc-driven
		 * refresh, opening a window where glibc's top chunk -- or a
		 * brk-arena bookkeeping page -- sits in [cached_brk_end,
		 * live_brk) and a fuzzed output / MAP_FIXED address in that
		 * band gets handed to the kernel instead of being
		 * relocated.  Symptoms: the kernel scribbles top->size and
		 * the next malloc anywhere in the child aborts with
		 * "malloc(): corrupted top size"; or a fuzzed
		 * mmap(MAP_FIXED, PROT_READ) lands on brk arena and the
		 * next get_writable_address() upgrade SEGV_ACCERRs on the
		 * known_rw=true store.  Pay one sbrk(0) when the address
		 * sits at or above the cached bound but below the
		 * user/kernel split (HEAP_BRK_RETEST_CEILING -- wild-high /
		 * kernel-VA / non-canonical addresses skip the syscall),
		 * refresh the cache, and re-test the brk arm; if the
		 * address now falls in the live arena, redirect it (return
		 * true).  Prior revision capped this at a fixed 256 MiB
		 * slack above hend, which the cmp-hint / RedQueen traffic
		 * outran between refreshes -- see HEAP_BRK_RETEST_CEILING.
		 * The counter, kept in place, signals the fix firing.
		 */
		if (addr >= hend && addr < HEAP_BRK_RETEST_CEILING) {
			unsigned long live_brk = (unsigned long) sbrk(0);

			if (live_brk != (unsigned long) -1) {
				if (live_brk > cached_brk_end)
					cached_brk_end = live_brk;
				if (live_brk > hend)
					hend = live_brk;
				if (addr < hend && end > heap_start) {
					struct childdata *c = this_child();

					if (c != NULL && c->stats_ring != NULL)
						stats_ring_enqueue(c->stats_ring,
								   STATS_FIELD_HEAP_BRK_STALE_WINDOW_HIT,
								   0, 1);
					else
						parent_stats.heap_brk_stale_window_hit++;
					return true;
				}
			}
		}
	}

	/*
	 * Walk the captured non-brk allocator regions.  Each entry is
	 * a fixed [start, end) snapshot from heap_bounds_init(), which
	 * the parent runs once pre-fork and each child re-runs at the
	 * end of init_child() so glibc arenas that the child's own
	 * post-fork allocator storm spawned (per-thread mmap arenas,
	 * libasan shadow growth, secondary allocator regions tagged
	 * via PR_SET_VMA_ANON_NAME) make it into the snapshot before
	 * the syscall fuzz loop starts hammering pointers through this
	 * gate.  The captured VMAs are large reservations whose bounds
	 * don't shrink and rarely grow once the child is settled, so a
	 * single refresh per child closes the post-fork window without
	 * touching the hot path.
	 */
	for (i = 0; i < nr_extra_heap_regions; i++) {
		if (addr < extra_heap_regions[i].end &&
		    end > extra_heap_regions[i].start)
			return true;
	}

	/*
	 * Post-init secondary-mmap miss detector.  Falling through to
	 * here means brk and every captured slot rejected the range,
	 * but the query still falls inside the bounding box that spans
	 * the captured slots -- the canonical shape of a libc large-
	 * malloc that bypassed the primary allocator into a fresh
	 * one-VMA-per-alloc landing between two captured arenas after
	 * the heap_bounds_init() snapshot was taken.  Bump an
	 * observability counter so the rate is visible in dump_stats(),
	 * and after every HEAP_OUTSIDE_CACHE_REFRESH_THRESHOLD misses
	 * pay for one /proc/self/maps re-parse and rescan the (now
	 * fresh) extras for this same query.  A genuine post-init mmap
	 * promotes to a real overlap on the rescan and the redirect
	 * fires for the very call that triggered the refresh; a query
	 * inside the bbox that doesn't correspond to any allocator VMA
	 * (sparse extras layout) leaves the snapshot unchanged and the
	 * counter resets, capping the refresh cost at one
	 * /proc/self/maps walk per THRESHOLD misses.
	 */
	if (extra_heap_regions_bbox_end > extra_heap_regions_bbox_start &&
	    addr < extra_heap_regions_bbox_end &&
	    end > extra_heap_regions_bbox_start) {
		static unsigned int outside_cache_since_refresh;
		struct childdata *c;

		c = this_child();
		if (c != NULL && c->stats_ring != NULL)
			stats_ring_enqueue(c->stats_ring,
					   STATS_FIELD_HEAP_POINTER_OUTSIDE_CACHE,
					   0, 1);
		else
			parent_stats.heap_pointer_outside_cache++;

		if (++outside_cache_since_refresh >=
		    HEAP_OUTSIDE_CACHE_REFRESH_THRESHOLD) {
			outside_cache_since_refresh = 0;
			heap_bounds_init();

			for (i = 0; i < nr_extra_heap_regions; i++) {
				if (addr < extra_heap_regions[i].end &&
				    end > extra_heap_regions[i].start)
					return true;
			}
			/* Re-check the brk arena too: heap_bounds_init()
			 * refreshes the brk cache as well, so a query that
			 * tripped because cached_brk_end was stale now
			 * resolves cleanly. */
			if (heap_start != 0) {
				unsigned long hend2 = heap_end;

				if (cached_brk_end > hend2)
					hend2 = cached_brk_end;
				if (addr < hend2 && end > heap_start)
					return true;
			}
		}
	}

	return false;
}

/*
 * Fast-path inverse-polarity check: is [addr, addr+len) fully inside
 * the cached brk arena, or fully inside any single captured non-brk
 * allocator region?  Mirrors range_in_tracked_shared() for the heap
 * snapshot maintained by heap_bounds_init().  Used only by
 * range_readable_user() below -- not a sanitiser gate, so unknown
 * layout returns false (no cached extent implies no proof of
 * readability; the caller treats that as skip-copy).
 */
bool range_inside_libc_heap(unsigned long addr, unsigned long len)
{
	unsigned long end, hend, cur;
	unsigned int i;

	if (len != 0 && addr > ULONG_MAX - len)
		return false;

	end = addr + len;

	if (heap_start != 0) {
		hend = heap_end;
		cur = cached_brk_end;
		if (cur > hend)
			hend = cur;

		if (addr >= heap_start && end <= hend)
			return true;
	}

	for (i = 0; i < nr_extra_heap_regions; i++) {
		if (addr >= extra_heap_regions[i].start &&
		    end <= extra_heap_regions[i].end)
			return true;
	}

	return false;
}

/*
 * Diagnostic helper for the mm-syscall arg sanitisers.  Called from each
 * mm-syscall hook (madvise / mmap / mprotect / mremap / mseal /
 * remap_file_pages) AFTER the brk-overlap gate
 * (range_overlaps_libc_heap) has returned "not heap" for [addr, addr+len)
 * and the per-syscall sanitiser has finished any further addr rewrites.
 * Pays one fresh sbrk(0) and, if the address now proves to lie inside
 * the live brk arena, bumps a counter and (rate-limited) logs the
 * slipping syscall so the next live run pins exactly which call passed
 * the gate with a stale snapshot.
 *
 * Two prior rounds widened the gate without pinning the slipping
 * syscall directly: the first capped the re-test at HEAP_BRK_STALE_
 * SLACK_BYTES (256 MiB) of slack above cached_brk_end, then the
 * widening to HEAP_BRK_RETEST_CEILING raised the ceiling to the
 * user/kernel split.  The live fleet kept faulting on RO-page writes
 * and glibc check_uid SIGABRTs anyway, which means a path either still
 * skips the re-test or there is a sanitise->syscall race the gate
 * never sees.  This helper makes the next round of triage data-driven
 * rather than another speculative widening.
 *
 * Pure observability -- does NOT rewrite the slipping addr (that would
 * pre-judge which gate is at fault; the log lets a real audit make
 * that call from fleet data).  Children inherit the rate-limiter via
 * the file-static counter; per-process limiter is fine for diagnostic
 * spam control.
 *
 *   @syscall_name : mm-syscall short name (madvise / mmap / ...).
 *   @addr, @len   : the (post-sanitise) range about to be handed to
 *                   the kernel.
 *   @detail       : per-syscall context arg -- madvise advice, mprotect
 *                   prot, mmap flags, etc.  Recorded verbatim in the
 *                   log line so the post-hoc filter can split by class.
 */
#define MM_GATE_SLIP_LOG_BURST		8
#define MM_GATE_SLIP_LOG_PERIOD		4096

void log_mm_syscall_post_gate_heap_slip(const char *syscall_name,
					unsigned long addr,
					unsigned long len,
					unsigned long detail)
{
	static unsigned int slip_log_count;
	struct childdata *c;
	unsigned long fresh_brk, end;
	unsigned int my_count;

	if (addr == 0 || len == 0)
		return;
	if (heap_start == 0)
		return;

	/* Wild-high / kernel-VA / non-canonical addrs cannot be heap. */
	if (addr >= HEAP_BRK_RETEST_CEILING)
		return;

	/* Wrap guard: a wrapped range is its own bug, not a brk slip. */
	if (addr > ULONG_MAX - len)
		return;

	/* Entirely below the brk base -- no way the gate is wrong here. */
	if (addr + len <= heap_start)
		return;

	fresh_brk = (unsigned long) sbrk(0);
	if (fresh_brk == (unsigned long) -1)
		return;

	end = fresh_brk;
	if (heap_end > end)
		end = heap_end;
	if (cached_brk_end > end)
		end = cached_brk_end;

	/* Fresh resample agrees with the gate: addr is above the live
	 * brk, so the gate was right to pass it through. */
	if (addr >= end)
		return;

	/* Back-fill the cache: we paid the syscall, no reason not to. */
	if (fresh_brk > cached_brk_end)
		cached_brk_end = fresh_brk;

	c = this_child();
	if (c != NULL && c->stats_ring != NULL)
		stats_ring_enqueue(c->stats_ring,
				   STATS_FIELD_MM_GATE_POST_SLIP, 0, 1);
	else
		parent_stats.mm_gate_post_slip++;

	my_count = __atomic_fetch_add(&slip_log_count, 1, __ATOMIC_RELAXED);
	if (my_count < MM_GATE_SLIP_LOG_BURST ||
	    ((my_count - MM_GATE_SLIP_LOG_BURST) %
	     MM_GATE_SLIP_LOG_PERIOD) == 0)
		outputerr("MM-GATE-POST-SLIP: %s addr=0x%lx len=0x%lx "
			  "detail=0x%lx heap_start=0x%lx heap_end=0x%lx "
			  "cached_brk_end=0x%lx fresh_sbrk=0x%lx\n",
			  syscall_name, addr, len, detail, heap_start,
			  heap_end, cached_brk_end, fresh_brk);
}

bool range_readable_user(const void *addr, size_t len)
{
	unsigned long a = (unsigned long) addr;

	if (len == 0)
		return false;
	if (addr == NULL)
		return false;
	if (a > ULONG_MAX - len)
		return false;

	/*
	 * Fast path 1: range is fully inside a tracked shared region.
	 * Trinity owns those mappings outright -- alloc_shared() creates
	 * them PROT_READ|PROT_WRITE and they live for the run, so VMA
	 * presence implies the source bytes are readable.
	 */
	if (range_in_tracked_shared(a, len))
		return true;

	/*
	 * Fast path 2: range is fully inside the cached libc heap (brk
	 * arena) or any captured non-brk allocator region.  Allocator
	 * mappings are PROT_READ|PROT_WRITE by construction; the
	 * heap_bounds_init() snapshot only records writable private VMAs.
	 */
	if (range_inside_libc_heap(a, len))
		return true;

	/*
	 * Unknown layout: a fuzz-introduced VMA outside every cached
	 * snapshot.  Treat as unproven and let the caller route to
	 * asb_relocate()'s no-copy fallback -- chasing the source via a
	 * /proc/self/maps walk on every hot-path call is what this code
	 * was retired to avoid.
	 */
	return false;
}

bool post_snapshot_str(char *dst, size_t dstsz, const char *src)
{
	size_t i;

	if (dst == NULL || dstsz == 0)
		return false;
	if (src == NULL)
		return false;

	/*
	 * Single-probe readability gate.  range_readable_user proves the
	 * full dstsz-byte window of src is mapped (tracked-shared region
	 * or cached libc heap); the copy loop below then never reads past
	 * what we proved.  False here means src is not provably readable
	 * and the caller skips the .post sample rather than feeding a
	 * stale heap-shaped pointer into a downstream strncpy that would
	 * walk off an unrelated allocation.  ASAN catches that walk-off in
	 * test; in production it silently surfaces as an oracle anomaly
	 * against a foreign byte pattern.
	 */
	if (!range_readable_user(src, dstsz))
		return false;

	/*
	 * Same TOCTOU window as post_snapshot_or_skip: a sibling
	 * mprotect/munmap between the readability proof and the read can
	 * fault the src[i] load.  Guard the copy loop with the
	 * asb_copy_active sigsetjmp slot so the fault degrades to a
	 * skipped sample rather than a child crash.
	 */
	if (sigsetjmp(asb_copy_recover, 1) != 0) {
		asb_copy_active = 0;
		return false;
	}
	asb_copy_active = 1;
	for (i = 0; i + 1 < dstsz; i++) {
		char c = src[i];

		dst[i] = c;
		if (c == '\0') {
			asb_copy_active = 0;
			return true;
		}
	}
	dst[i] = '\0';
	asb_copy_active = 0;
	return true;
}

bool post_snapshot_or_skip(void *dst, const void *src, size_t len)
{
	if (src == NULL)
		return false;

	/*
	 * Single-probe readability gate, identical in shape to the one
	 * in post_snapshot_str().  The post oracle's NULL + shape-only
	 * looks_like_corrupted_ptr guard waves through a heap-shaped but
	 * stale/unmapped snap->field; range_readable_user proves the
	 * full len-byte window is mapped (tracked-shared region or
	 * cached libc heap), so the memcpy below cannot fault on the
	 * sibling free / unmap / fuzz-redirect window between the
	 * syscall return and the post sample.  False here means the
	 * caller skips the .post sample rather than feeding the
	 * downstream oracle a foreign byte pattern.
	 */
	if (!range_readable_user(src, len))
		return false;

	/*
	 * range_readable_user() proves src is mapped per trinity's
	 * shared/heap bookkeeping, but a sibling syscall can mprotect or
	 * munmap the tracked region in the window between that check and
	 * this copy.  Guard the memcpy with the asb_copy_active sigsetjmp
	 * slot (the same recovery the get_writable_struct relocate-copy
	 * uses) so a TOCTOU fault skips the .post sample instead of
	 * killing the child.
	 */
	if (sigsetjmp(asb_copy_recover, 1) != 0) {
		asb_copy_active = 0;
		return false;
	}
	asb_copy_active = 1;
	memcpy(dst, src, len);
	asb_copy_active = 0;
	return true;
}

void sanitize_inherited_fds(void)
{
	DIR *dir;
	struct dirent *de;
	int dir_fd;

	dir = opendir("/proc/self/fd");
	if (dir == NULL) {
		outputerr("sanitize_inherited_fds: opendir(/proc/self/fd) failed: %s\n",
			  strerror(errno));
		return;
	}
	dir_fd = dirfd(dir);

	while ((de = readdir(dir)) != NULL) {
		char linkpath[64];
		char target[PATH_MAX];
		char *endp;
		ssize_t n;
		long fdl;
		int fd;

		if (de->d_name[0] == '.')
			continue;

		errno = 0;
		fdl = strtol(de->d_name, &endp, 10);
		if (errno != 0 || *endp != '\0' || fdl < 0 || fdl > INT_MAX)
			continue;
		fd = (int) fdl;

		/* Always keep stdin/stdout/stderr. */
		if (fd <= 2)
			continue;

		/* Skip the readdir() handle itself; closedir() will release
		 * it once the walk completes. */
		if (fd == dir_fd)
			continue;

		n = -1;
		if ((size_t) snprintf(linkpath, sizeof(linkpath),
				      "/proc/self/fd/%d", fd) < sizeof(linkpath))
			n = readlink(linkpath, target, sizeof(target) - 1);
		if (n < 0)
			n = 0;
		target[n] = '\0';

		outputerr("sanitize_inherited_fds: closing unexpected inherited fd %d (%s)\n",
			  fd, n > 0 ? target : "?");

		close(fd);
		if (shm != NULL)
			__atomic_add_fetch(&shm->stats.parent_inherited_fds_closed,
					   1, __ATOMIC_RELAXED);
	}
	closedir(dir);
}

int get_num_fds(void)
{
	struct linux_dirent64 {
		uint64_t       d_ino;
		int64_t        d_off;
		unsigned short d_reclen;
		unsigned char  d_type;
		char           d_name[];
	};
	char path[64];
	char buf[4096];
	int fd, fd_count = 0;
	long nread, pos;

	snprintf(path, sizeof(path), "/proc/%i/fd", mainpid);

	fd = open(path, O_RDONLY | O_DIRECTORY);
	if (fd == -1)
		return 0;

	while ((nread = syscall(SYS_getdents64, fd, buf, sizeof(buf))) > 0) {
		for (pos = 0; pos < nread; ) {
			struct linux_dirent64 *de = (struct linux_dirent64 *)(buf + pos);
			const char *name = de->d_name;

			/* Skip "." and ".." */
			if (!(name[0] == '.' &&
			      (name[1] == '\0' ||
			       (name[1] == '.' && name[2] == '\0'))))
				fd_count++;

			pos += de->d_reclen;
		}
	}

	close(fd);
	return fd_count;
}

/* Plain CRC32 (IEEE 802.3 polynomial, reflected).  Shared by every
 * persistence format trinity emits (minicorpus / cmp_hints /
 * kcov-bitmap) so the headers checksum payloads with one definition
 * instead of byte-identical copies that drift apart silently.  Lazy
 * 256-entry table; first call pays one build, every subsequent call
 * (in any caller) reuses the cached table. */
uint32_t crc32(const void *buf, size_t len)
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

/*
 * Online-CPU count snapshotted on first use.  The kernel rejects
 * sched_setaffinity masks with no bits in cpu_online_mask, so a
 * random CPU_SETSIZE-wide draw misses every legality test path
 * unless we constrain it to the real online range.
 */
unsigned int cached_online_cpus(void)
{
	static unsigned int n;
	long v;

	if (n != 0)
		return n;

	v = sysconf(_SC_NPROCESSORS_ONLN);
	if (v <= 0)
		v = 1;
	if (v > CPU_SETSIZE)
		v = CPU_SETSIZE;
	n = (unsigned int) v;
	return n;
}
