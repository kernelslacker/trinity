#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "breadcrumb_ring.h"
#include "child.h"
#include "debug.h"
#include "deferred-free.h"
#include "params.h"		/* self_corrupt_canary */
#include "pc_format.h"
#include "shm.h"
#include "stats.h"
#include "stats_ring.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"
#include "utils-internal.h"

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
 * Self-corruption attribution logger.  See the docstring on the
 * declaration in include/utils.h for the contract and rationale.
 * Body is one outputerr call with fixed formatters, plus a table
 * lookup for the syscall name -- no allocation, no atomics.
 *
 * Name resolution goes through get_syscall_entry(nr, do32bit)
 * rather than rec->entry: rec sits inside the same struct that
 * the wild write likely scribbled (the whole point of firing
 * this logger), so trusting rec->entry here would risk chasing
 * a wild pointer.  The syscall table is init-time-immutable and
 * safe to read.
 */
/*
 * --self-corrupt-canary state.  Per-child (a plain file-static is
 * per-process, and each trinity child is a fork'd separate process,
 * so different children never see each other's canary buffer).
 * Allocated once in self_corrupt_canary_init_child() when the flag
 * is set; NULL otherwise.  The signature helper folds the sentinel
 * bytes into its XOR-checksum so a scribble that lands in the
 * canary allocation itself (or in one of the tracked pointer fields
 * on struct childdata / struct kcov_child) shows up as a signature
 * delta between the pre-dispatch and post-dispatch computations.
 *
 * SELF_CORRUPT_CANARY_BYTES is a whole number of u64 words so the
 * signature loop is 8 fixed XORs -- bounded, no branches on the
 * happy path, and immune to loop-unroll perturbations from later
 * changes to the buffer size.  The magic pattern is repeated across
 * the buffer so a partial-word scribble is still detectable in the
 * XOR fold; the operator-visible value in the log line is
 * (canary_post ^ canary_pre), which is the exact XOR delta the
 * scribble introduced.
 */
#define SELF_CORRUPT_CANARY_MAGIC	0xdeadbeefcafebabeULL
#define SELF_CORRUPT_CANARY_BYTES	64
#define SELF_CORRUPT_CANARY_WORDS	(SELF_CORRUPT_CANARY_BYTES / sizeof(uint64_t))

static uint64_t *self_corrupt_canary_buf;

void self_corrupt_canary_init_child(void)
{
	uint64_t *buf;
	unsigned int i;

	if (!self_corrupt_canary)
		return;

	buf = zmalloc(SELF_CORRUPT_CANARY_BYTES);
	for (i = 0; i < SELF_CORRUPT_CANARY_WORDS; i++)
		buf[i] = SELF_CORRUPT_CANARY_MAGIC;
	self_corrupt_canary_buf = buf;
}

uint64_t self_corrupt_canary_signature(const struct childdata *child)
{
	uint64_t sig = 0;
	unsigned int i;

	if (!self_corrupt_canary)
		return 0;
	if (child == NULL)
		return 0;

	/*
	 * Tracked-pointer surface: five heap pointers a wild write is
	 * empirically observed to overwrite.  local_stats and objects
	 * are the childdata fields the always-on gates already cover;
	 * the kcov trace / cmp_trace / dedup pointers are inside
	 * struct kcov_child, past the always-on gate surface, and are
	 * exactly the class of "mid-struct scribble that leaves the
	 * VA bracket intact" the canary mode exists to catch.
	 */
	sig ^= (uint64_t)(uintptr_t)child->local_stats;
	sig ^= (uint64_t)(uintptr_t)child->objects;
	sig ^= (uint64_t)(uintptr_t)child->kcov.trace_buf;
	sig ^= (uint64_t)(uintptr_t)child->kcov.cmp_trace_buf;
	sig ^= (uint64_t)(uintptr_t)child->kcov.dedup;

	if (self_corrupt_canary_buf != NULL) {
		for (i = 0; i < SELF_CORRUPT_CANARY_WORDS; i++)
			sig ^= self_corrupt_canary_buf[i];
	}
	return sig;
}

void log_self_corrupt_culprit(const char *site, unsigned long wild,
			      const struct syscallrecord *rec)
{
	struct syscallentry *entry;
	const char *name = "?";
	unsigned int nr = 0;
	unsigned long a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0, a6 = 0;
	bool do32 = false;

	if (rec != NULL) {
		nr = rec->nr;
		do32 = rec->do32bit;
		a1 = rec->a1;
		a2 = rec->a2;
		a3 = rec->a3;
		a4 = rec->a4;
		a5 = rec->a5;
		a6 = rec->a6;

		entry = get_syscall_entry(nr, do32);
		if (entry != NULL && entry->name != NULL)
			name = entry->name;
	}

	outputerr("SELF-CORRUPT [%s] wild=0x%lx | last syscall nr=%u name=%s do32=%d args=0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx\n",
		  site != NULL ? site : "?", wild, nr, name,
		  do32 ? 1 : 0, a1, a2, a3, a4, a5, a6);
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
_Static_assert(sizeof(((struct stats_s *)0)->corrupt_ptr.site_count) ==
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
	__atomic_add_fetch(&shm->stats.corrupt_ptr.site_count[site], 1,
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

void validator_rejected_bump(void)
{
	struct childdata *child;

	/* Standalone headline; not routed through the
	 * post_handler_corrupt_ptr aggregate so the spike-detector on
	 * that counter reads only genuine .post scribble-catches. */
	child = this_child();
	if (child != NULL && child->stats_ring != NULL)
		stats_ring_enqueue(child->stats_ring,
				   STATS_FIELD_VALIDATOR_REJECTED, 0, 1);
	else
		parent_stats.validator_rejected++;

	/* Keep the per-site slot in step with the legacy attribution
	 * path so a TRINITY_CORRUPT_ATTRIB=1 run still shows the class
	 * under the same name.  Gated inside corrupt_ptr_site_record on
	 * the env-latched bool -- production callers pay one branch. */
	corrupt_ptr_site_record(CORRUPT_PTR_SITE_VALIDATOR_REJECTED);
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
	n = __atomic_add_fetch(&shm->stats.corrupt_ptr.sample_seq, 1,
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

