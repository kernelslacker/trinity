#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "child.h"
#include "compiler.h"
#include "debug.h"
#include "deferred-free.h"
#include "maps.h"
#include "objects.h"
#include "objects-internal.h"
#include "params.h"
#include "pc_format.h"
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "registry-internal.h"
#include "shm.h"
#include "stats_ring.h"
#include "utils.h"

/*
 * Per-type hard cap on parent_global_objects[].  High-volume providers
 * (sockets, bpf objs, ...) populated by REG_GLOBAL_OBJ init can balloon
 * an OBJ_GLOBAL pool to tens of thousands of entries pre-fork, which
 * (a) inflates every child's fork-time snapshot heap and (b) flattens
 * get_random_object()'s probability of revisiting any specific obj.
 * 4096 is comfortably above any pool we observe in steady state but low
 * enough to clamp pathological providers.
 */
#define OBJ_GLOBAL_MAX 4096

/*
 * Running count of OBJ_GLOBAL entries evicted by the hard-cap prune in
 * add_object().  Parent-private (the prune path runs only pre-fork, gated
 * by the mainpid guard above the OBJ_GLOBAL branch), so no atomic needed.
 * Surfaced under -v via the verbose output emitted on each prune event.
 */
static unsigned long obj_global_pruned;

static bool is_fd_type(enum objecttype type)
{
	return type >= OBJ_FD_PIPE && type <= OBJ_FD_SCRATCH_BLOCK;
}

/*
 * Global object array backing storage.  Allocated via __zmalloc (plain
 * malloc), so the buffer lives in the parent's PRIVATE heap and is
 * fork-COW'd into every child rather than shared MAP_SHARED.  Children
 * do not read the parent's view directly post-fork: get_objhead()
 * routes them to their own snapshot (clone_global_objects_to_child())
 * and returns NULL when the snapshot is missing, so the COW divergence
 * between the parent's live head->array and the child's frozen view
 * never reaches an indexed read.
 */
/*
 * Up-front input validation for add_object().  Three rejections,
 * all cheaper than the slot-resolution / grow / publish work that
 * follows -- if any of them fires we release the obj back to the
 * deferred-free ring and tell the caller to bail without ever
 * touching the per-type pool:
 *
 *   - the verbose-mode caller trace (gated on -vv, used when
 *     attributing churn back to a specific .post handler),
 *   - the fd-bound rejection check for fd-typed objects (any
 *     value past NR_OPEN is upper-bit corruption that the loose
 *     "(long)retval >= 0" gate in register_returned_fd / the
 *     per-syscall .post handlers let through),
 *   - the OBJ_GLOBAL post-fork guard (OBJ_GLOBAL is pre-fork-only
 *     by construction; a child that reached add_object(OBJ_GLOBAL)
 *     would mutate only its private copy with no benefit).
 *
 * obj->obj_type is stamped between the fd-bound gate and the
 * post-fork guard so the tag is set exactly once on the success
 * path; release_obj()'s memset zeroes it back to OBJ_NONE on the
 * failure paths.
 *
 * The caller_pc parameter is the captured __builtin_return_address(0)
 * from add_object()'s entry, threaded in so the verbose trace and
 * the bad-fd outputerr / post_handler_corrupt_ptr_bump_site PC
 * captures still name the real caller of add_object() rather than
 * this helper's frame.
 *
 * is_fd / fd are hoisted by add_object() from a single is_fd_type()
 * + fd_from_object() pair at function entry and threaded through to
 * here (and onward into the grow / publish helpers) so the same
 * inputs aren't re-resolved 3-4x per fd-returning syscall.  Pure
 * CSE -- the obj's fd union member is not written by any add_object
 * path, so any later re-read would return identical bytes.
 *
 * Returns true if the obj was rejected (release_obj already
 * called -- add_object() must return immediately); false if
 * validation passed and the slot-resolution / grow / publish
 * phases should run.
 */
static bool add_object_validate(struct object *obj, enum obj_scope scope,
				enum objecttype type, void *caller_pc,
				bool is_fd, int fd)
{
	char pcbuf[128];

	if (unlikely(verbosity > 1)) {
		output(2, "ADD-OBJ slot=%p type=%d caller=%s\n", obj, type,
			pc_to_string(caller_pc, pcbuf, sizeof(pcbuf)));
	}

	/*
	 * Reject obviously-corrupted fd values before they enter any pool.
	 * 1<<20 = 1048576 matches the kernel's NR_OPEN ceiling
	 * (include/uapi/linux/fs.h), the absolute upper bound RLIMIT_NOFILE
	 * may be raised to on every distro we exercise -- so any retval
	 * decoding to a value past this is a smoking-gun upper-bit
	 * corruption (sign-extended or wholesale-stomped rec->retval) that
	 * the existing "(long)retval >= 0" gate in register_returned_fd /
	 * the per-syscall .post handlers let through because the lower bits
	 * happened to be positive.
	 */
	if (is_fd && (fd < 0 || fd >= (1 << 20))) {
		outputerr("add_object: rejecting out-of-bound fd=%d "
			  "type=%u caller=%s\n", fd, type,
			  pc_to_string(caller_pc,
				       pcbuf, sizeof(pcbuf)));
		post_handler_corrupt_ptr_bump_site(NULL,
						   caller_pc,
						   "add_object:fd");
		release_obj(obj, scope, type);
		return true;
	}

	/*
	 * Stamp the pool tag now that the obj has passed the fd-bound
	 * gate and is about to enter a pool.  Read back by
	 * objpool_check() in consumers (the post-2026-05-18 audit sweep
	 * across fds/ + syscalls/keyctl.c + childops/misc/kvm-run-churn.c)
	 * to catch wild-obj-pointer derefs the loose 47-bit VA-range
	 * shape check lets through.  release_obj()'s memset zeroes the
	 * chunk on the way back to the deferred-free ring, which
	 * naturally invalidates the tag to OBJ_NONE for any future
	 * stale-pointer reader.
	 */
	obj->obj_type = type;

	/*
	 * OBJ_GLOBAL is pre-fork-only by construction: every provider
	 * REG_GLOBAL_OBJ init runs in the parent before fork_children(),
	 * and the per-child snapshot is taken at fork time.  A post-fork
	 * child that reached add_object(OBJ_GLOBAL) would mutate only its
	 * private copy with no benefit, so route the call to nowhere.
	 */
	if (scope == OBJ_GLOBAL && mypid() != mainpid) {
		release_obj(obj, scope, type);
		return true;
	}

	return false;
}

/*
 * Publish the inbound obj into its resolved slot and run the
 * post-publish bookkeeping: scope-conditional fd-hash registration
 * (with rollback on OBJ_GLOBAL hash-full), the verbose-mode
 * per-object dump, and the LOCAL / GLOBAL prune calls that keep
 * the pool within its steady-state ceiling.
 *
 * Stamp ordering inside the publish block is slot-array first,
 * then array_idx, then the monotonic slot_version tag, then the
 * publish-time fleet op tick, then the head->num_entries bump
 * last -- any consumer that re-reads obj fields off head->array
 * sees a fully-populated obj as soon as num_entries admits it.
 *
 * head / is_fd / fd are resolved once in add_object() and threaded
 * through, so this function does not re-enter get_objhead(),
 * is_fd_type() or fd_from_object() -- behavior-preserving CSE on a
 * hot path.
 *
 * OBJ_GLOBAL fd_hash registration is the only failure path: a
 * fd_hash_insert() reject means the parent's global fd_hash is
 * full -- we roll back the just-published slot (drop num_entries
 * back, NULL the array slot), close the fd that would otherwise
 * leak, release_obj() the inbound obj, and return internally.  No
 * further work follows the publish in the caller.
 */
static void add_object_publish(struct object *obj, enum obj_scope scope,
			       enum objecttype type, struct objhead *head,
			       bool is_fd, int fd)
{
	unsigned int n;

	n = head->num_entries;

	/*
	 * Attribution overlay: log the just-dispatched syscall's SREC if
	 * head->array is outside the userspace-VA bracket the wild-scribble
	 * bands are defined against.  The write below still runs -- this
	 * gate is diagnostic, not a short-circuit -- so a scribbled
	 * head->array still SIGSEGVs the child, but the child bug-log now
	 * carries one SELF-CORRUPT line naming the syscall whose arg-gen
	 * produced the wild write BEFORE the SEGV clobbers the rec.  Same
	 * [0x10000, 2^47) shape kcov_local_stats_plausible / the dispatch-
	 * boundary check use, so a false positive is impossible for any
	 * head->array value zmalloc_tracked could have returned; the only
	 * value that trips it is a scribbled slot.
	 */
	{
		uintptr_t arr = (uintptr_t)head->array;

		if (unlikely(!(arr >= 0x10000UL && arr < 0x800000000000UL))) {
			struct childdata *cc = this_child();

			log_self_corrupt_culprit(
				"objects:add_object", arr,
				cc != NULL ? &cc->syscall : NULL);
		}
	}

	head->array[n] = obj;
	obj->array_idx = n;
	/*
	 * Stamp the per-pool monotonic identity tag.  Pre-increment so
	 * the first issued value is 1; the zero left by release_obj()'s
	 * memset on a freed obj is reserved as a never-issued sentinel.
	 * On the ~4-billion-add counter wrap the pre-increment lands on
	 * 0; step past to 1 so the sentinel stays unissuable and a live
	 * obj is never stamped with the value that marks a freed slot.
	 * Stamped after the slot-array insert and the array_idx assign
	 * so any consumer that re-reads obj fields off head->array sees
	 * a fully populated obj as soon as num_entries below admits it.
	 */
	if (++head->next_slot_version == 0)
		head->next_slot_version = 1;
	obj->slot_version = head->next_slot_version;
	/*
	 * Stamp the publish-time fleet op tick from the child-readable
	 * mirror page.  parent_stats.op_count is MAP_PRIVATE heap so
	 * a child COW-copy goes stale immediately after fork; the
	 * shm_published mirror is the republished, child-visible copy
	 * of the same counter.  No current reader -- pre-stage field
	 * for the upcoming diag-drain consumer.  RELAXED matches the
	 * parent's __atomic_store_n in stats_publish_locked(); a plain
	 * child read racing the parent's atomic write of the same shm
	 * word is a C11 data race.
	 */
	obj->publish_call_nr = shm_published
	      ? __atomic_load_n(&shm_published->fleet_op_count, __ATOMIC_RELAXED)
	      : 0;
	head->num_entries = n + 1;

	/*
	 * Maintain the per-child OBJ_LOCAL OBJ_MMAP_* nonempty-pool mask
	 * that get_map_handle() uses to skip guaranteed-empty pools.  This
	 * publish is the 0->1 transition iff the pre-publish n was zero --
	 * any larger n means the bit is already set.  Only the three mmap
	 * pool types participate; mmap_pool_bit_for_type() returns -1 for
	 * everything else and the branch is skipped.  OBJ_GLOBAL is
	 * parent-only by construction (see add_object_validate's post-fork
	 * guard) and the mask lives in childdata, so the maintenance is
	 * gated on scope == OBJ_LOCAL.
	 */
	if (scope == OBJ_LOCAL && n == 0) {
		int bit = mmap_pool_bit_for_type(type);

		if (bit >= 0) {
			struct childdata *child = this_child();

			if (child != NULL)
				child->mmap_pool_nonempty_mask |= 1u << bit;
		}
	}

	/* Mirror the parent-side global fd hash for OBJ_LOCAL fd-typed
	 * pools so find_local_object_by_fd() resolves in O(1).  The buffer
	 * is lazily allocated by local_fd_hash_insert() on first use. */
	if (scope == OBJ_LOCAL && is_fd && fd >= 0)
		local_fd_hash_insert(head, fd, obj);

	/* Track global fd-type objects in the parent's fd_hash so
	 * remove_object_by_fd() and the per-child snapshot can resolve
	 * them by fd. */
	if (scope == OBJ_GLOBAL && is_fd) {
		if (!fd_hash_insert(fd, obj, type)) {
			outputerr("add_object: fd hash full for type %u, dropping fd %d\n",
				  type, fd);
			head->num_entries = n;
			head->array[n] = NULL;
			if (fd >= 0)
				close(fd);
			release_obj(obj, scope, type);
			return;
		}

		/* Per-provider outstanding-fd gauge: bump on successful
		 * registration into the parent's global fd_hash.  Paired
		 * with the decrement in fd_event_drain()'s CLOSE arm,
		 * which looks the type back up via fd_hash_lookup() on
		 * the consumer side. */
		__atomic_fetch_add(&shm->stats.fd.provider_outstanding[type],
				   1, __ATOMIC_RELAXED);
	}

	/* Per-object dumps are debug noise at startup (NFUTEXES = 5 * cpus
	 * identical "futex: 0 owner:0 scope:1" lines, etc.).  Gate on -vv. */
	if (head->dump != NULL && verbosity > 2)
		head->dump(obj, scope);

	/* if we just added something to a child list, check
	 * to see if we need to do some pruning. */
	if (scope == OBJ_LOCAL)
		prune_objects();

	/*
	 * Hard-cap prune for OBJ_GLOBAL: if this insert pushed the per-type
	 * pool past OBJ_GLOBAL_MAX, evict one random-index entry to keep
	 * the steady-state size at the cap.  Eviction is random-index
	 * rather than LRU because OBJ_GLOBAL pools have no per-entry
	 * timestamp -- they're populated pre-fork in one burst and read
	 * (never aged) thereafter.  Picks may land on the just-inserted
	 * obj at idx num_entries-1 with probability 1/(cap+1); that
	 * degenerates to a no-op insert which is harmless.  destroy_object()
	 * routes through __destroy_object() and so handles destructor +
	 * fd_hash unhook + slot swap-with-last for the evicted entry.
	 *
	 * Pre-fork only: the OBJ_GLOBAL post-fork guard in
	 * add_object_validate() sends every post-fork child's OBJ_GLOBAL
	 * add to release_obj() before we get here, so this branch only
	 * runs in the parent's pre-fork init.  That makes obj_global_pruned
	 * safe to bump without atomics and lets us use the cheap
	 * (non-locked) destroy path.
	 */
	if (scope == OBJ_GLOBAL && head->num_entries > OBJ_GLOBAL_MAX) {
		unsigned int victim_idx = rnd_modulo_u32(head->num_entries);
		struct object *victim = head->array[victim_idx];

		if (victim != NULL) {
			obj_global_pruned++;
			if (unlikely(verbosity > 1)) {
				output(2, "OBJ_GLOBAL prune type=%d count=%u "
					  "victim_idx=%u pruned_total=%lu\n",
					type, head->num_entries, victim_idx,
					obj_global_pruned);
			}
			destroy_object(victim, OBJ_GLOBAL, type);
		}
	}
}

/*
 * Marked noinline so __builtin_return_address(0) captured at entry
 * -- and threaded into add_object_validate() as caller_pc, where
 * the verbose trace and the bad-fd outputerr / post-handler
 * bump-site PC captures use it -- names the actual add_object()
 * callsite rather than whatever frame the inliner chose to fold
 * us into.  Caller attribution is the only reason that PC is
 * captured; losing it to inlining defeats the diagnostic.
 */
__attribute__((noinline))
void add_object(struct object *obj, enum obj_scope scope, enum objecttype type)
{
	void *caller_pc = __builtin_return_address(0);
	bool is_fd = is_fd_type(type);
	int fd = is_fd ? fd_from_object(obj, type) : -1;
	struct objhead *head;

	if (add_object_validate(obj, scope, type, caller_pc, is_fd, fd))
		return;

	/*
	 * Resolve the per-pool objhead once and thread it through the
	 * grow / publish helpers below.  The previous form re-entered
	 * get_objhead() inside each helper (and is_fd_type / fd_from_object
	 * 3-4x across the three helpers) on every fd-returning syscall;
	 * those resolutions are invariant across the call (no fork, no
	 * obj.fd union mutation, head pointer stable for the duration)
	 * so a single hoist is byte-equivalent.
	 */
	head = get_objhead(scope, type);
	if (head == NULL) {
		release_obj(obj, scope, type);
		return;
	}

	if (add_object_grow_capacity(obj, scope, type, head, is_fd, fd))
		return;

	add_object_publish(obj, scope, type, head, is_fd, fd);
}

/*
 * Call the destructor for this object, and then release it.
 * Internal version — caller must hold objlock if operating on globals.
 *
 * If already_closed is true, the fd has already been closed by the
 * kernel (e.g. after a successful close() syscall).  We invalidate
 * the fd in the object so the destructor's close() call is a harmless
 * no-op, while any other cleanup (munmap, free, etc.) still runs.
 */
void __destroy_object(struct object *obj, enum obj_scope scope,
		      enum objecttype type, bool already_closed)
{
	struct objhead *head;
	unsigned int idx, n, last;

	head = get_objhead(scope, type);
	if (head == NULL)
		return;
	n = head->num_entries;
	if (n == 0 || head->array == NULL)
		return;

	/*
	 * obj->array_idx is the slot we're about to swap-with-last and
	 * NULL.  add_object() set it once at insertion and the swap branch
	 * maintains it on every reshuffle -- the canonical invariant is
	 * head->array[obj->array_idx] == obj.
	 *
	 * Validate the invariant up front.  On mismatch the obj may not
	 * even belong to this pool any more (a stale slot pointer that
	 * survived deferred_free's TTL and got handed back through
	 * get_random_object()).  Drop the destroy cleanly rather than
	 * touching the wrong slot.
	 */
	idx = obj->array_idx;
	if (idx >= n || head->array[idx] != obj) {
		__atomic_add_fetch(&shm->stats.diag.destroy_object_idx_corrupt, 1,
				   __ATOMIC_RELAXED);
		return;
	}

	/* Swap-with-last removal from the parallel array */
	last = n - 1;
	if (idx != last) {
		head->array[idx] = head->array[last];
		if (head->array[idx] != NULL)
			head->array[idx]->array_idx = idx;
	}
	head->array[last] = NULL;
	head->num_entries = last;

	/*
	 * Maintain the per-child OBJ_LOCAL OBJ_MMAP_* nonempty-pool mask
	 * paired with the set-bit logic in add_object_publish.  This is the
	 * 1->0 transition iff the just-decremented last is zero -- any
	 * larger value means the bit must stay set.  destroy_objects()
	 * routes its drain through __destroy_object() so a whole-pool
	 * teardown flows naturally through this branch on the final entry.
	 * Gated on scope == OBJ_LOCAL because the mask lives in childdata;
	 * OBJ_GLOBAL teardowns from the parent's destroy_global_objects
	 * leave this_child() == NULL and the branch is a no-op there.
	 */
	if (scope == OBJ_LOCAL && last == 0) {
		int bit = mmap_pool_bit_for_type(type);

		if (bit >= 0) {
			struct childdata *child = this_child();

			if (child != NULL)
				child->mmap_pool_nonempty_mask &= ~(1u << bit);
		}
	}

	/* Remove from fd hash table */
	if (scope == OBJ_GLOBAL && is_fd_type(type)) {
		fd_hash_remove(fd_from_object(obj, type));
		/*
		 * Balance the add_object() increment at the GLOBAL+fd_type
		 * registration site.  Done here -- the common destruction
		 * path -- so every fd-provider destruction pays the
		 * decrement exactly once: child FD_EVENT_CLOSE drain,
		 * parent-side stuck-fd eviction, close/close_range post-
		 * handlers, perf/kvm peer pre-closes, and bulk shutdown
		 * drain all flow through __destroy_object().
		 */
		__atomic_fetch_sub(&shm->stats.fd.provider_outstanding[type],
				   1, __ATOMIC_RELAXED);
	} else if (scope == OBJ_LOCAL && is_fd_type(type))
		local_fd_hash_remove(head, fd_from_object(obj, type));

	if (already_closed && is_fd_type(type))
		invalidate_object_fd(obj, type);

	if (head->destroy != NULL)
		head->destroy(obj);

	release_obj(obj, scope, type);
}

void destroy_object(struct object *obj, enum obj_scope scope, enum objecttype type)
{
	if (scope == OBJ_GLOBAL && mypid() != mainpid)
		return;

	__destroy_object(obj, scope, type, false);
}

/*
 * Destroy a whole list of objects.
 */
void destroy_objects(enum objecttype type, enum obj_scope scope)
{
	struct objhead *head;
	struct object **oldarray;

	head = get_objhead(scope, type);
	if (head == NULL || head->array == NULL)
		return;

	/* Drain the array via repeated array[0] destroy.
	 * __destroy_object() does swap-with-last on the parallel array,
	 * so consuming the front slot each time pulls a fresh entry into
	 * slot 0 until num_entries reaches 0. */
	while (head->num_entries > 0) {
		struct object *obj = head->array[0];
		unsigned int prev_n;

		if (obj == NULL) {
			head->num_entries--;
			continue;
		}
		prev_n = head->num_entries;
		__destroy_object(obj, scope, type, false);
		if (head->num_entries == prev_n && head->array[0] == obj) {
			/* corrupt array_idx invariant -- skip past it. */
			head->array[0] = NULL;
			head->num_entries--;
		}
	}

	oldarray = head->array;
	head->array = NULL;
	head->array_capacity = 0;
	/*
	 * Teardown is the third array-replace site (the two grow paths
	 * are the others).  Bump before the deferred-free hand-off so a
	 * stale pick whose snapshot caught the pre-teardown array
	 * pointer re-reads a different generation and discards rather
	 * than indexing the (now-ttl'd) old container.  oldarray was
	 * allocated via zmalloc_tracked in add_object_grow_capacity()
	 * so deferred_free_enqueue() accepts it.
	 */
	head->array_generation++;
	deferred_free_enqueue(oldarray);
}

/*
 * Age threshold (in fleet op ticks) beyond which a pool entry is
 * considered stale for the purposes of eviction preference.  An obj
 * whose publish_call_nr is more than this many ticks behind the
 * current fleet_op_count has sat in its pool through a lot of
 * syscall activity without being consumed in an interesting way --
 * a good candidate to make room for something fresher.  32 is small
 * enough that the "stale" set fills quickly under normal churn and
 * large enough that a just-added obj isn't instantly re-evictable
 * on the very next prune tick.
 */
#define PRUNE_STALE_THRESHOLD  32UL

static bool obj_is_stale(const struct object *obj, unsigned long now)
{
	unsigned long ts = obj->publish_call_nr;

	/*
	 * ts == 0 is release_obj()'s memset sentinel and also the value
	 * stamped by add_object_publish() when shm_published wasn't live
	 * yet.  Either way we have no known age, so treat as stale --
	 * it's safe to evict something we can't date.
	 */
	if (ts == 0)
		return true;
	return (now - ts) > PRUNE_STALE_THRESHOLD;
}

static void __prune_objects(struct childdata *child, enum objecttype type, enum obj_scope scope)
{
	struct objhead *head;
	unsigned int n, expected_kills, i;
	struct object **array;
	unsigned long now;

	head = &child->objects[type];

	/* 0 = don't ever prune. */
	if (head->max_entries == 0)
		return;

	/* only prune full lists. */
	if (head->num_entries < head->max_entries)
		return;

	array = head->array;
	if (array == NULL)
		return;

	/* Direct random-victim sampling.  Pick expected_kills victims
	 * directly: ~N/10 rnd_modulo_u32 calls and N/10 branches for a
	 * ~10% eviction rate.
	 *
	 * Take n once: destroy_object() decrements num_entries via swap-
	 * with-last, but we sample over the original index space.  Slots
	 * beyond the shrunken num_entries are NULLed by __destroy_object,
	 * so the obj == NULL skip absorbs them.  Duplicate picks land on
	 * the same idx with probability ~expected_kills/n (~10%); a
	 * duplicate finds NULL on the second visit and is silently skipped.
	 */
	n = head->num_entries;

	expected_kills = n / 10U;
	if (expected_kills == 0)
		expected_kills = 1U;

	/*
	 * Snapshot the fleet op tick once for the whole batch and use it
	 * as the "now" reference against every obj->publish_call_nr below.
	 * RELAXED matches the store side in add_object_publish() and the
	 * parent's stats_publish_locked() writer.  now == 0 means either
	 * shm_published isn't live yet (very-early init) OR the counter
	 * genuinely hasn't ticked; in that case obj_is_stale()'s ts == 0
	 * short-circuit still handles never-stamped entries, and the
	 * (now - ts) branch below just uses zero as the reference tick.
	 */
	now = shm_published
	      ? __atomic_load_n(&shm_published->fleet_op_count, __ATOMIC_RELAXED)
	      : 0;

	for (i = 0; i < expected_kills; i++) {
		unsigned int idx = rnd_modulo_u32(n);
		struct object *obj = array[idx];

		if (obj == NULL)
			continue;

		/*
		 * Age-aware bias via best-of-2 sampling: if the first pick
		 * is a fresh publish (age <= PRUNE_STALE_THRESHOLD), draw
		 * one more random victim and prefer it if it's stale.  Both
		 * candidates were already eligible under the random policy;
		 * the extra roll just re-weights which of two random victims
		 * dies this round toward the older one, keeping recently-
		 * published objs alive long enough to be actually consumed.
		 * No walk of the pool -- one extra rnd_modulo_u32 per non-
		 * stale first pick, bounded per iteration.
		 */
		if (!obj_is_stale(obj, now)) {
			unsigned int idx2 = rnd_modulo_u32(n);
			struct object *obj2 = array[idx2];

			if (obj2 != NULL && obj_is_stale(obj2, now))
				obj = obj2;
		}

		destroy_object(obj, scope, type);
	}
}

void prune_objects(void)
{
	struct childdata *child;
	unsigned int i;

	/* We don't want to over-prune things and growing a little
	 * bit past the ->max is fine, we'll clean it up next time.
	 */
	if (!(ONE_IN(10)))
		return;

	/* Resolve the per-child object pool once.  Without this hoist,
	 * each __prune_objects() call would re-enter get_objhead() ->
	 * this_child() (a getpid + cache probe) for every one of the
	 * MAX_OBJECT_TYPES iterations -- a wasted lookup per type.
	 */
	child = this_child();
	if (child == NULL)
		return;

	for (i = 0; i < MAX_OBJECT_TYPES; i++) {
		__prune_objects(child, i, OBJ_LOCAL);
		// For now, we're only pruning local objects.
		// __prune_objects(child, i, OBJ_GLOBAL);
	}
}
