# Deferred-free design notes

Companion to `persist/deferred-free.c`.  The source file carries per-field and
per-decl invariants inline; this document collects the multi-paragraph
design-rationale essays those inline pointers refer to.  Sections are ordered
roughly to match declaration order in the source.

## alloc_track hash table

Side-set membership accelerator for `alloc_track[]`.

`alloc_track_consume()` and `alloc_track_lookup()` resolve membership through
this 16384-slot hash (0.25 load factor at full occupancy), so both hit and
miss are O(1).  A fast miss matters: misses are the path that fires when a
scribbled snapshot field arrives at `deferred_free_enqueue`, which is exactly
the case where we want a fast reject.

`alloc_track[]` remains the source of truth for lifecycle (which slot a ptr
lives in, who got displaced on rotation); the hash mirrors it for membership
only.  Every write to `alloc_track[]` in this file is paired with the matching
hash op inside the same function, so the two stay in lock-step.  A divergence
here isn't just a perf miss -- it would be a correctness bug in the
deferred-free gate, the very thing the opt-in `zmalloc_tracked()` set was
built around.

16384 slots vs `ALLOC_TRACK_SIZE=4096` -> 0.25 max load factor, keeping the
average probe length ~1.3 even at full occupancy.  Power of two so the modulo
collapses to a bitmask.  Storage shares the `alloc_track` mmap region (see
`alloc_track` declaration in the source) so one mprotect bracket covers both
arrays.  Slots DO hold pointer values an attacker can turn into a `free()`
target -- `alloc_track_lookup` gates `cleanup_release_post_state` ->
`tracked_free_now` -> `free()`, the deferred-free enqueue admission, AND the
deferred-free free-time ownership check -- so the `PROT_READ` steady state is
load-bearing for memory safety, not just a perf nicety.  Mirror the
`ring[]`/`inflight_hash[]` armor pattern.

Fibonacci hashing: `ptr>>4` strips the 4 always-zero low bits glibc malloc
gives us on x86_64 (16-byte-aligned chunks on 64-bit), then multiplies by the
golden-ratio constant.  Top 10 bits of the product become the slot index,
which scatters pointer streams that share a common prefix (e.g. addresses
drawn from the same arena) across the table.

Duplicate-ptr edge case: if the same address enters `alloc_track[]` twice
(rare; requires a direct `free()` outside the deferred path before a
re-malloc returns the same address), the hash records one membership entry.
When the first array slot rotates out, the displaced ptr is `hash_remove()`d
-- the second slot's copy is orphaned (hash says no, array says yes), and a
subsequent `deferred_free_enqueue` of that ptr is falsely rejected.  That is
a `deferred_free_reject` leak, not a bad-free; per the opt-in vs.
implicit-track design rationale, the safer direction to err.

## In-flight pointer set

Mirrors "currently admitted to the deferred ring" membership.  Populated at
the tail of `deferred_free_enqueue` after the ring slot write succeeds;
cleared at the tail of `free_ring_entry` / `ring_evict_oldest_safe` on the
successful `free()` path.  Used by `inflight_gc_sweep()` to reconcile stomp
orphans (set entries whose corresponding ring slot has been scribbled to a
different value) so the set stays bounded over long runs.

No longer the ownership gate at free time: the value-keyed shadow could
desync from `ring[]` under stomp + unlock-window pressure (set said "present"
when ptr was never admitted -- the `ring_evict_oldest_safe` ASAN bad-free
root cause) or reject a clean free (set said "absent" when ptr was live).
The authoritative gate is `alloc_track_lookup()`, which mirrors what
`__zmalloc()` returned and is held populated through ring residency by design
(see `deferred_free_enqueue_internal`'s lookup-not-consume gate and the
matching free-time consume in `free_ring_entry` / `ring_evict_oldest_safe`).

Storage shape mirrors `alloc_track_hash[]` (1024 slots, Fibonacci index,
open-addressed with shift-back deletion).  Sized for the 64-slot ring plus
headroom for stomp orphans accumulated between GC sweeps; an idle slot costs
8 bytes of the mmap'd backing.

Storage lives in an mmap'd region whose address range is registered with
`shared_regions[]` via `track_shared_region()`, mirroring `ring[]`'s shape.
Steady state is `PROT_READ`; writers (`inflight_hash_insert` /
`inflight_hash_remove` / the dispose-time clear) bracket their mutations
with `inflight_unlock()`/`inflight_lock()` so a sibling fuzzed value-result
syscall that aliases the set's pages between writes hits the `PROT_READ`
wall instead of silently flipping a membership bit.

## Three-result ring_unlock and the mprotect bracket

Bracket every writer/reader of `ring[]` with `mprotect()`.  Between ticks the
ring sits at `PROT_NONE`; any fuzzed value-result syscall that tries to
scribble inside it now SIGSEGVs in the kernel's `copy_from_user` instead of
silently overwriting `ring[i].ptr` with a pid-shaped value.  `mprotect` is
async-signal-safe so these are safe to call from anywhere `deferred_free_*`
is reachable.

`ring_unlock()` returns `RING_UNLOCK_OK` on success, `RING_UNLOCK_ENOMEM`
when the kernel rejected the protection change for VMA-budget reasons
(per-process `/proc/sys/vm/max_map_count` cap approached, or splitting the
surrounding mapping would overshoot it), and `RING_UNLOCK_FAIL` on any other
failure.  Callers handle the three cases differently: ENOMEM flips the
per-child drain-aggressive latch so the next tick drains the queue regardless
of TTL (the sooner the ring empties, the sooner the held-back glibc-arena
chunks can be returned to the kernel and the VMA budget recovers); generic
FAIL just falls back to immediate free for this ptr; either way the caller
bails before touching `ring[]`.  Distinguishing the three cases is
load-bearing: collapsing them into a single logged-and-return path leaves
the ring `PROT_NONE` while the caller falls through, turning queued pages
into `SEGV_ACCERR` bait for sibling value-result syscalls and leaking the
queued ptrs.  The current routing keeps the page `PROT_NONE` (no caller
proceeds on failure) but stops adding queue pressure while the kernel is at
the VMA limit.

## alloc_track_refresh

Refresh an existing tracked entry's LRU position without freeing it.  If
`@ptr` is currently tracked (`alloc_track_consume` hit), null its current
slot + remove from hash, then re-insert at head.  If `@ptr` is NOT currently
tracked (consume miss), bail without inserting -- see the consume-miss
rationale below.  Post-call state on a hit has `@ptr` exactly once in the
array (at head) and exactly once in the hash; on a miss the alloc_track
state is unchanged.

Pair with the `OBJ_LOCAL` anon-pool dedup-skip in `clone_global_mmap_pool`:
dedup'd pool entries don't trigger a fresh `__zmalloc_tracked`, so without
this refresh their `alloc_track` slots rotate out under churn from unrelated
tracked allocations faster than any fixed `ALLOC_TRACK_SIZE` can absorb at
full throughput.  Refreshing the LRU position on reuse keeps a long-lived
dedup'd entry resident regardless of churn rate.

Ring-residency gate: skip the consume + re-add when `@ptr` is currently
pinned in the deferred ring.  The ring already owns the chunk's lifecycle
(free-time consume runs in `free_ring_entry` / `ring_evict_oldest_safe`), so
a fresh `alloc_track` entry from `deferred_alloc_track(@ptr)` creates a
stale-survivor entry that outlives the ring's drain: after the ring drains
`@ptr` and frees the chunk, the heap recycles the address, and a stale
caller ref that re-enqueues `@ptr` (or any free-time `consume()` against the
reused address) matches the leftover entry and frees the new owner's live
chunk.  The choke-point enqueue dedup (`ring_contains` check feeding
`deferred_free_double_admit_skip`) catches the value-side symptom (two ring
slots for the same ptr) but the desync this refresh creates between
`alloc_track` and ring residency survives that gate -- it is the
address-reuse residual the leak-on-eviction interim (`ring_evict_leaked`)
was put in place to mask.  Treat "ring owns this ptr" as an authoritative
skip on the refresh source itself.

Source of truth: `ring[]` is mprotect-armored AND registered with
`shared_regions[]`, so neither scribble nor mprotect-failure can desync it
from itself; `alloc_track` is not.  The scan needs an open `ring_unlock()`
bracket (`ring[]` is `PROT_NONE` at rest, see `ring_contains`' contract).
`ring_unlock()` failure (typically ENOMEM under VMA pressure) cannot verify
residency; skip the refresh entirely rather than risk re-adding a
ring-resident ptr.  The cost of a skipped refresh is the LRU position only
-- the original `alloc_track` entry is untouched, so a follow-up lookup
still resolves and the entry rotates out per the normal `alloc_track[]`
aging.

## alloc_track_refresh consume-miss discipline

Preserve the recorded extent across the consume + re-add so downstream
`lookup_size()` readers continue to see the original allocation length.

`alloc_track_consume()` is the source-of-truth ownership gate (see
`tracked_free_checked()`).  A false return means `@ptr` is NOT currently in
`alloc_track[]` -- either it was rotated out by intervening churn, or it was
never tracked at all (a stale caller ref, an interior pointer the caller
derived by a few bytes off a tracked chunk, or a scribbled `head->array` /
`localobj` from a sibling fuzzed value-result syscall).  The two cases are
indistinguishable from this side.

The previous shape called `deferred_alloc_track(@ptr, 0)` unconditionally,
blessing the unproven `@ptr` as tracked and arming a bad-free at the next
`tracked_free_checked()`: `free_ring_entry` / `tracked_free_now` /
`ring_evict_oldest_safe` called `free()` on an interior pointer that
`alloc_track_consume()` now happily approved -- the ASAN "attempting free on
address which was not `malloc()`-ed" class caught in a recent fuzz run (88
bytes after a 40-byte region; address derived from a scribbled `head->array`
/ `localobj` from a sibling fuzzed value-result syscall).

Bump `@ptr`'s LRU position only when we have proof it was legitimately
tracked.  On a miss, bail without inserting; the cost is that a legitimately
rotated-out tracked ptr loses its next `deferred_free_enqueue` (rejected as
untracked, leaked).  That is the safer direction to err vs. silently
blessing an arbitrary VA -- the leak is bounded by child lifetime and the
kernel reclaims at exit, the bad-free is unrecoverable.

## Ownership gate: alloc_track_consume vs alloc_track_lookup

Free-time ownership gate shared by every path that hands a tracked pointer
back to `free()`.  `alloc_track_consume()` scans the authoritative
`alloc_track[]` array and clears the matching slot on a hit; only a true
return is proof that `__zmalloc()` currently owns `@ptr`.  On a miss the
caller is about to free something the heap does not own -- swallow the
`free()` and bump the per-site corrupt/untracked counter so existing
telemetry granularity (`ring_eviction_corrupt` vs `deferred_free_corrupt_ptr`
vs `deferred_free_reject_untracked`) is preserved.

Why not gate on `alloc_track_lookup()`?  `lookup` is a value-keyed hash
prefilter that can stay true after the backing `alloc_track[]` slot has been
rotated out -- duplicate-ptr edge case, or a hash entry that survived its
array slot's rotation.  The reverted slot-cookie stack tried adding a NEW
value-keyed shadow on top of the existing one; the new shadow also desynced.
`consume()` reads the source of truth (the array); its return is the binding
gate.  The previous shape gated on `lookup()` and then called `consume()`
while discarding its return, `free()`ing chunks `__zmalloc()` no longer
owned -- a repeated ASAN bad-free class (143 reports across mid-June 2026).

Cheap stateless prefilters (`is_in_glibc_heap`, `range_overlaps_shared`) may
still run before the helper at sites that want their own granular stat
counter for those rejection classes, but they are NOT sufficient proof of
ownership -- only a true return from `alloc_track_consume()` is.

## tracked_free_now ring-residency check

Synchronously free a `zmalloc_tracked()` pointer.  `alloc_track_consume()`
pulls the entry out of both `alloc_track[]` and `alloc_track_hash[]` in one
shot (hash-gated reject, then backward array scan with paired `hash_remove`
on the hit), which is exactly the removal the deferred ring would have done
at TTL expiry -- but here without the queue latency.  The consume-miss case
(pointer was never tracked, was already consumed, or rotated out) is
silently tolerated: `free()`ing a non-tracked pointer is not by itself a bug,
and a hard error here would punish callers that legitimately mix tracked
and untracked allocations on the same release path.

Ring-ownership gate: scan `ring[]` directly to decide whether `@ptr` is
currently pinned in the deferred-free ring.  `ring[]` is the source-of-truth
(mprotect-armored AND registered with `shared_regions[]`, so neither
scribble nor mprotect-failure can desync it from itself).  The previous
shape used `inflight_hash_contains()` as a proxy, but `inflight_hash` is a
value-keyed mirror that can desync from `ring[]` in two ways:
(1) `inflight_hash_insert()` silently skips when its mprotect-unlock returns
-1 (ENOMEM under VMA pressure, the same class the ring's
`RING_UNLOCK_ENOMEM` path defends against); (2) a sibling fuzzed
value-result syscall that scribbles `inflight_hash` during a writer's
`PROT_READ|PROT_WRITE` bracket can overwrite an entry.  Either lie returns
false from `contains()` for a ring-resident `@ptr`, the fall-through runs
`free()`, and a subsequent address-reuse re-admission re-arms `contains()`
for the dangling slot -- eviction passes its guard and double-frees.  Direct
`ring[]` scan trusts the stronger gate and is immune to both desync
vectors.

Cost: `ring_count > 0` gate (read against `rc`'s `PROT_READ` steady state --
no syscall); on the non-empty path, one `ring_unlock` pair plus a 64-slot
scan.  Acceptable on the cleanup boundary.

`ring_unlock()` failure (ENOMEM) cannot verify residency -- leak `@ptr`
rather than risk a double-free; child exit reclaims it.  Bumps
`deferred_free_tracked_free_unverified_leak` so the rate is observable.

## ring_dispose_after_enomem

Tear down the ring after `ring_unlock()` returned ENOMEM.  The page is still
`PROT_NONE` at this point (the RW flip is exactly what failed); if we just
bail and leave it that way, every sibling fuzzed value-result syscall whose
buffer lands inside the ring `SEGV_ACCERR`s in `copy_to_user`, and every
subsequent `ring_unlock` retry hits the same ENOMEM and emits another
"mprotect RW failed" line.

Releasing the VMA slot with `munmap()` drops both failure modes at the
source: the `PROT_NONE` residue is gone (so no more `SEGV_ACCERR` fault-
bait), and the kernel gets the VMA back to satisfy whatever split the wider
mm-syscall workload needed.  Cost: every ptr currently in the ring is leaked
from glibc's tracking until the child exits.  That is the same tradeoff the
drain-aggressive bypass already accepted for the per-allocation UAF-detection
window -- abandoning the remaining ring slots is the worst case of that
bypass, taken once when the kernel has actually told us it cannot satisfy
more mprotect splits.

Untrack the shared region BEFORE `munmap` so `range_overlaps_shared()` stops
answering yes on a VA the kernel will reclaim out from under it -- the
pairing rule the `check-static` script enforces for every other
`track`/`munmap` site.  `inflight_hash[]` is cleared in lock-step with
`ring_count` so the orphan-sweep at next tick (which won't run, since
`ring_count` is now zero) doesn't have a stale picture to recover from if a
future commit re-arms the ring; the heap chunks the hash entries pointed at
are leaked alongside the queued ptrs themselves.

Idempotent: a second caller (e.g. a flush after the enqueue path already
disposed) sees `ring==NULL` and returns.  After dispose every
`deferred_free_*` entry point falls through to the no-op path -- enqueue's
`ring==NULL` gate routes to immediate `free()`, tick/flush bail on
`ring_count==0` -- so the deferred-free machinery is functionally off in
this child for the rest of its life.  Per-child by fork's COW, so a flap in
one child doesn't perturb siblings.

## Leak-on-eviction defense (ring_evict_oldest_safe)

Interim leak-on-eviction defense: the eviction site does NOT `free()` the
evicted chunk.  Reclaim the ring slot, drop the inflight-hash entry, bump
`ring_evict_leaked`, and let the heap chunk leak.  Child exit reclaims it.

Why leak instead of free: the surviving bad-free class at the eviction site
is the address-reuse window.  A stale caller reference to a chunk that was
freed and recycled by glibc still holds the original pointer value; that
value now names a live chunk owned by an unrelated allocation.  The value
gates here (`is_in_glibc_heap`, `range_overlaps_shared`) and the
source-of-truth gate (`alloc_track_consume`) all answer "yes, this value is
a valid live tracked chunk" -- because it IS, just not the one the stale
ref thought it was.  Freeing on that signal frees a now-live chunk and the
original owner eventually trips ASAN.  The durable fix is at the caller-
lifecycle root (drop the retained ref before glibc can reuse the address);
removing eviction as a `free()` site closes the crash window while that work
bakes separately.

Bounded leak: eviction only fires when the ring is full (TTL range 5-50,
ticked every syscall, so steady-state eviction is rare).  The
`RING_DRAIN` / flush and immediate-free fallback paths intentionally keep
freeing -- leaking the whole ring would be an RSS blowup, not a bounded
defense.  Cannot double-free / bad-free because the site never calls
`free()`.

The cheap stateless prefilters stay for telemetry granularity: a scribbled
slot still bumps `ring_eviction_corrupt` instead of being silently leaked
under `ring_evict_leaked`, so the stomp-rate signal is preserved (and is
independent of the leak decision).  `alloc_track` is intentionally left
populated -- the chunk is, from the heap allocator's view, still live.

Validation gate: the next multi-child ASAN fuzz run should show the
`ring_evict` bad-free class drop to zero.  Until that run confirms it, this
lands on local master only.

## free_ring_entry corruption gating

Free one ring entry's payload, dropping it if the pointer fails the sanity
bands.  Both the tick (TTL expiry) and flush (child exit) paths route
through here -- pre-helper, only tick had these checks, so a corrupted ring
entry surviving until child exit would silently free a bogus pointer through
`deferred_free_flush()`.  The tick guard rejected ~47.7k corrupt-pointer
scribbles in a single 6.76h run (~2/sec), so the ring DOES get scribbled in
practice; every entry the tick guard would have rejected was being silently
freed by flush instead.

Caller must clear `ring[slot].ptr` (and decrement `ring_count` where it
tracks per-slot) before calling.  Clearing first means a signal that
`longjmp`s out of `fn()` can't leave a freed pointer pending in the ring.

Re-run the same stateless gates `deferred_free_enqueue` used to admit the
pointer in the first place: shape (pid-scribbled / sub-page / non-canonical
/ misaligned), heap-bounds, shared-region overlap.  A recent ASAN run logged
105 "attempting free on un-malloc'd" crashes whose root cause is the ring
entry being scribbled between the enqueue admission check and TTL expiry --
the slot lives RW inside `ring_unlock()` brackets, but a sibling fuzzed
value-result syscall can still land a stomp into the same page during that
window.  Before this guard, `free_ring_entry` checked only sub-page and
alignment; every stomp that landed on something heap-shaped but not actually
malloc-returned was being fed straight to `free()`.

`alloc_track` ownership is the binding gate, applied via
`tracked_free_checked()`: the helper calls `alloc_track_consume()` and only
hands `@ptr` to `free()` when consume returns true.  A stomp value whose
shape passes heap-bounds and avoids the shared regions can still mismatch
the originally admitted pointer -- the `alloc_track` set records what
`__zmalloc()` actually returned, so a consume miss means `@ptr` is either an
interior pointer (base + N hashes to a different slot) or a value that was
never produced by `__zmalloc()` at all.  Either case is exactly the bad-free
shape that the prior lookup-then-consume-ignored shape let through (`lookup`
is a hash prefilter that stays true after the backing array slot rotates out
-- the desync was the bug).  Gating on `consume`'s bool return reads the
source of truth.

Bumps `STATS_FIELD_DEFERRED_FREE_CORRUPT_PTR` (or its parent fallback) on
the stateless-prefilter rejections, with the specific gate that fired in
the `outputerr` log line.  A consume-miss inside `tracked_free_checked()`
bumps the same counter so the alloc-track-miss class stays observable; no
separate per-rejection log because the call site is unambiguous (only
`free_ring_entry` routes through `TRACKED_FREE_SITE_RING_DRAIN`).

On the clean-free path the entry is removed from `inflight_hash` so the GC
sweep does not later mistake it for an orphan, and the `alloc_track` entry
is consumed in lock-step with `free()` so the set stays in sync with the
heap.
