# objects/ — Object Pools & Result Threading

The pool layer that lets one syscall's successful result — an fd, id, or handle — become a later syscall's argument. A producing syscall's `.post` handler publishes the result as an `object`; a consuming syscall draws one back via `get_random_object()` or the fd-typed argument path. Two scopes: `OBJ_LOCAL` (per-child) and `OBJ_GLOBAL` (registered once at init, snapshotted into each child at fork).

Public API is `include/objects.h`. Cross-TU glue internal to this dir is `include/objects-internal.h`; consumers outside objects/ must go through `objects.h`.

## Files (14 files + internal headers, ~3,841 LOC)

The pre-carve `registry.c` core is now split across `registry*.c`; those files
share `objects/registry-internal.h`.

| File | Lines | Role |
|---|---|---|
| registry-lifecycle.c | 685 | `add_object` (+ its validate/publish halves), `__destroy_object` / `destroy_object` / `destroy_objects`, `prune_objects` staleness pass, deferred-free + maps integration. The object-pool heart. |
| type-graph.c | 604 | Observation-only resource type-graph: direct-mapped publish ring, open-addressed edge pool, EMA update, top-N text/JSON dumps. Does not feed back into the picker. |
| fd-event.c | 346 | Lock-free SPSC ring reporting child fd-state changes up to the parent: the child-side producers (`notify_child_fd_closed[_range]` for CLOSE / CLOSE_RANGE, EVICT from the stuck-fd watchdog) and the parent drain (`fd_event_drain[_all]`), which only counts closes and retires a pooled object for EVICT. `fd_event_drain_all()` reads each ring through the parent-private `expected_fd_event_rings[]` canary, never the child-writable pointer. Built on `lib/spsc-ring.c`. |
| fdhash.c | 349 | fd→object hash and live-fd list: the parent's `parent_fd_hash[]` (`fd_hash_init/insert/remove`), `fd_hash_lookup` (the parent's table, or a child's fork-time snapshot), the snapshot evictions `fd_hash_remove_local[_range]`, and `find_object_by_fd` (that lookup, then the child's OBJ_LOCAL pools). O(1) fd→object for the ARG_FD live-fd path. |
| prop_ring.c | 297 | Per-child ring of recent small-integer syscall return values, re-injectable as later arguments. |
| local.c | 305 | `OBJ_LOCAL` per-objhead fd→object hash (`local_fd_hash_insert/remove`) for fd-typed local pools, and its lookups `find_local_object_by_fd` / `local_fd_find_by_fd`; `remove_local_objects_by_fd` (retire a child's local objects under an fd the kernel closed or replaced, without closing it); per-child list init. |
| registry-pool.c | 216 | Pool growth: `add_object_grow_capacity()` and the objhead capacity bookkeeping. |
| dispatch.c | 188 | Fd-union accessors: `invalidate_object_fd` (clear the fd union before the destructor to prevent double-close after a successful `close()`), `set_object_fd`, `fd_from_object`. |
| objpool-arena.c | 188 | Per-child `MAP_PRIVATE\|MAP_ANON` arena backing OBJ_LOCAL objpool storage, so one tracked-region registration protects all object slots against fuzzed value-result kernel writes. |
| global.c | 183 | `OBJ_GLOBAL` pool: `register_global_obj_init` / `init_global_objects` / `clone_global_objects_to_child` / `destroy_global_objects`. Shared objects registered at init, snapshotted per-child at fork. Also `remove_object_by_fd`, which retires a global fd object from the parent (EVICT drain, stuck-fd watchdog, provider pre-close) and returns early in a child. |
| registry-pick.c | 170 | Consumer side: `get_random_object`, `objpool_check`, `objects_empty` / `objects_pool_empty`. |
| registry.c | 156 | `alloc_object`, `release_obj`, `get_objhead`, `__for_each_obj_init` — the shared primitives the other registry files build on. |
| futex-shared.c | 93 | Cross-child shared futex-word pool — the word lives in shared memory (wrapper in the parent heap) so children can contend on it. |
| registry-diag.c | 61 | `close_fd_destructor`, `generic_fd_dump`. |

## Data model

- `struct object` holds the typed result (fd / id / handle) in a union, keyed by `enum objecttype` × `enum obj_scope`. Objects live on per-`objhead` lists; `get_objhead(scope, type)` selects the list.
- **OBJ_LOCAL** = per-child pools (each child owns its objects). **OBJ_GLOBAL** = registered once via `register_global_obj_init()` (a `REG_GLOBAL_OBJ` provider), materialised by `init_global_objects()`, then `clone_global_objects_to_child()` snapshots them into each child at fork.
- The **fd-hash** (fdhash.c / local.c) gives O(1) fd→object so fd-typed consumers and the close/destructor paths resolve a live fd back to its owning object without scanning a pool.
- Destruction goes through `__destroy_object()`; fd-typed objects run `close_fd_destructor`, with `invalidate_object_fd` first when the fd was already closed (so the destructor's `close(-1)` harmlessly EBADFs). Frees route through the deferred-free machinery.

## Gotchas

- Adding a new global object type = a `register_global_obj_init()` provider registered in the **parent, pre-fork**. `add_object(OBJ_GLOBAL)` from *child* context is a documented **no-op** (mainpid guard in `registry-lifecycle.c`) — globals are populated only before fork, then cloned in.
- Nothing retires an `OBJ_LOCAL` fd object when its fd closes: `close()` and `close_range()` report the close and drop the child's `OBJ_GLOBAL` snapshot entry and live-fd slot, and leave the local pools alone, so a number the kernel hands out again can still sit in a local pool under the file it used to name. The dup family retires what its result's number held (`remove_local_objects_by_fd()`) before it pools the copy; any other reader of a local pool has to tolerate a stale object.
- Cross-dir access is `objects.h` only. If you need a symbol currently in `objects-internal.h`, it's dir-internal by design — widen its linkage to `objects.h` deliberately, don't reach past the header.
