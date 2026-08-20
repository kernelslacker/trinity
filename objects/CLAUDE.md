# objects/ — Object Pools & Result Threading

The pool layer that lets one syscall's successful result — an fd, id, or handle — become a later syscall's argument. A producing syscall's `.post` handler publishes the result as an `object`; a consuming syscall draws one back via `get_random_object()` or the fd-typed argument path. Two scopes: `OBJ_LOCAL` (per-child) and `OBJ_GLOBAL` (registered once at init, snapshotted into each child at fork).

Public API is `include/objects.h`. Cross-TU glue internal to this dir is `include/objects-internal.h` — symbols that were file-local `static` in the pre-carve `objects.c`; consumers outside objects/ must go through `objects.h`.

## Files (14 files + internal headers, ~3,867 LOC)

The pre-carve `registry.c` core is now split across `registry*.c`; those files
share `objects/registry-internal.h`.

| File | Lines | Role |
|---|---|---|
| registry-lifecycle.c | 688 | `add_object` (+ its validate/publish halves), `__destroy_object` / `destroy_object` / `destroy_objects`, `prune_objects` staleness pass, deferred-free + maps integration. The object-pool heart. |
| type-graph.c | 607 | Observation-only resource type-graph: direct-mapped publish ring, open-addressed edge pool, EMA update, top-N text/JSON dumps. Does not feed back into the picker. |
| fd-event.c | 390 | Lock-free SPSC ring reporting child fd-state changes (e.g. closes) up to the parent (`notify_child_fd_closed[_range]`, the canonical FD_EVENT_CLOSE producer); built on `lib/spsc-ring.c`. |
| fdhash.c | 334 | Global fd→object hash — `fd_hash_init/insert/remove`, `find_local_object_by_fd`, `remove_object_by_fd[_local][_range]`. O(1) fd→object for the ARG_FD live-fd path. |
| prop_ring.c | 297 | Per-child ring of recent small-integer syscall return values, re-injectable as later arguments. |
| local.c | 285 | `OBJ_LOCAL` per-objhead fd→object hash (`local_fd_hash_insert/remove`) for fd-typed local pools; per-child list init. |
| registry-pool.c | 216 | Pool growth: `add_object_grow_capacity()` and the objhead capacity bookkeeping. |
| dispatch.c | 197 | Fd-union accessors: `invalidate_object_fd` (clear the fd union before the destructor to prevent double-close after a successful `close()`), `set_object_fd`, `fd_from_object`. |
| objpool-arena.c | 192 | Per-child `MAP_PRIVATE\|MAP_ANON` arena backing OBJ_LOCAL objpool storage, so one tracked-region registration protects all object slots against fuzzed value-result kernel writes. |
| global.c | 181 | `OBJ_GLOBAL` pool: `register_global_obj_init` / `init_global_objects` / `clone_global_objects_to_child` / `destroy_global_objects`. Shared objects registered at init, snapshotted per-child at fork. |
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
- Cross-dir access is `objects.h` only. If you need a symbol currently in `objects-internal.h`, it's dir-internal by design — widen its linkage to `objects.h` deliberately, don't reach past the header.
