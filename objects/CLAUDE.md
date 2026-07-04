# objects/ — Object Pools & Result Threading

The pool layer that lets one syscall's successful result — an fd, id, or handle — become a later syscall's argument. A producing syscall's `.post` handler publishes the result as an `object`; a consuming syscall draws one back via `get_random_object()` or the fd-typed argument path. Two scopes: `OBJ_LOCAL` (per-child) and `OBJ_GLOBAL` (registered once at init, snapshotted into each child at fork).

Public API is `include/objects.h`. Cross-TU glue internal to this dir is `include/objects-internal.h` — symbols that were file-local `static` in the pre-carve `objects.c`; consumers outside objects/ must go through `objects.h`.

## Files (5 files + internal header, ~1,956 LOC)

| File | Lines | Role |
|---|---|---|
| registry.c | 1046 | Core lifecycle: `alloc_object` / `add_object` / `destroy_object` (+ internal `__destroy_object`, `destroy_objects`), `get_random_object`, `prune_objects`, pool/objhead bookkeeping, deferred-free + maps integration. The object-pool heart. |
| fdhash.c | 326 | Global fd→object hash — `fd_hash_init/insert/remove`, `find_local_object_by_fd`, `remove_object_by_fd[_local][_range]`. O(1) fd→object for the ARG_FD live-fd path. |
| local.c | 268 | `OBJ_LOCAL` per-objhead fd→object hash (`local_fd_hash_insert/remove`) for fd-typed local pools; per-child list init. |
| global.c | 181 | `OBJ_GLOBAL` pool: `register_global_obj_init` / `init_global_objects` / `clone_global_objects_to_child` / `destroy_global_objects`. Shared objects registered at init, snapshotted per-child at fork. |
| dispatch.c | 162 | Object-op dispatch: `invalidate_object_fd` (clear the fd union before the destructor to prevent double-close after a successful `close()`), `close_fd_destructor`, `generic_fd_dump`. |

## Data model

- `struct object` holds the typed result (fd / id / handle) in a union, keyed by `enum objecttype` × `enum obj_scope`. Objects live on per-`objhead` lists; `get_objhead(scope, type)` selects the list.
- **OBJ_LOCAL** = per-child pools (each child owns its objects). **OBJ_GLOBAL** = registered once via `register_global_obj_init()` (a `REG_GLOBAL_OBJ` provider), materialised by `init_global_objects()`, then `clone_global_objects_to_child()` snapshots them into each child at fork.
- The **fd-hash** (fdhash.c / local.c) gives O(1) fd→object so fd-typed consumers and the close/destructor paths resolve a live fd back to its owning object without scanning a pool.
- Destruction goes through `__destroy_object()`; fd-typed objects run `close_fd_destructor`, with `invalidate_object_fd` first when the fd was already closed (so the destructor's `close(-1)` harmlessly EBADFs). Frees route through the deferred-free machinery.

## Gotchas

- Adding a new global object type = a `register_global_obj_init()` provider registered in the **parent, pre-fork**. `add_object(OBJ_GLOBAL)` from *child* context is a documented **no-op** (mainpid guard in `registry.c`) — globals are populated only before fork, then cloned in.
- Cross-dir access is `objects.h` only. If you need a symbol currently in `objects-internal.h`, it's dir-internal by design — widen its linkage to `objects.h` deliberately, don't reach past the header.
