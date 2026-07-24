# childops/recipe/ — Recipe-Runner Framework

A childop framework that runs "recipes" — structured multi-step operation sequences — with variants for close-races, deadline-races, networking, and supervised orchestration. Builds on `childops/io_uring/`'s recipe pool. The `recipe-runner-` prefix is dropped (redundant with the dir). Dispatched by symbol via `op_dispatch[]` in `child/child-altop-table.c`.

## Files (6 .c + internal header)
- `runner.c` — the core recipe-runner dispatcher.
- `simple.c` — baseline recipe variant.
- `close-race.c` — close-during-op races.
- `deadline-race.c` — deadline/timeout races.
- `net.c` — networking-recipe variant.
- `supervisor.c` — supervised multi-recipe orchestration.
- `internal.h` — cross-TU declarations shared by the variants.

## Notes
- Builds on `childops/io_uring/recipes.h` + `ring.h` (path-qualified includes).
