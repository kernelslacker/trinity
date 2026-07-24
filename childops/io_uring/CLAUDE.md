# childops/io_uring/ — io_uring Childops

Scripted io_uring stress workloads: SQE/CQE floods, command passthrough, multishot networking, zero-copy send, and the "recipes" catalogue (a family-based recipe dispatcher covering fs/net/poll-timeout/register operations). The `iouring-` prefix is dropped (redundant with the dir). One workload per file, dispatched by symbol via `op_dispatch[]` in `child/child-altop-table.c`.

## Files (10 .c + 3 headers)
- `flood.c` — SQE/CQE submission flood.
- `cmd-passthrough.c` — `IORING_OP_URING_CMD` passthrough.
- `net-multishot.c` — multishot accept/recv networking.
- `send-zc-churn.c` — zero-copy send churn.
- `recipes.c` — the recipe dispatcher + shared pool-race fault handler; families in `recipes-fs.c`, `recipes-net.c`, `recipes-poll-timeout.c`, `recipes-register.c`.
- `ring.c` — ring lifecycle (setup/teardown) used by the recipes.
- Headers: `recipes.h`, `recipes-internal.h` (cross-TU recipe declarations), `ring.h` (ring lifecycle API).

## Notes
- Includes are path-qualified (`#include "childops/io_uring/recipes.h"`, resolved via `-I.`). `recipes.h`/`ring.h` are consumed by `childops/recipe/` (the recipe-runner framework builds on this recipe pool) and by `childops/fs/ublk-lifecycle.c`.
