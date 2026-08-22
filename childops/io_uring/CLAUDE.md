# childops/io_uring/ — io_uring Childops

## Files (1 dispatched + 1 helper)
- `send-zc-churn.c` — zero-copy send churn. Forks a loopback peer, so it is
  in the canary picker's pid-heavy suppression set.
- `ring.c` / `ring.h` — ring lifecycle (setup/teardown), shared helper, not
  dispatched.

## Notes
- Includes are path-qualified (`#include "childops/io_uring/ring.h"`,
  resolved via `-I.`).
