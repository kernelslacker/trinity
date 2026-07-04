# childops/net/tc/ — Traffic-Control Childops

Traffic-control qdisc / classifier / action stress. The `tc-` prefix is dropped (redundant with the dir).

## Files (3 + internal header)
- `qdisc-churn.c` + `qdisc-churn-builders.c` — qdisc create/config churn + builders. `qdisc-churn-internal.h` holds the shared declarations.
- `mirred-blockcast.c` — tc-mirred action + block / broadcast.
