# childops/net/tc/ — Traffic-Control Childops

Traffic-control qdisc / classifier / action stress. The `tc-` prefix is dropped (redundant with the dir).

## Files (5 + internal header)
- `qdisc-churn.c` + `qdisc-churn-builders.c` — qdisc create/config churn + builders. `qdisc-churn-internal.h` holds the shared declarations.
- `live-traffic.c` — drive real packets through programmable tc filters while the filter chain is being replaced (the data-plane sibling of `qdisc-churn.c`).
- `mirred-blockcast.c` — tc-mirred action + block / broadcast.
- `standalone-action.c` — standalone tc-action plane: RTM_NEWACTION / RTM_DELACTION over TCA_ACT_TAB, racing shared gact replace (tcf_action_set_ctrlact) against in-flight traffic. Covers the TOCTOU window fixed by f60b396ee174.
