# childops/net/xfrm/ — IPsec / XFRM Childops

IPsec SA/policy and PF_KEY stress.

## Files (13 .c + 2 internal headers)

Both dispatched ops are split one phase per translation unit.

- `xfrm-churn.c` — the dispatched xfrm SA/policy churn orchestrator, with `xfrm-churn-builders.c` (coherent message builders), `xfrm-churn-traffic.c`, `xfrm-churn-pfkey.c`, `xfrm-churn-sk-policy.c`, `xfrm-churn-ah-esn.c` and `xfrm-churn-compat-sweep.c`. `xfrm-churn-internal.h` holds the shared declarations.
- `nat-t-churn.c` — the dispatched IPsec NAT-Traversal (ESP-in-UDP) churn orchestrator, with `nat-t-churn-setup.c`, `nat-t-churn-sa.c`, `nat-t-churn-traffic.c` and `nat-t-churn-cleanup.c`. `nat-t-churn-internal.h` holds the shared declarations.
- `pfkey-spd-walk.c` — PF_KEY security-policy-database walk.
