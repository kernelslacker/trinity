# childops/net/xfrm/ — IPsec / XFRM Childops

IPsec SA/policy and PF_KEY stress.

## Files (4 + internal header)
- `xfrm-churn.c` + `xfrm-churn-builders.c` — xfrm SA/policy churn + coherent message builders. `xfrm-churn-internal.h` holds the shared declarations.
- `pfkey-spd-walk.c` — PF_KEY security-policy-database walk.
- `nat-t-churn.c` — IPsec NAT-Traversal (ESP-in-UDP) churn.
