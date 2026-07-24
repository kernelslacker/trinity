# childops/net/ — Networking Childops

The largest childops cluster: scripted stress workloads for socket families and networking subsystems. 49 per-protocol workloads at the top level, plus four control-plane sub-clusters. Dispatched by symbol via `op_dispatch[]` in `child/child-altop-table.c` — registration is by extern symbol, no path coupling.

## Sub-directories
- [netfilter/](netfilter/CLAUDE.md) (17) — nftables expr families, conntrack, flowtable, nfnetlink util.
- [netlink/](netlink/CLAUDE.md) (9) — genl/rtnetlink control-plane fuzzers + helpers.
- [xfrm/](xfrm/CLAUDE.md) (4) — IPsec/xfrm SA/policy, PF_KEY, NAT-T.
- [tc/](tc/CLAUDE.md) (3) — traffic-control qdisc/mirred (`tc-` prefix dropped).

## Top-level files (49)
One workload per socket family or net feature, grouped roughly by layer:
- **L2 / link**: af-unix-*, bridge-*, eth-emitter, vxlan-encap, veth-asymmetric-xdp, l2tp-ifname-race, atm-vcc-churn.
- **L3 / routing**: ip6erspan-netns-migrate, ip6gre-bond-lapb-stack, ipv6-ndisc-proxy, ipv6-pmtu-teardown-race, ipfrag-source-churn, ipmr-cache-report, igmp-mld-source-churn, mpls-route-churn, vrf-fib-churn.
- **L4 / transport**: tcp-ao-rotate, tcp-md5-listener-race, tcp-ulp-swap-churn, tls-rotate, tls-ulp-churn, sctp-assoc-churn, mptcp-pm-churn, msg-zerocopy-churn, sock-ulp-sockmap-layering, splice-protocols, inplace_crypto_oracle.
- **socket families / misc**: af-alg-* (3), afxdp-churn, rxrpc-* (2), vsock-transport-churn, tipc-link-churn, qrtr-bind-race, iscsi-* (2), packet-fanout-thrash, obscure-af-churn, sock-diag-walker, socket-family-chain, ipvs-sysctl-writer, ovs-tunnel-vport-churn, psp-key-rotate, wireguard-decrypt-flood, pfkey-adjacent.

## Notes
- Shared netlink/genl/nfnetlink scaffolding headers (`childops-genl.h`, `childops-netlink.h`) live in `include/` and are unaffected by this move.
