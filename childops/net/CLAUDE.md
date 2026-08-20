# childops/net/ — Networking Childops

The largest childops cluster: scripted stress workloads for socket families and networking subsystems. 103 `.c` files at the top level, plus four control-plane sub-clusters. Dispatched by symbol via `op_dispatch[]` in `child/child-altop-table.c` — registration is by extern symbol, no path coupling.

## Sub-directories
- [netfilter/](netfilter/CLAUDE.md) (5 here + 14 under `nftables/`) — nftables expr families, conntrack, flowtable, ipset, nfnetlink util.
- [netlink/](netlink/CLAUDE.md) (14) — genl/rtnetlink control-plane fuzzers + helpers.
- [xfrm/](xfrm/CLAUDE.md) (13) — IPsec/xfrm SA/policy, PF_KEY, NAT-T.
- [tc/](tc/CLAUDE.md) (5) — traffic-control qdisc/mirred/action plane (`tc-` prefix dropped).

## Top-level files (103 .c + 7 headers)
One workload per socket family or net feature, grouped roughly by layer:
- **L2 / link**: af-unix-peek-race, af-unix-scm-rights-gc, bridge-conntrack-churn, bridge-fdb-stp, bridge-ip6frag-refrag, bridge-ip6-refrag-fraggap, bridge-vlan-churn, vlan-filter-churn, eth-emitter, vxlan-encap, geneve-rx, bareudp-rx, veth-asymmetric-xdp, netdev-netns-migrate, l2tp-ifname-race, atm-vcc-churn.
- **L3 / routing**: ip6erspan-netns-migrate, ip6gre-bond-lapb-stack, ip6mr-churn, ip6-tunnel-churn, ip_gre-churn, sit-proto41-rx, fou-gue-mcast-rx, ipv6-ndisc-proxy, ipv6-pmtu-teardown-race, ipv6-rpl-clone-fidelity, ipfrag-source-churn, ipmr-cache-report, igmp-mld-source-churn, crafted-icmp-rx, mpls-route-churn, mpls-label-stack-rx, seg6-end-dt4-rx, seg6-end-dx4-rx, vrf-fib-churn, fnhe-pmtu-mtu-race, multipath-linkdown-rebalance, nexthop-replace-churn.
- **L4 / transport**: tcp-ao-rotate, tcp-md5-listener-race, tcp-ulp-swap-churn, inet-listener-rehash-race, tls-rotate, tls-ulp-churn, sctp-assoc-churn, sctp-chunk-rx, mptcp-pm-churn, msg-zerocopy-churn, sock-ulp-sockmap-layering, sockmap-cork-race, ip4-udp-cork-splice, ip6-udp-cork-splice, splice-protocols, inplace_crypto_oracle.
- **socket families / misc**: af-alg-* (3), afxdp-churn, rxrpc-* (2), rds-* (2), vsock-transport-churn, tipc-link-churn, qrtr-bind-race, iscsi-* (2), packet-fanout-thrash, packet-qdisc-bypass-unanchored-l2, obscure-af-churn, sock-diag-walker, socket-family-chain, ipvs-sysctl-writer, ovs-tunnel-vport-churn, psp-key-rotate, wireguard-decrypt-flood, esp-crafted-rx, espintcp-coalesce-churn.

Six of these are large enough that they were carved one phase per
translation unit behind a private `*-internal.h`, so the dispatched
entry point is only the first file of its group:
`afxdp-churn` (+ `-attach`, `-io`, `-teardown`, `-umem`),
`bridge-fdb-stp` (+ `-setup`, `-fdb`, `-stp`, `-traffic`, `-vlan-mass`),
`esp-crafted-rx` (+ `-sa`, `-packet`, `-frag`, `-stacked`, `-helpers`),
`psp-key-rotate` (+ `-cmd`, `-devlink-port`, `-lifecycle`, `-traffic`),
and `pkt-builder` (+ `-l2`, `-l3`, `-l4`, `-deliver`, `-repair`), the
shared crafted-packet construction helpers, with `pkt-builder-probe` as
its own dispatched op. `rds-bind-transport-refleak.h` and
`crafted-icmp-rx.h` are single-consumer headers rather than cluster
headers.

## Notes
- Shared netlink/genl/nfnetlink scaffolding headers (`childops-genl.h`, `childops-netlink.h`) live in `include/` and are unaffected by this move.
