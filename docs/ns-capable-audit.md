# ns\_capable Reach Audit

This audit classifies every admin-gated surface that trinity enumerates — ioctl
tables, generic-netlink family grammars, and inline capability checks inside
netlink handlers — according to whether the kernel-side gate is permanently dead
under a capset-to-empty child or is unlockable by a child that owns a user
namespace.

## Summary

**Class 1** (inline `capable(CAP_*)` — host-scoped, permanently dead): **39 entries**  
**Class 2** (`ns_capable(obj->user_ns, CAP_*)` where *obj* is child-creatable — reachable via userns): **186 entries**  
**Class 3** (`ns_capable(&init_user_ns, …)` or object always host-owned — dead, equivalent to class 1): **61 entries**

Total admin-gated entries audited: **286**.  The class-1 count of 39 and the
class-3 count of 61 together represent **100 permanently dead entries** under the
current child capability model — a substantial dead tail that burns fuzz budget on
guaranteed `-EPERM` fast-rejects.

---

## Classification

### Gate taxonomy

| Gate macro / call | Resolves to | Class |
|---|---|---|
| `capable(CAP_*)` | `ns_capable(&init_user_ns, cap)` at task level; dead once capset drops all caps | 1 |
| `GENL_ADMIN_PERM` | `netlink_capable()` → `netlink_ns_capable(skb, &init_user_ns, cap)` — always init\_user\_ns | 3 |
| `GENL_UNS_ADMIN_PERM` | `netlink_ns_capable(skb, net->user_ns, cap)` — net is the socket's netns, child-creatable | 2 |
| `ns_capable(sb->s_user_ns, cap)` | superblock user\_ns; class 2 when sb belongs to a child-owned mount | 2 |
| `ns_capable(net->user_ns, cap)` direct | network namespace; class 2 when child clones its own netns | 2 |
| `ns_capable(&init_user_ns, cap)` | hardcoded init\_user\_ns; dead | 3 |

---

### Ioctl surfaces

| Surface | Trinity file | Kernel gate | Class | Notes |
|---|---|---|---|---|
| `FIFREEZE` | `ioctls/vfs.c:240` | `ns_capable(sb->s_user_ns, CAP_SYS_ADMIN)` (`fs/ioctl.c:389`) | **2** | Reachable when child owns the mount's superblock (e.g. tmpfs in a child-owned mount namespace); `sb->s_user_ns` reflects user\_ns of the namespace that mounted the fs |
| `FITHAW` | `ioctls/vfs.c:241` | `ns_capable(sb->s_user_ns, CAP_SYS_ADMIN)` (`fs/ioctl.c:406`) | **2** | Same as FIFREEZE; both ioctls share the `ioctl_fsfreeze`/`ioctl_fsthaw` path |
| `TUNSETIFF` | `ioctls/tun.c:283` | `ns_capable(net->user_ns, CAP_NET_ADMIN)` via `tun_not_capable()` (`drivers/net/tun.c:520`) | **2** | Reachable when child unshares its own network namespace; `net` is derived from `current`'s netns |
| `TUNSETPERSIST` | `ioctls/tun.c:285` | `ns_capable(net->user_ns, CAP_NET_ADMIN)` (`drivers/net/tun.c:2709` has `capable()` path, `2763` has `ns_capable()`) | **2** | Mixed: TUNSETPERSIST with flag=0 hits `ns_capable`; non-zero flag path hits `capable(CAP_NET_ADMIN)` → class 1 for that branch |
| `BTRFS_IOC_ENCODED_READ` | `ioctls/btrfs.c:199` | `capable(CAP_SYS_ADMIN)` (`fs/btrfs/ioctl.c`) | **1** | Already documented as permanently dead |
| `BTRFS_IOC_ENCODED_WRITE` | `ioctls/btrfs.c:202` | `capable(CAP_SYS_ADMIN)` (`fs/btrfs/ioctl.c`) | **1** | Same; btrfs encoded I/O unconditionally requires global CAP\_SYS\_ADMIN |
| btrfs snap/resize/scrub/balance/quota/send/device group (~32 ioctls) | `ioctls/btrfs.c` (various) | `capable(CAP_SYS_ADMIN)` in `fs/btrfs/ioctl.c` (35 distinct call sites) | **1** | Covers `BTRFS_IOC_SNAP_CREATE(_V2)`, `RESIZE`, `SCAN_DEV`, `ADD_DEV`, `RM_DEV(_V2)`, `BALANCE(_V2/_CTL/_PROGRESS)`, `SCRUB(_CANCEL/_PROGRESS)`, `SUBVOL_CREATE(_V2)`, `SNAP_DESTROY(_V2)`, `QUOTA_CTL`, `QGROUP_{ASSIGN,CREATE,LIMIT}`, `SEND`, `DEV_REPLACE`, `SET_FEATURES`, `GET_DEV_STATS` (reset flag) — all call `capable(CAP_SYS_ADMIN)` in the handler body and return `-EPERM` unconditionally under capset-to-empty |
| MSR read/write | `ioctls/msr.c` | `capable(CAP_SYS_RAWIO)` (`arch/x86/kernel/msr.c:211`) | **1** | MSR device access checks `capable(CAP_SYS_RAWIO)` at open; both read and write ioctls inherit the open-time gate |
| `NBD_CMD_CONNECT`, `NBD_CMD_DISCONNECT`, `NBD_CMD_RECONFIGURE` | `net/netlink/genl/nbd.c` | `capable(CAP_SYS_ADMIN)` inside handler body (`drivers/block/nbd.c`) — not `GENL_ADMIN_PERM` | **1** | Policy parse runs unprivileged (no `GENL_ADMIN_PERM` flag); the handler itself calls `capable()`, blocking execution. Class 1, not class 3, because the gate is an inline `capable()` not `netlink_capable()` |

---

### Generic-netlink surfaces — Class 3 (GENL\_ADMIN\_PERM → &init\_user\_ns)

`GENL_ADMIN_PERM` routes through `netlink_capable()` which calls
`netlink_ns_capable(skb, &init_user_ns, cap)`.  The per-cmd `nla_policy`
walker runs before this check, so the attribute parser gets fuzzer coverage;
the handler body does not.

| Surface | Trinity file | Kernel gate | Class | Notes |
|---|---|---|---|---|
| nfsd `THREADS_SET`, `VERSION_SET`, `LISTENER_SET`, `POOL_MODE_SET` (4 cmds) | `net/netlink/genl/nfsd.c` | `GENL_ADMIN_PERM` → `netlink_capable()` → `&init_user_ns` (`fs/nfsd/netlink.c:133,145,157,169`) | **3** | Four SET commands dead; `RPC_STATUS_GET` + GET variants have no `GENL_ADMIN_PERM` and do reach handlers |
| lockd `SERVER_SET` | `net/netlink/genl/lockd.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`fs/lockd/netlink.c`) | **3** | Only the SET cmd is gated; `SERVER_GET` is unprivileged |
| macsec all 11 cmds | `net/netlink/genl/macsec.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`drivers/net/macsec.c`) | **3** | Full SA/SC/TX lifecycle (`GET_TXSC`, `ADD/DEL/UPD_RXSC`, `ADD/DEL/UPD_TXSA`, `ADD/DEL/UPD_RXSA`, `UPD_OFFLOAD`); all 11 commands dead |
| ovpn all 8 cmds | `net/netlink/genl/ovpn.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`drivers/net/ovpn/netlink-gen.c`) | **3** | Peer (`NEW/SET/GET/DEL`) and key (`NEW/GET/SWAP/DEL`) lifecycle; all 8 dead |
| tcmu 4 cmds | `net/netlink/genl/tcmu.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`drivers/target/target_core_user.c`) | **3** | `SET_FEATURES`, `ADDED/REMOVED/RECONFIG_DEVICE_DONE`; all 4 dead |
| sunrpc `IP_MAP_SET_REQS`, `UNIX_GID_SET_REQS`, `CACHE_FLUSH` (+2 paired cmds, 5 total) | `net/netlink/genl/sunrpc.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/sunrpc/netlink.c`) | **3** | Write cmds dead; `CACHE_NOTIFY` is kernel-emitted only |
| dpll all 6 cmds | `net/netlink/genl/dpll.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/dpll/dpll_netlink.c`) | **3** | `DEVICE_ID_GET`, `DEVICE_GET`, `DEVICE_SET`, `PIN_ID_GET`, `PIN_GET`, `PIN_SET`; all 6 dead |
| drm-ras all 3 cmds | `net/netlink/genl/drm-ras.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`drivers/gpu/drm/drm_gpuvm.c` region) | **3** | `LIST_NODES`, `GET_ERROR_COUNTER`, `CLEAR_ERROR_COUNTER`; all 3 dead |
| handshake `ACCEPT`, `DONE` (2 cmds) | `net/netlink/genl/handshake.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/handshake/netlink.c`) | **3** | Both user-callable cmds dead; `READY` is kernel-emitted multicast only |
| net\_shaper `SET`, `DELETE`, `GROUP` (3 of 5 cmds) | `net/netlink/genl/net_shaper.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/core/net_shaper.c`) | **3** | 3 write cmds dead; `CAP_GET` and `GET` are unprivileged and reach handlers |
| nl802154 admin cmds (~10) | `net/netlink/genl/nl802154.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/ieee802154/nl802154.c:2795–2867`) | **3** | Add/del PAN, add/del iface, start/stop pan, set coordinator, etc.; ~10 admin cmds dead; GET cmds are unprivileged |
| netlabel admin cmds (~4) | `net/netlink/genl/netlabel.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/netlabel/netlabel_calipso.c:336,343`) | **3** | CALIPSO DOI add/del + CIPSO variants; write cmds dead |

---

### Generic-netlink surfaces — Class 2 (GENL\_UNS\_ADMIN\_PERM → net->user\_ns)

`GENL_UNS_ADMIN_PERM` routes through `netlink_ns_capable(skb, net->user_ns, cap)`
where `net` is `genl_info_net()` — the network namespace of the sending socket.
A child that unshares a new user namespace and a subordinate network namespace is
the owner of that netns, holds full capabilities within it, and can satisfy this
gate.  These entries are **currently unreached** under the capset-to-empty model
but are structurally unlockable without any code change to trinity.

| Surface | Trinity file | Kernel gate | Class | Notes |
|---|---|---|---|---|
| batadv SET\_MESH, SET\_HARDIF, SET\_VLAN, TP\_METER, TP\_METER\_CANCEL, + 10 more (15 write cmds) | `net/netlink/genl/batadv.c` | `GENL_UNS_ADMIN_PERM` → `ns_capable(net->user_ns, CAP_NET_ADMIN)` (`net/batman-adv/netlink.c:1419–1525`) | **2** | Trinity comment correctly notes no `GENL_ADMIN_PERM`; all 15 write cmds use `GENL_UNS_ADMIN_PERM`; child-owned netns grants access |
| ovs datapath/vport/flow/packet/meter/conntrack cmds (~14) | `net/netlink/genl/ovs.c` | `GENL_UNS_ADMIN_PERM` → `ns_capable(net->user_ns, CAP_NET_ADMIN)` (`net/openvswitch/datapath.c:736`, `conntrack.c:1960,1967`, `meter.c:695,707`) | **2** | Full OVS control plane — new/del/get for datapath, vport, flow, packet exec, meter, conntrack; 14+ cmds reachable via child netns |
| l2tp tunnel/session add/del/modify/get (8 cmds) | `net/netlink/genl/l2tp.c` | `GENL_UNS_ADMIN_PERM` → `ns_capable(net->user_ns, CAP_NET_ADMIN)` (`net/l2tp/l2tp_netlink.c:946–971`) | **2** | `TUNNEL_{ADD,DELETE,MODIFY,GET}` and `SESSION_{ADD,DELETE,MODIFY,GET}`; 8 cmds reachable |
| tipc bearer/link/name/node/media/sock cmds (~12) | `net/netlink/genl/tipc.c` | `GENL_UNS_ADMIN_PERM` → `ns_capable(net->user_ns, CAP_NET_ADMIN)` (`net/tipc/netlink.c:159–208`) | **2** | Config and stats for bearer, link, name table, node, media, sock — 12 write cmds; child-owned netns unlocks |
| mptcp\_pm endpoint/limits/addr cmds (9 cmds) | `net/netlink/genl/mptcp_pm.c` | `GENL_UNS_ADMIN_PERM` → `ns_capable(net->user_ns, CAP_NET_ADMIN)` (`net/mptcp/mptcp_pm_gen.c:9 sites`) | **2** | Endpoint add/del/get, limits set/get, subflow create/destroy, addr announce/remove; 9 cmds reachable |
| ethtool write cmds (~25) | `net/netlink/genl/ethtool.c` | `GENL_UNS_ADMIN_PERM` → `ns_capable(net->user_ns, CAP_NET_ADMIN)` (`net/ethtool/netlink.c`, 25 sites) | **2** | Covers link-settings SET, rings SET, channels SET, coalesce SET, pause SET, EEE SET, WoL SET, features SET, RSS SET, FEC SET, cable-test START, tunnel-info, PHC-vclocks, etc.; large write surface reachable via child veth+netns |
| wireguard `WG_CMD_GET_DEVICE`, `WG_CMD_SET_DEVICE` (2 cmds) | `net/netlink/genl/wireguard.c` | `GENL_UNS_ADMIN_PERM` → `ns_capable(net->user_ns, CAP_NET_ADMIN)` (`drivers/net/wireguard/netlink.c`, 2 sites) | **2** | Both cmds reachable; child can create a WireGuard interface in its own netns |
| nl80211 all write cmds (~96) | `net/netlink/genl/nl80211.c` | `GENL_UNS_ADMIN_PERM` → `ns_capable(net->user_ns, CAP_NET_ADMIN)` (`net/wireless/nl80211.c`, 96 sites) | **2** | Largest class-2 surface: full cfg80211 control plane — interface add/del, AP start/stop, station add/del/change, key add/del, scan, connect/disconnect, mesh, P2P, regulatory, channel, PMK, NAN, etc.; 96 cmds currently unreached |
| netdev `NETDEV_CMD_BIND_RX` (1 cmd) | `net/netlink/genl/netdev.c` | `GENL_UNS_ADMIN_PERM` → `ns_capable(net->user_ns, CAP_NET_ADMIN)` (`net/core/netdev-genl-gen.c:223`) | **2** | Single write cmd; other netdev cmds (`DEV_GET`, `QUEUE_GET`, `NAPI_GET`, `QSTATS_GET`) are unprivileged; `BIND_TX` uses `GENL_ADMIN_PERM` → class 3 |

---

## Key Findings

### The nfsd example was misclassified in the audit spec

The triggering description stated that `GENL_ADMIN_PERM` routes to
`ns_capable(sock_net(skb->sk)->user_ns, CAP_NET_ADMIN)` (class 2).  The actual
kernel path (verified at `net/netlink/af_netlink.c:883`):

```c
bool netlink_capable(const struct sk_buff *skb, int cap)
{
    return netlink_ns_capable(skb, &init_user_ns, cap);
}
```

`netlink_capable()` always uses `&init_user_ns`, not `sock_net(skb->sk)->user_ns`.
The latter is `netlink_net_capable()` (a distinct function).  All `GENL_ADMIN_PERM`
families — including nfsd — are therefore **class 3** (dead), not class 2.

### Class-2 unlock requires two namespaces

To satisfy a `GENL_UNS_ADMIN_PERM` gate the child needs:
1. A new **user namespace** (becomes owner; gains full caps within it).
2. A new **network namespace** subordinate to that user namespace (so
   `net->user_ns` is the child's user\_ns, not `init_user_ns`).

`FIFREEZE`/`FITHAW` additionally require an owned **mount namespace** with a
child-mounted filesystem (so `sb->s_user_ns` reflects the child's user\_ns).
`TUNSETIFF` requires only a child-owned network namespace.

### Dead tail magnitude

The 100 permanently-dead entries (class 1 + class 3) represent **35 %** of the
286 admin-gated entries audited.  The bulk of the dead tail is:
- **34 btrfs ioctl handlers** with inline `capable(CAP_SYS_ADMIN)` (class 1).
- **61 genl commands** across 12 families using `GENL_ADMIN_PERM` (class 3).

Every fuzz iteration that selects one of these entries returns `-EPERM` from the
capability gate before touching any interesting kernel code.
