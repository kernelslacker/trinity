# ns\_capable Reach Audit

This audit classifies every admin-gated surface that trinity enumerates — ioctl
tables, generic-netlink family grammars, and inline capability checks inside
netlink handlers — according to whether the kernel-side gate is permanently dead
under a capset-to-empty child or is unlockable by a child that owns a user
namespace.

## Summary

**Class 1** (inline `capable(CAP_*)` — host-scoped, permanently dead): **40 entries**  
**Class 2** (`ns_capable(obj->user_ns, CAP_*)` where *obj* is child-creatable — reachable via userns): **186 entries**  
**Class 3** (`ns_capable(&init_user_ns, …)` or object always host-owned — dead, equivalent to class 1): **261 entries**

Total admin-gated entries audited: **487**.  The class-1 count of 40 and the
class-3 count of 261 together represent **301 permanently dead entries** under the
current child capability model.  Trinity's tables list 300 of the 487 entries (all
40 of class 1, 63 of class 2 and 197 of class 3), so 237 of the dead entries are
ones the fuzzer can pick, each a guaranteed `-EPERM` fast-reject that burns fuzz
budget.  The other 187 (123 class 2, 64 class 3) are gated commands of the same
families that no grammar lists, which trinity never sends.

Counts and citations were taken against a kernel tree at v7.3-16411-g6b4b543fa187
(the 7.4 merge window).  An entry is either an ioctl request that a trinity ioctl
table lists and whose handler is gated, or a generic-netlink command, in the
kernel's ops tables of a family trinity has a grammar for, that carries
`GENL_ADMIN_PERM`, `GENL_UNS_ADMIN_PERM` or an inline gate, whether or not the
grammar lists it.  A command with both a do and a dump handler counts once, a
command compiled only under some `CONFIG_*` option counts, an inline gate in the
handler of an unflagged op is class 1 (as in the NBD row), and a grammar entry that
names a kernel-emitted event is not an op and counts as nothing.  "N of M cmds" in
the tables below means N gated commands among the family's M kernel ops; the
grammar lists all M unless the row says otherwise.  Kernel families with no
trinity grammar are out of scope; the ones with gated commands are drbd (25 class
3), mac80211\_hwsim (3 class 2) and mac802154\_hwsim (5 class 2).  Kernel paths and
line numbers move with every release, so grep for the gate macro when one stops
matching.

All 54 grammars registered in `net/netlink/genl/families.c` were counted: 36 have
class-3 commands in their kernel table and 14 have class-2 commands (`netdev` and
`nl80211` both), `nbd` and `thermal` gate inline, and `binder`, `dev-energymodel`,
`hsr` and `psample` have no gated command (`binder` has no ops).  The ioctl rows
cover only the ioctl tables audited here; other tables hold gates this audit does
not count (`FIBMAP` in `ioctls/vfs.c`, for one, tests `capable(CAP_SYS_RAWIO)` at
`fs/ioctl.c:65`).

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
| `TUNSETIFF` | `ioctls/tun.c:299` | `ns_capable(net->user_ns, CAP_NET_ADMIN)`: `tun_permitted()` (`drivers/net/tun.c:527`, called at `:2886`) when attaching to an existing device, `tun_set_iff()` (`:2917`) when creating one | **2** | Reachable when child unshares its own network namespace; `net` is derived from `current`'s netns.  `IFF_NAPI_FRAGS` also needs `capable(CAP_NET_ADMIN)` (`:2863`), dead for that flag |
| `TUNSETPERSIST` | `ioctls/tun.c:301` | none of its own (`drivers/net/tun.c:3304`); needs an fd already attached by `TUNSETIFF` | **2** | `-EBADFD` on an unattached fd, so it inherits the `TUNSETIFF` gate above; the flag value does not change the check |
| `BTRFS_IOC_ENCODED_READ` | `ioctls/btrfs.c:201` | `capable(CAP_SYS_ADMIN)` (`fs/btrfs/ioctl.c:4366`) | **1** | Already documented as permanently dead |
| `BTRFS_IOC_ENCODED_WRITE` | `ioctls/btrfs.c:204` | `capable(CAP_SYS_ADMIN)` (`fs/btrfs/ioctl.c:4470`) | **1** | Same; btrfs encoded I/O unconditionally requires global CAP\_SYS\_ADMIN |
| btrfs admin ioctls (28 requests) | `ioctls/btrfs.c:140–219` | `capable(CAP_SYS_ADMIN)` first thing in the handler (`fs/btrfs/ioctl.c`, 25 handlers; `fs/btrfs/send.c:7971`); `INO_PATHS` tests `capable(CAP_DAC_READ_SEARCH)` instead (`fs/btrfs/ioctl.c:3232`) | **1** | `FITRIM`, `RESIZE`, `DEFAULT_SUBVOL`, `ADD_DEV`, `RM_DEV`, `RM_DEV_V2`, `DEV_REPLACE`, `TREE_SEARCH`, `TREE_SEARCH_V2`, `INO_PATHS`, `LOGICAL_INO`, `LOGICAL_INO_V2` (one handler), `SCRUB`, `SCRUB_CANCEL`, `SCRUB_PROGRESS`, `BALANCE_V2`, `BALANCE_CTL`, `BALANCE_PROGRESS`, `SEND`, `QUOTA_CTL`, `QGROUP_{ASSIGN,CREATE,LIMIT}`, `QUOTA_RESCAN`, `QUOTA_RESCAN_STATUS`, `QUOTA_RESCAN_WAIT`, `SET_FSLABEL`, `SET_FEATURES` — all return `-EPERM` unconditionally under capset-to-empty |
| btrfs-control `BTRFS_IOC_SCAN_DEV`, `BTRFS_IOC_DEVICES_READY` (2 requests) | `ioctls/btrfs-control.c:22–23` | `capable(CAP_SYS_ADMIN)` in `btrfs_control_ioctl()` (`fs/btrfs/super.c:2248`) | **1** | The check precedes the command switch, so every request on `/dev/btrfs-control` is dead |
| MSR read/write (`X86_IOC_RDMSR_REGS`, `X86_IOC_WRMSR_REGS`) | `ioctls/msr.c` | `capable(CAP_SYS_RAWIO)` (`arch/x86/kernel/msr.c:214`) | **1** | MSR device access checks `capable(CAP_SYS_RAWIO)` at open; both read and write ioctls inherit the open-time gate |
| `NBD_CMD_CONNECT`, `NBD_CMD_DISCONNECT`, `NBD_CMD_RECONFIGURE` (3 of 4 cmds) | `net/netlink/genl/nbd.c` | `netlink_capable(skb, CAP_SYS_ADMIN)` inside handler body (`drivers/block/nbd.c:2175,2351,2389`) — not `GENL_ADMIN_PERM` | **1** | Policy parse runs unprivileged (no `GENL_ADMIN_PERM` flag); the handler itself calls `netlink_capable()`, blocking execution. Counted as class 1 because the check is inline in the handler body rather than a `GENL_ADMIN_PERM` flag; it resolves to the same `&init_user_ns` test as class 3, so the entry is dead either way |
| thermal `THRESHOLD_ADD`, `THRESHOLD_DELETE`, `THRESHOLD_FLUSH` (3 of 9 cmds) | `net/netlink/genl/thermal.c` | `capable(CAP_SYS_ADMIN)` inside handler body (`drivers/thermal/thermal_netlink.c:693,718,743`) — no op carries `GENL_ADMIN_PERM` | **1** | The request reaches the handler, whose first statement is the check; the other six thermal cmds are unprivileged |

The 35 `capable(CAP_SYS_ADMIN)` call sites of `fs/btrfs/ioctl.c` are not 35
ioctls.  25 are the handlers in the btrfs admin row above, 2 are
`ENCODED_READ`/`ENCODED_WRITE`, and 3 more (the io_uring encoded-read and
encoded-write paths, and `BTRFS_IOC_SHUTDOWN`) are reached through no entry of
trinity's ioctl tables.  The last 5 are conditional, so the requests behind them
are not entries:
`INO_LOOKUP` is gated only when `objectid` is not `BTRFS_FIRST_FREE_OBJECTID`;
`SNAP_DESTROY` and `SNAP_DESTROY_V2` let a regular user in under the
`user_subvol_rm_allowed` mount option; `DEFRAG` and `DEFRAG_RANGE` let in a
caller with write permission on a regular file; `GET_DEV_STATS` is gated only
for `BTRFS_DEV_STATS_RESET`.  `SNAP_CREATE(_V2)` and `SUBVOL_CREATE(_V2)` are not
admin-gated.  The table of `ioctls/btrfs.c` also lists `SCAN_DEV`, `FORGET_DEV`
and `DEVICES_READY`, which only `/dev/btrfs-control` handles, and `BALANCE`,
`TRANS_START` and `TRANS_END`, which no kernel code handles any more: on a btrfs
file `btrfs_ioctl()` answers all six `-ENOTTY` before any gate.

---

### Generic-netlink surfaces — Class 3 (GENL\_ADMIN\_PERM → &init\_user\_ns)

`GENL_ADMIN_PERM` routes through `netlink_capable()` which calls
`netlink_ns_capable(skb, &init_user_ns, cap)`.  `genl_family_rcv_msg()` makes
this check after the op lookup and before any attribute is parsed, so a child
without the capability is answered `-EPERM` before the per-cmd `nla_policy`
walker runs: neither the attribute parser nor the handler body gets fuzzer
coverage.

| Surface | Trinity file | Kernel gate | Class | Notes |
|---|---|---|---|---|
| nfsd `THREADS_SET`, `VERSION_SET`, `LISTENER_SET`, `POOL_MODE_SET`, `SVC_EXPORT_{GET,SET}_REQS`, `EXPKEY_{GET,SET}_REQS`, `CACHE_FLUSH`, `UNLOCK_{IP,FILESYSTEM,EXPORT}` (12 of 18 cmds) | `net/netlink/genl/nfsd.c` | `GENL_ADMIN_PERM` → `netlink_capable()` → `&init_user_ns` (`fs/nfsd/netlink.c:134–227`) | **3** | 12 cmds dead; `RPC_STATUS_GET`, `SERVER_STATS_GET` and the `THREADS`/`VERSION`/`LISTENER`/`POOL_MODE` GET cmds have no `GENL_ADMIN_PERM` and do reach handlers; `CACHE_NOTIFY` is a kernel-emitted event, not an op |
| lockd `SERVER_SET` (1 of 2 cmds) | `net/netlink/genl/lockd.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`fs/lockd/netlink.c:28`) | **3** | Only the SET cmd is gated; `SERVER_GET` is unprivileged |
| macsec `ADD/DEL/UPD_RXSC`, `ADD/DEL/UPD_TXSA`, `ADD/DEL/UPD_RXSA`, `UPD_OFFLOAD` (10 of 11 cmds) | `net/netlink/genl/macsec.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`drivers/net/macsec.c:3363–3417`) | **3** | SC and SA lifecycle; 10 cmds dead; only `GET_TXSC`, an unprivileged dump, reaches a handler |
| ovpn all 8 cmds | `net/netlink/genl/ovpn.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`drivers/net/ovpn/netlink-gen.c:190–260`) | **3** | Peer (`NEW/SET/GET/DEL`) and key (`NEW/GET/SWAP/DEL`) lifecycle; all 8 dead |
| tcmu all 4 cmds | `net/netlink/genl/tcmu.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`drivers/target/target_core_user.c:453–471`) | **3** | `SET_FEATURES`, `ADDED/REMOVED/RECONFIG_DEVICE_DONE`; all 4 dead |
| sunrpc `IP_MAP_{GET,SET}_REQS`, `UNIX_GID_{GET,SET}_REQS`, `CACHE_FLUSH` (all 5 cmds) | `net/netlink/genl/sunrpc.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/sunrpc/netlink.c:52–78`) | **3** | All 5 ops dead; `CACHE_NOTIFY` is kernel-emitted only |
| dpll all 6 cmds | `net/netlink/genl/dpll.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`drivers/dpll/dpll_nl.c:92–147`; handlers in `dpll_netlink.c`) | **3** | `DEVICE_ID_GET`, `DEVICE_GET`, `DEVICE_SET`, `PIN_ID_GET`, `PIN_GET`, `PIN_SET`; all 6 dead |
| drm-ras all 5 cmds | `net/netlink/genl/drm-ras.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`drivers/gpu/drm/drm_ras_nl.c:49–84`) | **3** | `LIST_NODES`, `GET_ERROR_COUNTER`, `CLEAR_ERROR_COUNTER`, `GET_ERROR_THRESHOLD`, `SET_ERROR_THRESHOLD`; all 5 dead.  The grammar lists the first 3 and not the two threshold cmds |
| handshake `ACCEPT`, `DONE` (both cmds) | `net/netlink/genl/handshake.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/handshake/genl.c:34,41`) | **3** | Both user-callable cmds dead; `READY` is kernel-emitted multicast only |
| net\_shaper `SET`, `DELETE`, `GROUP` (3 of 5 cmds) | `net/netlink/genl/net_shaper.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/shaper/shaper_nl_gen.c:112,121,130`) | **3** | 3 write cmds dead; `CAP_GET` and `GET` are unprivileged and reach handlers |
| nl802154 34 of 37 cmds | `net/netlink/genl/nl802154.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/ieee802154/nl802154.c:2795–3075`) | **3** | Every cmd but `GET_WPAN_PHY`, `GET_INTERFACE` and `LIST_ASSOCIATIONS`: interface add/del, 13 `SET_*` cmds (channel, PAN id, short address, TX power, CCA, backoff, retries, LBT, ack default, PHY netns, max associations), scan and beacon control, associate / disassociate, and 13 `SEC_*` cmds (`SET_SEC_PARAMS` and the `NEW`/`DEL`/`GET` key, device, devkey and level cmds) that exist only with `CONFIG_IEEE802154_NL802154_EXPERIMENTAL`; 34 dead |
| netlabel 13 of 24 cmds: NLBL\_MGMT 4, NLBL\_CIPSOv4 2, NLBL\_UNLBL 5, NLBL\_CALIPSO 2 | `net/netlink/genl/netlabel.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/netlabel/netlabel_mgmt.c:760–788`, `netlabel_cipso_v4.c:734–741`, `netlabel_unlabeled.c:1295–1337`, `netlabel_calipso.c:336–343`) | **3** | `MGMT` `ADD`, `REMOVE`, `ADDDEF`, `REMOVEDEF`; `CIPSOV4` and `CALIPSO` `ADD`, `REMOVE`; `UNLABEL` `ACCEPT`, `STATICADD`, `STATICREMOVE`, `STATICADDDEF`, `STATICREMOVEDEF`; the `LIST*`, `PROTOCOLS` and `VERSION` cmds are unprivileged; 13 dead |
| cifs `SWN_NOTIFY` (1 of 1 cmd) | `net/netlink/genl/cifs.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`fs/smb/client/netlink.c:36`) | **3** | The only op of the family; `REGISTER` and `UNREGISTER` are kernel-emitted events the grammar does not list |
| devlink 35 of 57 cmds | `net/netlink/genl/devlink.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/devlink/netlink_gen.c:745–1380`) | **3** | Every `NEW`, `SET`, `DEL` and action cmd (port, sb, eswitch, resource, reload, param, region, health reporter, flash, trap, rate, linecard, selftests) is gated, as are the reads `ESWITCH_GET`, `REGION_READ` and `HEALTH_REPORTER_DUMP_GET`; 35 dead.  The grammar lists 6 of the 57 cmds, the unprivileged `*_GET` ones, and none of the gated cmds |
| fou `ADD`, `DEL` (2 of 3 cmds) | `net/netlink/genl/fou.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/ipv4/fou_nl.c:35,41`) | **3** | `GET` is unprivileged |
| gtp `NEWPDP`, `DELPDP`, `GETPDP`, `ECHOREQ` (all 4 cmds) | `net/netlink/genl/gtp.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`drivers/net/gtp.c:2461–2480`) | **3** | Even the `GETPDP` getter is gated; all 4 dead |
| ieee802154 (legacy "802.15.4 MAC") 22 of 24 cmds | `net/netlink/genl/ieee802154.c` | `GENL_ADMIN_PERM` set by the `IEEE802154_OP`, `IEEE802154_OP_RELAXED` and `IEEE802154_DUMP_PRIV` macros → `&init_user_ns` (`net/ieee802154/ieee802154.h:11–41`; table at `net/ieee802154/netlink.c:84–119`) | **3** | Every cmd but `LIST_PHY` and `LIST_IFACE` (the unflagged `IEEE802154_DUMP` entries): iface add/del, the associate, scan and start requests, `SET_MACPARAMS` and the 14 `LLSEC_*` cmds; 22 dead |
| ila `ADD`, `DEL`, `FLUSH` (3 of 4 cmds) | `net/netlink/genl/ila.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/ipv6/ila/ila_main.c:20–32`) | **3** | `GET` is unprivileged |
| ioam6 all 7 cmds | `net/netlink/genl/ioam6.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/ipv6/ioam6.c:557–605`) | **3** | Namespace and schema add / del / dump and `NS_SET_SCHEMA`; all 7 dead |
| ipvs all 16 cmds | `net/netlink/genl/ipvs.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/netfilter/ipvs/ip_vs_ctl.c:4921–5012`) | **3** | Every IPVS op is gated, the read-only getters included; all 16 dead.  The grammar lists 5 of the 16, the `GET_SERVICE`, `GET_DEST`, `GET_DAEMON`, `GET_CONFIG` and `GET_INFO` getters; the 11 mutators (`NEW`/`SET`/`DEL` for service and dest, `NEW_DAEMON`, `DEL_DAEMON`, `SET_CONFIG`, `ZERO`, `FLUSH`) are left out on purpose |
| ncsi 5 of 6 cmds | `net/netlink/genl/ncsi.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/ncsi/ncsi-netlink.c:739–763`) | **3** | Every cmd but `PKG_INFO`; 5 dead |
| net\_dm `START`, `STOP`, `CONFIG` (3 of 5 cmds) | `net/netlink/genl/net_dm.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/core/drop_monitor.c:1614–1626`) | **3** | `CONFIG_GET` and `STATS_GET` are unprivileged |
| netdev `NAPI_SET`, `QUEUE_CREATE` (2 of 10 cmds) | `net/netlink/genl/netdev.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/core/netdev-genl-gen.c:237,251`) | **3** | `BIND_RX` is class 2 (below); the rest are unprivileged.  `QUEUE_CREATE` also tests `capable(CAP_NET_ADMIN)` inline when `NETDEV_A_LEASE_NETNS_ID` is present (`net/core/netdev-genl.c:1332`) |
| nfc 15 of 19 cmds | `net/netlink/genl/nfc.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/nfc/netlink.c:1711–1813`) | **3** | Every cmd but `GET_DEVICE`, `GET_TARGET`, `LLC_GET_PARAMS` and `GET_SE`; 15 dead |
| nl80211 16 of 124 cmds | `net/netlink/genl/nl80211.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/wireless/nl80211.c:20641–21343`) | **3** | `SET_REG`, `REQ_SET_REG`, `RELOAD_REGDB`, `UPDATE_CONNECT_PARAMS`, `EXTERNAL_AUTH`, `UPDATE_OWE_INFO`, `START_PD`, `STOP_PD`, and the NAN cmds `START_NAN`, `STOP_NAN`, `ADD_NAN_FUNCTION`, `DEL_NAN_FUNCTION`, `CHANGE_NAN_CONFIG`, `NAN_SET_LOCAL_SCHED`, `NAN_SET_PEER_SCHED`, `NAN_SET_NON_EVAC_CHANNELS`; 16 dead (`SET_REG` exists only with `CONFIG_CFG80211_CRDA_SUPPORT`).  The grammar lists 6 of the family's 124 cmds and none of these 16 |
| psp `DEV_SET`, `KEY_ROTATE`, `DEV_ASSOC`, `DEV_DISASSOC` (4 of 8 cmds) | `net/netlink/genl/psp.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/psp/psp-nl-gen.c:93–152`) | **3** | `DEV_GET`, `RX_ASSOC`, `TX_ASSOC` and `GET_STATS` are unprivileged |
| seg6 all 4 cmds | `net/netlink/genl/seg6.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/ipv6/seg6.c:470–490`) | **3** | `SETHMAC`, `DUMPHMAC`, `SET_TUNSRC`, `GET_TUNSRC`; all 4 dead |
| SMC\_GEN\_NETLINK `ADD_UEID`, `REMOVE_UEID`, `FLUSH_UEID`, `ENABLE_SEID`, `DISABLE_SEID`, `ENABLE_HS_LIMITATION`, `DISABLE_HS_LIMITATION` (7 of 18 cmds) | `net/netlink/genl/smc_gen.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/smc/smc_netlink.c:84–126`) | **3** | The mutators; the `GET_*` and `DUMP_*` cmds are unprivileged |
| SMC\_PNETID `ADD`, `DEL`, `FLUSH` (3 of 4 cmds) | `net/netlink/genl/smc_pnetid.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/smc/smc_pnet.c:705–717`) | **3** | `GET` is unprivileged |
| taskstats `TASKSTATS_CMD_GET` (1 of 2 cmds) | `net/netlink/genl/taskstats.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`kernel/taskstats.c:655`) | **3** | The PID, TGID and cpumask selectors all sit behind the one gated cmd; the family's other op, `CGROUPSTATS_CMD_GET`, is unprivileged and not listed |
| tcp\_metrics `DEL` (1 of 2 cmds) | `net/netlink/genl/tcp_metrics.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`net/ipv4/tcp_metrics.c:993`) | **3** | `GET` is unprivileged |
| team `OPTIONS_SET`, `OPTIONS_GET`, `PORT_LIST_GET` (3 of 4 cmds) | `net/netlink/genl/team.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`drivers/net/team/team_nl.c:46–58`) | **3** | Only `NOOP` is open; the getters are gated too |
| vdpa `DEV_NEW`, `DEV_DEL`, `DEV_VSTATS_GET`, `DEV_ATTR_SET` (4 of 7 cmds) | `net/netlink/genl/vdpa.c` | `GENL_ADMIN_PERM` → `&init_user_ns` (`drivers/vdpa/vdpa.c:1516–1541`) | **3** | `MGMTDEV_GET`, `DEV_GET` and `DEV_CONFIG_GET` are unprivileged.  `DEV_NEW` also tests `netlink_capable(skb, CAP_NET_ADMIN)` inline when network attributes are given (`drivers/vdpa/vdpa.c:625`) |

---

### Generic-netlink surfaces — Class 2 (GENL\_UNS\_ADMIN\_PERM → net->user\_ns)

`GENL_UNS_ADMIN_PERM` routes through `netlink_ns_capable(skb, net->user_ns, cap)`
where `net` is `genl_info_net()` — the network namespace of the sending socket.
A child that unshares a new user namespace and a subordinate network namespace is
the owner of that netns, holds full capabilities within it, and can satisfy this
gate.  These entries are **currently unreached** under the capset-to-empty model
but are structurally unlockable without any code change to trinity beyond the lane
itself; the 123 that no grammar lists (the nl80211, ethtool and tipc rows say which)
also need the grammar to name them.  Every family in this table sets `.netnsok`, so
`genl_family_rcv_msg()` (`net/netlink/genetlink.c:1167`) does not turn a child's own
netns away with `-ENOENT`.

| Surface | Trinity file | Kernel gate | Class | Notes |
|---|---|---|---|---|
| batadv `SET_MESH`, `SET_HARDIF`, `SET_VLAN`, `TP_METER`, `TP_METER_CANCEL` (5 write cmds) + 10 table / routing-algo dumps (15 of 18 cmds) | `net/netlink/genl/batadv.c` | `GENL_UNS_ADMIN_PERM` → `ns_capable(net->user_ns, CAP_NET_ADMIN)` (`net/batman-adv/netlink.c:1427–1533`) | **2** | The grammar comment correctly names `GENL_UNS_ADMIN_PERM`, not `GENL_ADMIN_PERM`; the 5 write cmds and the 10 dumps all use `GENL_UNS_ADMIN_PERM`; `GET_MESH`, `GET_HARDIF` and `GET_VLAN` carry no flag; child-owned netns grants access |
| ovs datapath / vport / flow `NEW`, `DEL`, `SET`, packet `EXECUTE`, meter `SET`, `DEL`, conntrack-limit `SET`, `DEL` (14 of 20 cmds, six families) | `net/netlink/genl/ovs.c` | `GENL_UNS_ADMIN_PERM` → `ns_capable(net->user_ns, CAP_NET_ADMIN)` (`net/openvswitch/datapath.c:738,1580–1596,2129–2145,2644–2660`, `conntrack.c:1992,1999`, `meter.c:695,707`) | **2** | OVS control plane — 9 datapath / vport / flow writers, 1 packet exec, 2 meter, 2 conntrack-limit; the `GET` cmds and `METER_FEATURES` carry no flag; 14 cmds reachable via child netns |
| l2tp `TUNNEL_{CREATE,DELETE,MODIFY,GET}` and `SESSION_{CREATE,DELETE,MODIFY,GET}` (8 of 9 cmds) | `net/netlink/genl/l2tp.c` | `GENL_UNS_ADMIN_PERM` → `ns_capable(net->user_ns, CAP_NET_ADMIN)` (`net/l2tp/l2tp_netlink.c:946–990`) | **2** | 8 cmds reachable; `NOOP` carries no flag |
| tipc `BEARER_ENABLE`, `BEARER_DISABLE`, `BEARER_ADD`, `BEARER_SET`, `MEDIA_SET`, `NET_SET`, `LINK_SET`, `LINK_RESET_STATS`, `MON_SET`, `PEER_REMOVE`, `KEY_SET`, `KEY_FLUSH` (12 of 24 cmds) | `net/netlink/genl/tipc.c` | `GENL_UNS_ADMIN_PERM` → `ns_capable(net->user_ns, CAP_NET_ADMIN)` (`net/tipc/netlink.c:159–292`) | **2** | 12 write cmds reachable via child-owned netns (`KEY_SET` and `KEY_FLUSH` exist only with `CONFIG_TIPC_CRYPTO`); the getters carry no flag.  The grammar lists 15 of the 24 cmds, 7 of them gated (`BEARER_ENABLE`, `BEARER_DISABLE`, `BEARER_SET`, `NET_SET`, `LINK_SET`, `LINK_RESET_STATS`, `MON_SET`); the other 5 gated cmds are unlisted |
| mptcp\_pm `ADD_ADDR`, `DEL_ADDR`, `FLUSH_ADDRS`, `SET_LIMITS`, `SET_FLAGS`, `ANNOUNCE`, `REMOVE`, `SUBFLOW_CREATE`, `SUBFLOW_DESTROY` (9 of 11 cmds) | `net/netlink/genl/mptcp_pm.c` | `GENL_UNS_ADMIN_PERM` → `ns_capable(net->user_ns, CAP_NET_ADMIN)` (`net/mptcp/mptcp_pm_gen.c:99–178`) | **2** | 9 cmds reachable; `GET_ADDR` and `GET_LIMITS` carry no flag |
| ethtool `*_SET` and `*_ACT` cmds plus `WOL_GET` and `MODULE_EEPROM_GET` (25 of 52 cmds) | `net/netlink/genl/ethtool.c` | `GENL_UNS_ADMIN_PERM` → `ns_capable(net->user_ns, CAP_NET_ADMIN)` (`net/ethtool/netlink.c:1184–1563`) | **2** | Covers link-settings, link-modes, debug, WoL, features, privflags, rings, channels, coalesce, pause, EEE, FEC, module, PSE, PLCA, MM, TSCONFIG and RSS `SET`, `CABLE_TEST_ACT`, `CABLE_TEST_TDR_ACT`, `MODULE_FW_FLASH_ACT`, `RSS_CREATE_ACT` and `RSS_DELETE_ACT`; large write surface reachable through any netdev, such as a veth, in the child's own netns.  The grammar lists 28 of the 52 cmds, all read-side, and 2 of them are gated (`WOL_GET`, `MODULE_EEPROM_GET`); the other 23 gated cmds are unlisted |
| wireguard `WG_CMD_GET_DEVICE`, `WG_CMD_SET_DEVICE` (2 of 2 cmds) | `net/netlink/genl/wireguard.c` | `GENL_UNS_ADMIN_PERM` → `ns_capable(net->user_ns, CAP_NET_ADMIN)` (`drivers/net/wireguard/generated/netlink.c:64,71`) | **2** | Both cmds reachable; child can create a WireGuard interface in its own netns.  `SET_DEVICE` with `LISTEN_PORT` or `FWMARK` also tests `ns_capable(net->user_ns, CAP_NET_ADMIN)` on the netns that created the device (`drivers/net/wireguard/netlink.c:494`), which the child owns |
| nl80211 `GET_KEY` and the cfg80211 write cmds (96 of 124 cmds) | `net/netlink/genl/nl80211.c` | `GENL_UNS_ADMIN_PERM` → `ns_capable(net->user_ns, CAP_NET_ADMIN)` (`net/wireless/nl80211.c:20467–21349`) | **2** | Largest class-2 surface: full cfg80211 control plane — interface add/del/set, AP start/stop, station and mesh-path add/del/set, key add/del, scan and sched-scan, authenticate / associate / connect / disconnect, IBSS, mesh, OCB, P2P, TDLS, PMKSA, channel, MLO link cmds, etc. (`SET_WOWLAN` exists only with `CONFIG_PM`, `TESTMODE` only with `CONFIG_NL80211_TESTMODE`).  The grammar lists 6 of the family's 124 cmds, all read-side, and 1 of them is gated (`GET_KEY`); the other 95 gated cmds are unlisted.  The family's 16 `GENL_ADMIN_PERM` cmds are in the class-3 table |
| netdev `NETDEV_CMD_BIND_RX` (1 of 10 cmds) | `net/netlink/genl/netdev.c` | `GENL_UNS_ADMIN_PERM` → `ns_capable(net->user_ns, CAP_NET_ADMIN)` (`net/core/netdev-genl-gen.c:230`) | **2** | Single write cmd; other netdev cmds (`DEV_GET`, `QUEUE_GET`, `NAPI_GET`, `QSTATS_GET`, `BIND_TX`, the page-pool getters) are unprivileged; `NAPI_SET` and `QUEUE_CREATE` use `GENL_ADMIN_PERM` → class 3 |

---

## Key Findings

### The nfsd example was misclassified in the audit spec

The triggering description stated that `GENL_ADMIN_PERM` routes to
`ns_capable(sock_net(skb->sk)->user_ns, CAP_NET_ADMIN)` (class 2).  The actual
kernel path (verified at `net/netlink/af_netlink.c:880`):

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

The 301 permanently-dead entries (class 1 + class 3) represent **62 %** of the
487 admin-gated entries audited, and trinity's tables list 237 of them.  The bulk
of the dead tail is:
- **261 genl commands** across 36 grammars using `GENL_ADMIN_PERM` (class 3), 197 of
  them listed in a grammar.
- **32 btrfs ioctl requests** with an unconditional inline `capable()` (class 1):
  30 in `ioctls/btrfs.c` and 2 in `ioctls/btrfs-control.c`.

The other 8 class-1 entries are the 2 MSR ioctls and 6 genl commands whose handlers
test the capability inline (`nbd` 3, `thermal` 3).

Every fuzz iteration that selects one of the 237 listed dead entries returns
`-EPERM` from the capability gate before touching any interesting kernel code; the
64 class-3 commands that no grammar lists are never sent.
