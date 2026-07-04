# net/netlink/genl/ — Generic Netlink Family Grammars

One file per generic-netlink family, plus the runtime registry. Each family file declares a `genl_cmd_grammar[]` (`{CMD, "name"}`) and an `nla_attr_spec[]` (`{ATTR, NLA_KIND_*, size}`, mirroring the kernel's `nla_policy`), packaged into a `struct genl_family_grammar`.

## Files (46 files)
- `families.c` (621) — runtime registry: walks the statically-declared `genl_family_grammar` structs, resolves each family's dynamic `family_id` via `CTRL_CMD_GETFAMILY`/`NLM_F_DUMP`, exposes lookup helpers to the message generator. Families are `__has_include()`-gated against kernel UAPI headers.
- 45 per-family files (`nl80211.c`, `ethtool.c`, `devlink.c`, `wireguard.c`, `macsec.c`, `ovs.c`, `tipc.c`, `dpll.c`, ...). Pattern shown by `taskstats.c` (54 lines, smallest). Largest: `ovs.c` (441), `macsec.c` (232), `netlabel.c` (226), `nl802154.c` (209), `ieee802154.c` (201); ~35 are under 130 lines.

## Notes
- Attribute specs mirror the kernel `nla_policy` exactly; header comments often cite the CVE or validation function the shape targets (e.g. taskstats → CVE-2017-2671).
- Wired by extern `struct genl_family_grammar fam_*` (declared in `include/netlink-genl-families.h`), collected by `families.c`. Adding a family = a new file here + a registry entry + the extern decl — link-time, no path coupling.
- `childops/genetlink-fuzzer.c` does its own independent runtime op-discovery, intentionally decoupled from this registry so the two paths can't share fragile state.
