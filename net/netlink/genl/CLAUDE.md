# net/netlink/genl/ — Generic Netlink Family Grammars

One file per generic-netlink family, plus the runtime registry. Each family file declares a `genl_cmd_grammar[]` (`{CMD, "name"}`) and an `nla_attr_spec[]` (`{ATTR, NLA_KIND_*, size}`, mirroring the kernel's `nla_policy`), packaged into a `struct genl_family_grammar`.

## Files (47 .c files, ~6,221 LOC)
- `families.c` (712) — runtime registry: walks the statically-declared `genl_family_grammar` structs, resolves each family's dynamic `family_id` via `CTRL_CMD_GETFAMILY`/`NLM_F_DUMP` and records each listed op's doit/dumpit capability in the grammar's `cmd_caps[]`, exposes lookup helpers to the message generator. Families are `__has_include()`-gated against kernel UAPI headers.
- 46 per-family files (`nl80211.c`, `ethtool.c`, `devlink.c`, `wireguard.c`, `macsec.c`, `ovs.c`, `tipc.c`, `dpll.c`, ...). Pattern shown by `taskstats.c` (54 lines, smallest). Largest: `ovs.c` (441), `netlabel.c` (226), `batadv.c` (178), `macsec.c` (175), `nfsd.c` (167); 34 are under 130 lines.

## Notes
- Attribute specs mirror the kernel `nla_policy` exactly; header comments often cite the CVE or validation function the shape targets (e.g. taskstats → CVE-2017-2671).
- Wired by extern `struct genl_family_grammar fam_*` (declared in `include/netlink-genl-families.h`), collected by `families.c`. Adding a family = a new file here + a registry entry + the extern decl — link-time, no path coupling.
- `cmd_caps[cmd]` holds the `GENL_CMD_CAP_DO` / `GENL_CMD_CAP_DUMP` bits of the `CTRL_ATTR_OPS` entry for that cmd, 0 when the reply left the cmd out or listed no ops. Every nested length is checked against the attribute enclosing it, and an op id past 255 (`genlmsghdr.cmd` is a u8) is dropped. `gen_genl_body()` hands the picked cmd's bits to `build_one_nlmsg()`, which sets `NLM_F_DUMP` to match; `tests/genl_ops_test.c` feeds a canned reply through `genl_resolve_families()` and checks both halves, and that most genl requests clear `genl_header_check()`'s flag and reserved tests.
