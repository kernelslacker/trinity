# childops-nfnl design notes

Companion to `include/childops-nfnl.h`.  The header keeps the struct
definitions and per-function contracts (load-bearing wire semantics
stay next to the declarations); this document holds the top-level
scaffolding essay: why this layer exists, what it consolidates from
the per-file copies it replaced, and where the boundary sits between
this layer and per-childop code.

## Why a shared NETLINK_NETFILTER scaffolding layer

Companion layer to `include/childops-netlink.h`.  Several childops
open `NETLINK_NETFILTER` sockets and emit nfnetlink-shaped messages
(`nlmsghdr` with `type = (subsys << 8) | msg_type`, followed by an
`nfgenmsg` payload carrying family + version + res_id).  Each
per-file copy reimplemented the same socket / bind / `SO_RCVTIMEO`
sequence and the same nfgenmsg-envelope stamper.  A couple also
reimplemented the `BATCH_BEGIN ... ops ... BATCH_END` coalesced
`sendmsg` + drain that nf_tables transactions ride on top of.

This header consolidates that wire scaffolding so per-childop code
can stay focused on the per-message attribute / op selection that is
the actual fuzzing surface.

## In scope (intentionally narrow)

- Open / close a `NETLINK_NETFILTER` socket via the shared `nl_open()`
  plumbing, with an optional multicast subscribe mask and
  `SO_RCVTIMEO`.
- Stamp an nfnetlink envelope (`nlmsghdr` with the subsys-encoded
  type + an `nfgenmsg` payload) into a caller-provided buffer.
- Stamp `BATCH_BEGIN` / `BATCH_END` markers for nf_tables
  transactions so callers can compose a multi-op batch into one
  `sendmsg`.
- Single-ack send/recv with the same `-EIO`-on-non-error semantic as
  `nl_send_recv()`.
- Coalesced batch send/drain for the `BATCH_BEGIN ... BATCH_END`
  pattern: one `sendmsg` of the whole transaction, then drain every
  queued reply, returning the first `NLMSG_ERROR` with `err != 0`.
- Dump-style send/drain that tolerates `EAGAIN` as "no completion
  seen" without wedging on a kernel that doesn't reply.

## Out of scope (per-childop concerns that stay local)

- Per-op message builders (attribute walk, expression composition,
  verdict selection).  These are the fuzzing surface; they belong
  next to the per-op coverage rationale.
- Per-subsys constant shims.  `NFNL_SUBSYS_NFTABLES`,
  `NFNL_SUBSYS_CTNETLINK` and the `NFNL_MSG_BATCH_BEGIN` / `_END`
  marker IDs live in `<linux/netfilter/nfnetlink.h>`; the per-subsys
  message-type / attribute IDs live in
  `<linux/netfilter/nfnetlink_*.h>` and
  `<linux/netfilter/nf_tables.h>` and are caller business.
- `NLMSG_ALIGN` and the `nla_put_*()` family.  Already provided by
  `<linux/netlink.h>` and `include/childops-netlink.h` respectively.
