# Argument-generator tuning options

Companion to `main/params/help.c`, `args/`, and `chains/`.  These
options tune the content-authoring lanes that sit BEHIND the argument
generator (post-`ARG_*` hook, pre-syscall issue) and the chain link
generator.  The `--help` output carries only a one-line contract per
option; the ladder shape, the fallback path, and the byte-identical
`off` guarantee live here.

## --arg-len-semantics

Object-size-relative `ARG_LEN` draw mode.  When the slot before an
`ARG_LEN` is an `ARG_ADDRESS` / `ARG_NON_NULL_ADDRESS` whose value
falls in a tracked writable region, the length is drawn from a
size-relative boundary set capped by the region's remaining extent
so a kernel-WRITES-buffer syscall cannot scribble past the writable
region.  Falls back to `get_len()` on no companion / unresolvable
size.

- `off`: `gen_arg_len` calls `get_len()` verbatim, no companion-arg
  lookup, no extra RNG draw.  Byte-identical to a build without this
  flag.
- `on`: object-size-relative draw with the fallback described above.

## --cmsg-richness

Extended `sendmsg` / `sendmmsg` control-message generator.

- `off`: `pick_cmsg_kind()` draws from the original 5 base kinds with
  a single `rnd_modulo_u32` call; the cmsg-build site is bit-for-bit
  identical to a build without this lever -- no extra RNG draws, no
  new kinds, no new arms.
- `on`: extends the per-call cmsg pool with family-gated single-cmsg
  kinds -- `IP_PKTINFO` / `IPV6_PKTINFO`, `IP_TOS` / `IP_TTL` /
  `IP_RETOPTS`, `IPV6_TCLASS` / `IPV6_HOPLIMIT` / `IPV6_RTHDR`,
  `SCM_TXTIME`, `TLS_SET_RECORD_TYPE` -- and adds a `ONE_IN(4)`
  multi-cmsg packer that sizes the buffer by the sum of
  `CMSG_SPACE(plen)` across 2-3 distinct entries from a per-family
  pool, zero-fills the buffer up front, and walks `CMSG_FIRSTHDR`
  -> `CMSG_NXTHDR` with `CMSG_LEN(plen)` per entry.

## --chain-resource-typing

Chain-generator bias to pair resource producers with consumers using
the small fd-family table in `chain-restype.c`.

- `off`: classify hook returns early; byte-identical to today.
- `shadow`: count per-kind `chain_restype_produced` /
  `chain_restype_would_bias` but leave generation identical to `off`.
  Pure observation to measure the opportunity size.
- `live`: actually override the next chain link with a random
  consumer of the produced kind, probabilistically so other links
  stay possible; bumps `chain_restype_biased`.

Per-kind `chain_restype_save` / `chain_restype_replay_win` are the
productivity signals that decide which families to extend into.
