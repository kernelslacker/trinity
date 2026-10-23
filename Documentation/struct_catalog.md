# struct_catalog design notes

Long-form design rationale lifted out of `struct_catalog/registry.c`.
The C file keeps per-entry one-liners and regression-guard invariants
inline; the essays below explain the mechanisms those entries lean on.

## Attribution-only registration

Recurring pattern across most `syscall_struct_args[]` rows below: the
entry does **not** switch the schema-aware fill path onto the slot
(that path is gated on `argtype[N] == ARG_STRUCT_PTR_*`). The bespoke
sanitiser in `syscalls/<foo>.c` remains the sole writer of `rec->aN`,
and the catalog row exists only so that `struct_field_for_cmp()` can
name the specific struct field a KCOV-CMP-learned constant fell out
of, rather than attributing that constant to a coincidentally-same-
width slot.

"Not mapped here on purpose" comments elsewhere in the file mark
sibling arg slots that carry the same struct on a kernel-written
output path -- registering an OUTPUT slot would steer learned
constants at bytes the kernel wrote rather than bytes we stamped.

## fcntl a3 -- cmd-discriminated struct pointer

`fcntl(int fd, int cmd, ... arg)`: a3's type depends on the cmd in a2
-- the first proof of the discriminator-aware `syscall_struct_args[]`
mechanism. Two attribution-only variants (bespoke `sanitise_fcntl()`
owns the live fill):

- `struct flock` for `F_GETLK` / `F_SETLK` / `F_SETLKW`, the
  `F_OFD_*` variants, `F_CANCELLK` (and the LK64 variants on archs
  where `F_GETLK64 != F_GETLK`). `build_flock()` picks an
  `l_type` / `l_whence` vocab member, a bounded `l_start` and
  `l_len`, and zeroes `l_pid`. `struct_field_for_cmp()` steers
  CMP-learned constants at the named `l_type` / `l_whence` slots.

- `struct f_owner_ex` for `F_GETOWN_EX` / `F_SETOWN_EX`. The bespoke
  arm picks type from `{F_OWNER_TID, F_OWNER_PID, F_OWNER_PGRP}` and
  stamps `get_pid()` into `pid`; `struct_field_for_cmp()` steers
  CMP-learned constants at the named `type` slot.

cmds that don't carry a struct at a3 (`F_DUPFD`, `F_GETFD`,
`F_SETFL`, `F_*OWN`, `F_*SIG`, `F_*LEASE`, `F_*PIPE_SZ`,
`F_ADD_SEALS`, `F_NOTIFY`, `F_DUPFD_QUERY`, ...) match no variant
and resolve to NULL -- `gen_arg_struct_ptr_inout` falls through to a
zeroed fallback buffer that `sanitise_fcntl` overwrites with an fd
or integer flag word, same as before.

## setsockopt optval -- two-key (level, optname) rows

`setsockopt(fd, level, optname, optval, optlen)` optval -- a4.

Proof batch for the two-key discriminator extension: (level,
optname) shapes already owned by bespoke `build_*()` functions in
`syscalls/socket/setsockopt-optval-builders.c`, now resolved through
`struct_arg_lookup_two_key()` from `apply_sockopt_entry()` in
`syscalls/socket/setsockopt.c`.
`discrim_arg_idx=2` is level (a2) and `discrim2_arg_idx=3` is
optname (a3); the explicit-key consumer passes them directly off
the picked `sockopt_table[]` row so the lookup runs against the
authoritative picked values, not the post-mangle `rec->a2/a3` the
kernel would see.

`argtype[3]` is not `ARG_STRUCT_PTR_*`, so the rec-based
`struct_arg_lookup()` never resolves these rows -- which is the
point: the bespoke driver owns selection / optlen / BPF-arm
replacement / per-fd pairing, and routes only the fill through the
catalog when a row matches. Bespoke builders remain in code as the
miss-fallback for the int / bool / string scalar `sockopt_table[]`
entries (no struct shape, no row to register) and for the
higher-leverage shapes (sctp / mptcp / tcp_repair / can_filter[]
etc.) that follow this proof.

`setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, ...)` stays bespoke: the
BPF arm REPLACES the optval allocation wholesale rather than fills it
(see the `SO_ATTACH_FILTER` branch of `socket_setsockopt()`), so a
schema-fill row would race the `bpf_gen_filter()` replacement.
