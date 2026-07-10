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

## timeval slots -- settimeofday / select / futimesat / utimes

All four rows are attribution-only; the bespoke sanitiser remains
the sole writer of the timeval slot, and the catalog row lets
`struct_field_for_cmp` steer CMP-learned constants at `tv_sec` /
`tv_usec` rather than at a coincidentally-same-width slot.

- `settimeofday(struct timeval *tv, struct timezone *tz)`: a1 is the
  INPUT timeval. `sanitise_settimeofday()` fills 70% near-now via
  `clock_gettime()` + bounded `tv_usec`, 30% random with an explicit
  invalid-`tv_usec` leg.

- `select(int n, fd_set *, fd_set *, fd_set *, struct timeval *tvp)`:
  a5 is the INOUT timeout. `sanitise_select()` stamps a deterministic
  `{0, 10us}` short timeout in the writable buffer it allocates; the
  kernel may write back the remaining time, so the slot is INOUT.

- `futimesat(int dfd, const char *filename, struct timeval *utimes)`:
  a3 is the INPUT `struct timeval[2]` pointer. `sanitise_futimesat()`
  owns the live fill via a bucketed picker (NULL leg, near-now /
  far-past / far-future valid, deliberately invalid `tv_usec`, mixed,
  fully random) writing both array elements into a
  `get_writable_address(sizeof(*tv) * 2)` slab. Registration
  describes `utimes[0]` only -- the single-struct descriptor cannot
  span the `[2]` array, but covering the first element is enough.

- `utimes(char *filename, struct __kernel_old_timeval *utimes)`: a2 is
  the INPUT `struct timeval[2]` pointer. Same single-element caveat
  as `futimesat`.

Not mapped: `gettimeofday`'s a1 is a kernel-written OUTPUT with no
input fill to attribute against.

`settimeofday`'s a2 (`struct timezone`) is registered separately with
its own attribution-only row -- `sanitise_settimeofday()` runs a
`RAND_BOOL()` gate over `get_writable_address()`: a 50/50 zero-leg
vs random-leg producing `tz_minuteswest` in `[-780, +780]` and
`tz_dsttime` in `[0, 3]`. `gettimeofday`'s a2 is likewise a
kernel-written OUTPUT and not mapped.

## landlock_add_rule a3 -- rule_type-discriminated struct pointer

`landlock_add_rule(int ruleset_fd, enum landlock_rule_type rule_type,
const void *rule_attr, __u32 flags)`: a3's type depends on the
`rule_type` in a2, mirroring fcntl's cmd-discriminated a3.

Two variants, both attribution-only (the bespoke
`sanitise_landlock_add_rule()` keeps owning the live fill --
`argtype[2]` is not declared, so the schema-aware fill path never
runs against `rec->a3`):

- `struct landlock_path_beneath_attr` for
  `LANDLOCK_RULE_PATH_BENEATH`. The bespoke arm masks
  `allowed_access` to the low 16 bits (`LANDLOCK_ACCESS_FS_*`) and
  stamps `get_random_fd()` into `parent_fd`; `struct_field_for_cmp()`
  steers CMP-learned constants at the named `allowed_access` /
  `parent_fd` slots.

- `struct landlock_net_port_attr` for `LANDLOCK_RULE_NET_PORT`. The
  bespoke arm picks `allowed_access` from the 2-bit
  `LANDLOCK_ACCESS_NET_*` pool and stratifies `port` across
  ephemeral / well-known / privileged / unprivileged ranges;
  `struct_field_for_cmp()` steers CMP-learned constants at the named
  `allowed_access` / `port` slots.

`rule_type`s outside both lists match no variant and resolve to NULL
-- `gen_arg_struct_ptr_inout` falls through to a zeroed fallback
buffer that `sanitise_landlock_add_rule`'s switch default leaves
untouched (`rec->a3` keeps whatever the generic arg-gen wrote), same
as before.

Pre-discriminator the catalog could map only one descriptor per
(syscall, arg), so a3 resolved to `landlock_path_beneath_attr` for
every `rule_type` and `struct_field_for_cmp()` was attributing
CMP-learned constants at `allowed_access` / `parent_fd` even on
`NET_PORT` dispatches where the kernel was reading a wholly
different struct.

## quotactl / quotactl_fd a4 -- packed subcmd discriminator

`quotactl(unsigned int cmd, const char *special, qid_t id, void *addr)`
and
`quotactl_fd(unsigned int fd, unsigned int cmd, qid_t id, void *addr)`
share the `addr` slot: `struct if_dqblk` under `Q_SETQUOTA`,
`struct if_dqinfo` under `Q_SETINFO`, `struct fs_disk_quota` under
`Q_XSETQLIM`. The SET paths are the input arms where the bytes we
stamp actually reach the kernel's quota lookup.

Both sanitisers keep owning the live fill; the catalog rows are
attribution-only so `struct_field_for_cmp()` can steer CMP-learned
constants at the named limit / time / valid slots.

**Packed cmd discriminator.** `rec->a1` (quotactl) / `rec->a2`
(quotactl_fd) is `QCMD(subcmd, type)` ==
`(subcmd << SUBCMDSHIFT) | (type & SUBCMDMASK)`, so the
pre-extension exact-match discriminator could never resolve
(`Q_SETQUOTA` would have had to land in the low byte to compare
equal to the raw arg). `discrim_shift = SUBCMDSHIFT` strips the
type byte before the match; `discrim_mask` defaults to zero
(i.e. `~0UL`, all bits after the shift), which suffices because the
kernel-side subcmd values are disjoint scalars.

**GET path exclusion.** `Q_GETQUOTA` / `Q_GETNEXTQUOTA` (if_dqblk),
`Q_GETINFO` (if_dqinfo), and `Q_XGETQUOTA` / `Q_XGETNEXTQUOTA`
(fs_disk_quota) also use the same struct at the same slot but are
output-only -- registering them would attribute CMP-learned
constants against bytes the kernel wrote. Subcmds outside the SET
pools match no variant and resolve to NULL; the fallback path is
unchanged.

## seccomp / prctl -- cBPF install (sock_fprog)

Two syscall entry points install the same cBPF program shape:

- `seccomp(unsigned int op, unsigned int flags, void *args)`: a3 is
  a `struct sock_fprog` pointer only on `SECCOMP_SET_MODE_FILTER`.
  Other ops point a3 at different shapes (`uint32_t *` for
  `SECCOMP_GET_ACTION_AVAIL`, a `seccomp_notif_sizes`-sized scratch
  buffer for `SECCOMP_GET_NOTIF_SIZES`) or leave it unused
  (`SECCOMP_SET_MODE_STRICT`).

- `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, sock_fprog *, ...)`:
  arg3 points at a `struct sock_fprog` the kernel reads to load the
  classic BPF program (the cBPF arm; `PR_SET_SECCOMP` with arg2 ==
  `SECCOMP_MODE_STRICT` ignores arg3, and other option values do not
  touch a sock_fprog at all -- those dispatches match no variant
  and resolve to NULL). Registered as a two-key row (option at a1
  == `PR_SET_SECCOMP`, mode at a2 == `SECCOMP_MODE_FILTER`).

Both are attribution-only. The bespoke `sanitise_seccomp()` and
`sanitise_prctl()` PR_SET_SECCOMP arm own the live fill via
`bpf_gen_seccomp()`, which builds a Markov-chain cBPF program the
kernel verifier will load; an `FT_RAW` splat across `sock_filter[]`
insn words could not. `argtype` for the args slot is `ARG_ADDRESS` /
`ARG_UNDEFINED` respectively, not `ARG_STRUCT_PTR_*`, so the
schema-aware fill path never overwrites `rec->a3` -- the bespoke
fill stays the sole writer.

`struct_field_for_cmp()` steers CMP-learned constants at the named
`len` / `filter` slots (and at the cataloged `sock_filter`
elem_struct's `code` / `jt` / `jf` / `k` slots).

**setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, ...)** is the
`SO_ATTACH_FILTER` arm of the (level, optname) two-key family the
proof batch below exercises. It stays bespoke because the BPF arm
REPLACES the optval allocation wholesale rather than fills it (see
`socket_setsockopt()` `SO_ATTACH_FILTER` branch), so a schema-fill
row would race the `bpf_gen_filter()` replacement.

## setsockopt / getsockopt optval -- two-key (level, optname) rows

`setsockopt(fd, level, optname, optval, optlen)` optval -- a4.

Proof batch for the two-key discriminator extension: (level,
optname) shapes already owned by bespoke `build_*()` functions in
`syscalls/setsockopt.c`, now resolved through
`struct_arg_lookup_two_key()` from `apply_sockopt_entry()`.
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

`getsockopt(fd, level, optname, optval, optlen)` optval -- a4.

Mirrors the setsockopt two-key proof batch for the (level, optname)
pairs the kernel also implements on the getsockopt side. The shape
at optval is symmetric with setsockopt for these options
(`struct linger` for `SO_LINGER`, `struct timeval` for `SO_RCVTIMEO`
/ `SO_SNDTIMEO`), so the same `struct_desc` slots the setsockopt
rows point at describe the bytes the kernel writes back through
optval.

`sanitise_getsockopt()` picks (level, optname) via
`do_setsockopt()` and then allocates a page_size valresult buffer
at a4 -- `argtype[3]` is `ARG_ADDRESS`, not `ARG_STRUCT_PTR_*`, so
the schema-aware fill never resolves these rows. Attribution-only
registration lets `struct_field_for_cmp()` steer KCOV-CMP-learned
constants at the named `l_onoff` / `l_linger` / `tv_sec` /
`tv_usec` fields the kernel wrote rather than at coincidentally-
same-width slots.

Set-only optnames from the setsockopt batch (`IP_ADD_MEMBERSHIP`,
`MCAST_*`, `SCTP_AUTH_CHUNK`, `SCTP_AUTH_*_KEY`,
`SCTP_ADD_STREAMS`, `SCTP_SET_PEER_PRIMARY_ADDR`, `SCTP_EVENT`,
`TCP_REPAIR_OPTIONS`, etc.) are deliberately not mirrored: the
kernel does not return their payload struct on the get path, and a
row there would attribute learned constants against bytes never
written by getsockopt.
