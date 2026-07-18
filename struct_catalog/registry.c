/*
 * Struct-catalog registration + (nr, arg) lookup.
 *
 * Carved out of struct_catalog/catalog.c: this TU owns the mapping
 * from a fuzzed syscall dispatch to the struct_desc that describes
 * the argument's payload, plus the fast nr-indexed lookup built at
 * init time.
 *
 * The slot_binding pool + desc_by_nr_64/32[] sizing bounds
 * (SLOT_POOL_MAX, DISCRIM_VARIANTS_PER_SLOT_MAX) BUG on overflow
 * rather than silently drop mappings.
 *
 * Three public resolvers:
 *   - struct_arg_lookup: rec-driven (nr, arg) with discriminator match.
 *   - struct_arg_lookup_two_key: explicit (name, arg, k1, k2).
 *   - struct_arg_lookup_by_name: discriminator-blind default.
 */

#include <stddef.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sched.h>
#include <utime.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/netlink.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/tipc.h>
#include <linux/capability.h>
#include <linux/netfilter.h>
#include <linux/futex.h>
#include <linux/rseq.h>
#include <linux/sched.h>
#include <linux/sched/types.h>
#include <linux/io_uring.h>
#include <linux/kexec.h>
#include <linux/landlock.h>
#include <linux/mman.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include <linux/quota.h>
#include <linux/dqblk_xfs.h>
#include <mqueue.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>

#include "config.h"
/*
 * linux/if_pppox.h pulls in linux/l2tp.h, whose enum declares
 * L2TP_ATTR_IP6_SADDR / RX_COOKIE_DISCARDS / ... as identifiers.
 * include/kernel headers define those same names as fallback numeric macros for
 * older kernel-headers packages, so the include must precede the kernel fallback header;
 * otherwise the macro expansion turns the enum members into integer
 * literals and -Werror trips.
 */
#ifdef USE_PPPOX
#include <linux/if_pppox.h>
#endif
#ifdef USE_BPF
#include <linux/bpf.h>
#endif
#ifdef USE_VSOCK
#include <linux/vm_sockets.h>
#endif
#ifdef USE_CAN
#include <linux/can.h>
#endif
#ifdef USE_RXRPC
#include <linux/rxrpc.h>
#endif
#ifdef USE_X25
#include <linux/x25.h>
#endif
#ifdef USE_PHONET
#include <linux/phonet.h>
#endif
#ifdef USE_ATALK
#include <linux/atalk.h>
#endif
#ifdef USE_ATM
#include <linux/atm.h>
#endif
#ifdef USE_LLC
#include <linux/llc.h>
#endif
#ifdef USE_MCTP
#include <linux/mctp.h>
#endif
#ifdef USE_IF_ALG
#include <linux/if_alg.h>
#endif
#ifdef USE_XDP
#include <linux/if_xdp.h>
/*
 * XDP_USE_NEED_WAKEUP landed in 5.4 (commit 77cd0d7b3f25); older
 * toolchain headers won't carry it even when the rest of the
 * sockaddr_xdp definitions are present.  Fall back to the upstream
 * bit value so the FT_FLAGS mask stays the same on either side.
 */
#ifndef XDP_USE_NEED_WAKEUP
#define XDP_USE_NEED_WAKEUP	(1 << 3)
#endif
#endif
#ifdef USE_XATTR_ARGS
#include <linux/xattr.h>
#endif
#ifdef USE_SCTP
#include <linux/sctp.h>
#endif
#ifdef USE_TCP_REPAIR_OPT
#include <linux/tcp.h>
#endif

#include "argtype-ops.h"
#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"
#ifdef X86
#include <asm/ldt.h>		/* struct user_desc -- modify_ldt arg2 */
#endif
#include "debug.h"
#include "perf.h"		/* random_tracepoint_config -- FT_PICKER for TRACEPOINT.config */
#include "perf_event.h"
#include "random.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"


#include "kernel/fcntl.h"
#include "kernel/l2tp.h"
#include "kernel/seccomp.h"
#include "kernel/in.h"
#include "kernel/sctp.h"
/* ------------------------------------------------------------------ */
/* Discriminator value lists                                            */
/* ------------------------------------------------------------------ */

/*
 * fcntl arg3 cmd discriminator pools.  Sibling arg a2 (cmd) selects
 * which struct backs the a3 pointer; the discriminator-aware lookup
 * resolves these lists against rec->a2 to pick the right descriptor.
 *
 * fcntl_flock_cmds: every cmd where the kernel reads a struct flock
 * at a3 -- POSIX (F_GETLK / F_SETLK / F_SETLKW), OFD (F_OFD_*) and
 * F_CANCELLK.  The LK64 variants are folded in via the
 * F_GETLK64 != F_GETLK preprocessor gate so 64-bit-clean toolchains
 * (where the LK64 cmd values collapse onto their non-LK64 siblings)
 * don't waste a duplicate-match slot.
 *
 * fcntl_f_owner_ex_cmds: the two cmds where a3 is a struct
 * f_owner_ex pointer.
 */
static const unsigned long fcntl_flock_cmds[] = {
	F_GETLK, F_SETLK, F_SETLKW,
	F_OFD_GETLK, F_OFD_SETLK, F_OFD_SETLKW,
	F_CANCELLK,
#if F_GETLK64 != F_GETLK
	F_GETLK64, F_SETLK64, F_SETLKW64,
#endif
};

static const unsigned long fcntl_f_owner_ex_cmds[] = {
	F_GETOWN_EX, F_SETOWN_EX,
};

/*
 * landlock_add_rule arg3 rule_type discriminator pools.  Sibling arg
 * a2 (rule_type) selects which struct backs the a3 pointer; the
 * discriminator-aware lookup resolves these lists against rec->a2 to
 * pick the right descriptor.
 *
 * landlock_add_rule_path_beneath_rule_types: just
 * LANDLOCK_RULE_PATH_BENEATH (a3 is a struct landlock_path_beneath_attr).
 *
 * landlock_add_rule_net_port_rule_types: just LANDLOCK_RULE_NET_PORT
 * (a3 is a struct landlock_net_port_attr).
 *
 * One-element pools so the registration shape matches the fcntl
 * cmd-discriminator above; new landlock rule_types will land here as
 * additional entries with their own descriptor + pool.
 */
static const unsigned long landlock_add_rule_path_beneath_rule_types[] = {
	LANDLOCK_RULE_PATH_BENEATH,
};

static const unsigned long landlock_add_rule_net_port_rule_types[] = {
	LANDLOCK_RULE_NET_PORT,
};

/*
 * quotactl / quotactl_fd cmd discriminator pools.  Both syscalls pack
 * the cmd into a single arg as QCMD(subcmd, type) (subcmd in the high
 * bits, USRQUOTA / GRPQUOTA / PRJQUOTA / ... type in the low byte),
 * so the discriminator-aware lookup unpacks via the (shift, mask)
 * extension: discrim_shift = SUBCMDSHIFT strips the type byte and
 * leaves the raw subcmd that the kernel switches on, which is what
 * Q_SETQUOTA / Q_SETINFO actually equal.
 *
 * quotactl_if_dqblk_subcmds: just Q_SETQUOTA (a4 / a3 is a struct
 * if_dqblk pointer the kernel reads on dispatch).  Q_GETQUOTA /
 * Q_GETNEXTQUOTA also use if_dqblk at the same slot but they're
 * output-only -- registering them would attribute CMP-learned
 * constants against bytes the kernel wrote rather than bytes we
 * stamped.
 */
static const unsigned long quotactl_if_dqblk_subcmds[] = {
	Q_SETQUOTA,
};

/*
 * quotactl_if_dqinfo_subcmds: just Q_SETINFO (a4 / a3 is a struct
 * if_dqinfo pointer the kernel reads on dispatch).  Q_GETINFO also
 * uses if_dqinfo at the same slot but is output-only -- registering
 * it would attribute CMP-learned constants against bytes the kernel
 * wrote rather than bytes we stamped.
 */
static const unsigned long quotactl_if_dqinfo_subcmds[] = {
	Q_SETINFO,
};

/*
 * quotactl_fs_disk_quota_subcmds: just Q_XSETQLIM (a4 is a struct
 * fs_disk_quota pointer the kernel reads on dispatch under the XFS
 * quota set-limit command).  Q_XGETQUOTA / Q_XGETNEXTQUOTA also use
 * fs_disk_quota at the same slot but they're output-only -- registering
 * them would attribute CMP-learned constants against bytes the kernel
 * wrote rather than bytes we stamped.
 */
static const unsigned long quotactl_fs_disk_quota_subcmds[] = {
	Q_XSETQLIM,
};

/*
 * seccomp(op, flags, args) op-discriminator pool.  Sibling arg a1 (op)
 * selects which struct backs the a3 pointer; the discriminator-aware
 * lookup resolves this list against rec->a1 to pick the right descriptor.
 *
 * seccomp_set_mode_filter_ops: just SECCOMP_SET_MODE_FILTER (a3 is a
 * struct sock_fprog pointer the kernel reads for cBPF install).  The
 * other three ops (SECCOMP_SET_MODE_STRICT, SECCOMP_GET_ACTION_AVAIL,
 * SECCOMP_GET_NOTIF_SIZES) point a3 at a different shape (or NULL) and
 * are not registered -- attributing CMP-learned constants against
 * sock_fprog fields on those dispatches would steer them at bytes the
 * kernel never reads as filter program.
 */
static const unsigned long seccomp_set_mode_filter_ops[] = {
	SECCOMP_SET_MODE_FILTER,
};

/*
 * setsockopt (level, optname) discriminator vocab -- proof batch for
 * the two-key extension.  Each list enumerates the optnames inside a
 * single level that share an optval struct shape, so one
 * syscall_struct_args[] row covers every (level, this-vocab) tuple
 * without cloning the entry.  Same pattern as cgroup link_create's
 * 20-attach-type discrim_values list.
 *
 * Symbol comes from setsockopt.c's sockopt_table[] vocabulary; the
 * lookup matches on the raw integer value, not the symbolic name.
 */
static const unsigned long setsockopt_timeval_optnames[] = {
	SO_RCVTIMEO,
	SO_SNDTIMEO,
};

static const unsigned long setsockopt_ip_mreqn_optnames[] = {
	IP_ADD_MEMBERSHIP,
	IP_DROP_MEMBERSHIP,
	IP_MULTICAST_IF,
};

static const unsigned long setsockopt_ip_mreq_source_optnames[] = {
	IP_ADD_SOURCE_MEMBERSHIP,
	IP_DROP_SOURCE_MEMBERSHIP,
	IP_BLOCK_SOURCE,
	IP_UNBLOCK_SOURCE,
};

static const unsigned long setsockopt_ipv6_mreq_optnames[] = {
	IPV6_ADD_MEMBERSHIP,
	IPV6_DROP_MEMBERSHIP,
};

static const unsigned long setsockopt_packet_mreq_optnames[] = {
	PACKET_ADD_MEMBERSHIP,
	PACKET_DROP_MEMBERSHIP,
};

/*
 * Protocol-independent MCAST_* setsockopt family: the same optname
 * payload is accepted under both IPPROTO_IP and IPPROTO_IPV6.  The
 * two-key map entry uses both lists so one row covers the full
 * (level, optname) cross product without cloning the entry.
 */
static const unsigned long setsockopt_mcast_levels[] = {
	IPPROTO_IP,
	IPPROTO_IPV6,
};

static const unsigned long setsockopt_mcast_join_optnames[] = {
	MCAST_JOIN_GROUP,
	MCAST_LEAVE_GROUP,
};

/*
 * Source-filter optnames in the same protocol-independent MCAST_*
 * family, sharing setsockopt_mcast_levels[] with the join/leave row.
 * Sibling list for the group_source_req payload shape.
 */
static const unsigned long setsockopt_mcast_source_optnames[] = {
	MCAST_JOIN_SOURCE_GROUP,
	MCAST_LEAVE_SOURCE_GROUP,
	MCAST_BLOCK_SOURCE,
	MCAST_UNBLOCK_SOURCE,
};

#ifdef USE_SCTP
static const unsigned long setsockopt_sctp_assoc_value_optnames[] = {
	SCTP_CONTEXT,
	SCTP_MAXSEG,
	SCTP_MAX_BURST,
	SCTP_STREAM_SCHEDULER,
};

static const unsigned long setsockopt_sctp_authkeyid_optnames[] = {
	SCTP_AUTH_ACTIVE_KEY,
	SCTP_AUTH_DELETE_KEY,
	SCTP_AUTH_DEACTIVATE_KEY,
};

static const unsigned long setsockopt_sctp_prim_optnames[] = {
	SCTP_PRIMARY_ADDR,
	SCTP_SET_PEER_PRIMARY_ADDR,
};
#endif

/*
 * futex_timeout_ops: the op subset where a4 (utime) is a struct
 * timespec pointer rather than the val2 integer overload.  Mirrors
 * the kernel's futex_cmd_has_timeout() switch (kernel/futex/syscalls.c).
 * Matched against rec->a2 masked by FUTEX_CMD_MASK so the PRIVATE /
 * CLOCK_REALTIME / ROBUST flag bits don't perturb the dispatch.
 */
static const unsigned long futex_timeout_ops[] = {
	FUTEX_WAIT,
	FUTEX_LOCK_PI,
	FUTEX_WAIT_BITSET,
	FUTEX_WAIT_REQUEUE_PI,
	FUTEX_LOCK_PI2,
};

/* ------------------------------------------------------------------ */
/* Syscall -> struct arg mapping                                        */
/* ------------------------------------------------------------------ */

/*
 * Maps (syscall name, 1-based arg index) to the struct type passed at
 * that argument.  Only covers args that are struct pointers filled by
 * a custom sanitise callback.  Terminated by .syscall_name == NULL.
 */
static const struct syscall_struct_arg syscall_struct_args_all[] = {
	/* clone3(struct clone_args *, size_t) */
	{ "clone3",		1, &struct_catalog[SC_CLONE_ARGS] },
	/* setrlimit(unsigned int, struct rlimit *) */
	{ "setrlimit",		2, &struct_catalog[SC_RLIMIT] },
	/* getrlimit(unsigned int, struct rlimit *) */
	{ "getrlimit",		2, &struct_catalog[SC_RLIMIT] },
	/* prlimit64(pid_t, unsigned int, struct rlimit *, struct rlimit *) */
	{ "prlimit64",		3, &struct_catalog[SC_RLIMIT] },
	{ "prlimit64",		4, &struct_catalog[SC_RLIMIT] },
	/* epoll_ctl(int, int, int, struct epoll_event *) */
	{ "epoll_ctl",		4, &struct_catalog[SC_EPOLL_EVENT] },
	/* perf_event_open(struct perf_event_attr *, pid_t, int, int, ulong) */
	{ "perf_event_open",	1, &struct_catalog[SC_PERF_EVENT_ATTR] },
	/* rt_sigaction(int, const struct sigaction *, struct sigaction *, size_t) */
	{ "rt_sigaction",	2, &struct_catalog[SC_SIGACTION] },
	{ "rt_sigaction",	3, &struct_catalog[SC_SIGACTION] },
	/* sigaction(int, const struct old_sigaction *, struct old_sigaction *) */
	{ "sigaction",		2, &struct_catalog[SC_SIGACTION] },
	{ "sigaction",		3, &struct_catalog[SC_SIGACTION] },
	/* sendmsg(int, const struct msghdr *, int) */
	{ "sendmsg",		2, &struct_catalog[SC_MSGHDR] },
	/* recvmsg(int, struct msghdr *, int) */
	{ "recvmsg",		2, &struct_catalog[SC_MSGHDR] },
	/* sendmmsg(int, struct mmsghdr *, unsigned int, unsigned int) */
	{ "sendmmsg",		2, &struct_catalog[SC_MMSGHDR] },
	/* recvmmsg(int, struct mmsghdr *, unsigned int, unsigned int, struct timespec *) */
	{ "recvmmsg",		2, &struct_catalog[SC_MMSGHDR] },
	/* bind(int, struct sockaddr *, socklen_t) */
	{ "bind",		2, &struct_catalog[SC_SOCKADDR_STORAGE] },
	/* connect(int, struct sockaddr *, socklen_t) */
	{ "connect",		2, &struct_catalog[SC_SOCKADDR_STORAGE] },
	/* sendto(int, const void *, size_t, int, struct sockaddr *, socklen_t) */
	{ "sendto",		5, &struct_catalog[SC_SOCKADDR_STORAGE] },
	/*
	 * accept(int, struct sockaddr *upeer_sockaddr, int *upeer_addrlen)
	 * accept4(int, struct sockaddr *upeer_sockaddr, int *upeer_addrlen,
	 *         int flags)
	 * a2 is the peer-address OUTPUT slot: sanitise_accept_addrlen()
	 * publishes a writable-region sockaddr_storage (or a NULL/NULL pair)
	 * and the kernel writes the peer address back via move_addr_to_user().
	 * argtype[1] is ARG_SOCKADDR, not ARG_STRUCT_PTR_*, so the schema-aware
	 * fill never resolves these rows -- attribution-only registration lets
	 * struct_field_for_cmp() steer KCOV-CMP-learned constants at the named
	 * ss_family / port / addr fields of sockaddr_storage_variants[] rather
	 * than at a coincidentally-same-width slot on the accept path.  Mirrors
	 * bind / connect / sendto above; same descriptor covers both accept
	 * arms since the sockaddr shape is family-tagged by ss_family and does
	 * not depend on the extra accept4 flags arg.
	 */
	{ "accept",		2, &struct_catalog[SC_SOCKADDR_STORAGE] },
	{ "accept4",		2, &struct_catalog[SC_SOCKADDR_STORAGE] },
	/* landlock_create_ruleset(const struct landlock_ruleset_attr *, size_t, u32) */
	{ "landlock_create_ruleset",	1, &struct_catalog[SC_LANDLOCK_RULESET_ATTR] },
	/* statmount(const struct mnt_id_req *, struct statmount *, size_t, u32) */
	{ "statmount",		1, &struct_catalog[SC_MNT_ID_REQ] },
	/* listmount(const struct mnt_id_req *, u64 *, size_t, u32) */
	{ "listmount",		1, &struct_catalog[SC_MNT_ID_REQ] },
	/* capset(cap_user_header_t hdr, const cap_user_data_t data) */
	{ "capset",		1, &struct_catalog[SC_USER_CAP_HEADER] },
	{ "capset",		2, &struct_catalog[SC_USER_CAP_DATA] },
	/* capget(cap_user_header_t hdr, cap_user_data_t data) */
	{ "capget",		1, &struct_catalog[SC_USER_CAP_HEADER] },
	/* futex_waitv(struct futex_waitv *waiters, unsigned int nr, unsigned int flags, struct timespec *timo, clockid_t clockid) */
	{ "futex_waitv",	1, &struct_catalog[SC_FUTEX_WAITV] },
	/* futex_requeue(struct futex_waitv *waiters, unsigned int flags, int nr_wake, int nr_requeue) */
	{ "futex_requeue",	1, &struct_catalog[SC_FUTEX_WAITV] },
	/* sigaltstack(const stack_t *ss, stack_t *old_ss) */
	{ "sigaltstack",	1, &struct_catalog[SC_STACK_T] },
	/*
	 * rt_sigqueueinfo(pid_t pid, int sig, siginfo_t __user *uinfo)
	 * rt_tgsigqueueinfo(pid_t tgid, pid_t pid, int sig,
	 *                   siginfo_t __user *uinfo)
	 *
	 * Attribution-only registration -- argtype[*] for the siginfo
	 * slot is not ARG_STRUCT_PTR_*, so the schema-aware fill never
	 * runs against rec->a3 (rt_sigqueueinfo) / rec->a4
	 * (rt_tgsigqueueinfo).  The bespoke sanitisers keep owning the
	 * live fill (fill_siginfo_by_class on rt_sigqueueinfo, a fixed
	 * SI_QUEUE shape on rt_tgsigqueueinfo), and this entry lets
	 * struct_field_for_cmp() steer CMP-learned constants at the
	 * named si_signo / si_code / si_pid / si_uid / si_value slots
	 * rather than at coincidentally-same-width slots.  Variants in
	 * the descriptor scope the candidate field pool to the live
	 * _kill / _rt arm whenever struct_desc_resolve_variant is
	 * called with the post-fill buf (CMP-time callers that pass
	 * buf == NULL fall through to the shared head).
	 *
	 * Not mapped here on purpose: waitid's a3 is a kernel-written
	 * OUTPUT (mirrors the gettimeofday / get_robust_list /
	 * cachestat-output skips above) and registering it would
	 * attribute CMP-learned constants against bytes the kernel
	 * wrote rather than bytes we stamped.  pidfd_send_signal's a3
	 * IS mapped (attribution-only, same as rt_sigqueueinfo /
	 * rt_tgsigqueueinfo — the bespoke sanitisers keep owning the
	 * live fill).
	 */
	{ "rt_sigqueueinfo",	3, &struct_catalog[SC_SIGINFO_T] },
	{ "rt_tgsigqueueinfo",	4, &struct_catalog[SC_SIGINFO_T] },
	{ "pidfd_send_signal",	3, &struct_catalog[SC_SIGINFO_T] },
	/* mq_open(const char *, int, mode_t, struct mq_attr *) */
	{ "mq_open",		4, &struct_catalog[SC_MQ_ATTR] },
	/* mq_getsetattr(mqd_t, const struct mq_attr *, struct mq_attr *) */
	{ "mq_getsetattr",	2, &struct_catalog[SC_MQ_ATTR] },
	{ "mq_getsetattr",	3, &struct_catalog[SC_MQ_ATTR] },
	/* msgctl(int msqid, int cmd, struct msqid_ds *buf) — IPC_SET path */
	{ "msgctl",		3, &struct_catalog[SC_MSQID_DS] },
	/* shmctl(int shmid, int cmd, struct shmid_ds *buf) — IPC_SET path */
	{ "shmctl",		3, &struct_catalog[SC_SHMID_DS] },
#ifdef USE_BPF
	/* bpf(int, union bpf_attr *, unsigned int) */
	{ "bpf",		2, &struct_catalog[SC_BPF_ATTR] },
#endif
	/*
	 * keyctl(int cmd, unsigned long a2, unsigned long a3,
	 *        unsigned long a4, unsigned long a5)
	 * The a2 slot's shape is cmd-selected: DH_COMPUTE points it at a
	 * struct keyctl_dh_params, the four PKEY_{ENCRYPT,DECRYPT,SIGN,
	 * VERIFY} ops at a struct keyctl_pkey_params; the remaining cmds
	 * put a scalar (key_serial_t, mask, or opaque flag) there and
	 * match no variant.  argtype[1] is left at the syscall's default
	 * (ARG_UNDEFINED) and sanitise_keyctl() owns the live fill for
	 * every cmd, so this is an attribution-only row -- the schema-
	 * aware fill path never resolves rec->a2 through the catalog, and
	 * struct_field_for_cmp() gets to name the specific struct field
	 * (keyctl_dh_params.prime, keyctl_pkey_params.in_len, ...) that a
	 * KCOV-CMP-learned constant fell out of.  The variants dispatch
	 * off rec->a1 (discrim_arg_idx=1 on the descriptor itself, same
	 * shape bpf_attr uses for its per-cmd tagged union).
	 */
	{ "keyctl",		2, &struct_catalog[SC_KEYCTL_PAYLOAD] },
	/*
	 * utimensat(int, const char *, struct timespec[2], int)
	 * utimensat's `utimes` arg is a 2-element timespec array -- the
	 * mapping table has no array semantics, so the entry below names
	 * the single-struct desc and the existing sanitise_utimensat
	 * callback continues to own the 2-element layout.
	 */
	{ "utimensat",		3, &struct_catalog[SC_TIMESPEC] },
	/*
	 * ppoll(struct pollfd *, nfds_t, struct timespec *tsp, const sigset_t *, size_t)
	 * a3 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_ppoll / ppoll_post_state in syscalls/poll.c continues to
	 * own the live fill; this row only lets schema-aware CMP attribution
	 * name the tv_sec / tv_nsec fields.  ppoll's a1 (pollfd array) is
	 * mapped to SC_POLLFD above and is unaffected.
	 */
	{ "ppoll",		3, &struct_catalog[SC_TIMESPEC] },
	/*
	 * rt_sigtimedwait(const sigset_t *uthese, siginfo_t *uinfo,
	 *                 const struct timespec *uts, size_t sigsetsize)
	 * a3 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitiser (build_timeout stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.  a1 (uthese,
	 * sigset_t) and a2 (uinfo, siginfo_t) are not timespecs and are
	 * intentionally unregistered here.
	 */
	{ "rt_sigtimedwait",	3, &struct_catalog[SC_TIMESPEC] },
	/*
	 * pselect6(int n, fd_set *inp, fd_set *outp, fd_set *exp,
	 *          struct timespec *tsp, void *sig)
	 * a5 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_pselect6 (allocs the timespec via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.  a6 (sig, a
	 * packed { sigset_t *, size_t } pointer) is not a timespec and is
	 * intentionally unregistered here.
	 */
	{ "pselect6",		5, &struct_catalog[SC_TIMESPEC] },
	/*
	 * semtimedop(int semid, struct sembuf *sops, unsigned nsops,
	 *            const struct timespec *timeout)
	 * a4 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_semtimedop (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.  a2 (sops, the
	 * sembuf array) is mapped to SC_SEMBUF below and is unaffected.
	 */
	{ "semtimedop",		4, &struct_catalog[SC_TIMESPEC] },
	/*
	 * mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len,
	 *              unsigned int msg_prio, const struct timespec *abs_timeout)
	 * a5 is the INPUT abs_timeout timespec.  Attribution-only: the bespoke
	 * sanitise_mq_timedsend (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "mq_timedsend",	5, &struct_catalog[SC_TIMESPEC] },
	/*
	 * mq_timedreceive(mqd_t mqdes, char *msg_ptr, size_t msg_len,
	 *                 unsigned int *msg_prio, const struct timespec *abs_timeout)
	 * a5 is the INPUT abs_timeout timespec.  Attribution-only: the bespoke
	 * sanitise_mq_timedreceive (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "mq_timedreceive",	5, &struct_catalog[SC_TIMESPEC] },
	/*
	 * io_getevents(aio_context_t ctx_id, long min_nr, long nr,
	 *              struct io_event *events, struct timespec *timeout)
	 * a5 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_io_getevents (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "io_getevents",	5, &struct_catalog[SC_TIMESPEC] },
	/*
	 * futex_wait(void *uaddr, unsigned long val, unsigned long mask,
	 *            unsigned int flags, struct timespec *timeout,
	 *            clockid_t clockid)
	 * a5 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_futex_wait (stamps the slot via get_writable_struct)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "futex_wait",		5, &struct_catalog[SC_TIMESPEC] },
	/*
	 * futex(u32 *uaddr, int op, u32 val, struct timespec *utime,
	 *       u32 *uaddr2, u32 val3)
	 * a4 (utime) is a struct timespec pointer only for the WAIT-family
	 * and LOCK_PI / LOCK_PI2 ops (kernel: futex_cmd_has_timeout); for
	 * every other cmd it carries the val2 integer overload instead.
	 * Discriminate on a2 masked by FUTEX_CMD_MASK so the row matches
	 * only the timeout-taking ops, mirroring the kernel's own
	 * `cmd = op & FUTEX_CMD_MASK` dispatch.  Attribution-only: the
	 * bespoke sanitise_futex still owns the a4 fill via &utime_clamp;
	 * this row only lets schema-aware CMP attribution name the
	 * tv_sec / tv_nsec fields for the matching ops.
	 */
	{
		"futex", 4, &struct_catalog[SC_TIMESPEC],
		.discrim_arg_idx	= 2,
		.discrim_mask		= FUTEX_CMD_MASK,
		.discrim_values		= futex_timeout_ops,
		.num_discrim_values	= ARRAY_SIZE(futex_timeout_ops),
	},
	/*
	 * futex_waitv(struct futex_waitv *waiters, unsigned int nr_futexes,
	 *             unsigned int flags, struct timespec *timeout,
	 *             clockid_t clockid)
	 * a4 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_futex_waitv (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.  a1 (waiters)
	 * is mapped to SC_FUTEX_WAITV above and is unaffected.
	 */
	{ "futex_waitv",	4, &struct_catalog[SC_TIMESPEC] },
	/*
	 * epoll_pwait2(int epfd, struct epoll_event *events, int maxevents,
	 *              struct timespec *timeout, const sigset_t *sigmask,
	 *              size_t sigsetsize)
	 * a4 is the INPUT timeout timespec (epoll_pwait2 takes a timespec*
	 * where epoll_pwait took an int ms).  Attribution-only: the bespoke
	 * sanitise_epoll_pwait2 / pick_timespec (stamps the slot via
	 * get_writable_struct) continues to own the live fill; this row only
	 * lets schema-aware CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "epoll_pwait2",	4, &struct_catalog[SC_TIMESPEC] },
	/*
	 * io_pgetevents(aio_context_t ctx_id, long min_nr, long nr,
	 *               struct io_event *events, struct timespec *timeout,
	 *               const struct __aio_sigset *usig)
	 * a5 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_io_pgetevents (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "io_pgetevents",	5, &struct_catalog[SC_TIMESPEC] },
	/*
	 * cachestat(unsigned int fd, struct cachestat_range *cstat_range,
	 *           struct cachestat *cstat, unsigned int flags)
	 * Maps the INPUT cstat_range arg only; cstat is the kernel-written
	 * output and is intentionally not registered.  Attribution-only:
	 * sanitise_cachestat / pick_range continues to own the live fill.
	 */
	{ "cachestat",		2, &struct_catalog[SC_CACHESTAT_RANGE] },
	/*
	 * mount_setattr(int dfd, const char *path, unsigned int flags,
	 *               struct mount_attr *uattr, size_t usize)
	 * open_tree_attr(int dfd, const char *filename, unsigned int flags,
	 *                struct mount_attr *uattr, size_t usize)
	 * Both a4 slots are ARG_STRUCT_PTR_IN, but the bespoke sanitisers
	 * (build_mount_attr / sanitise_mount_setattr) overwrite rec->a4
	 * after the schema-aware fill -- attribution-only registration so
	 * struct_field_for_cmp can steer CMP-learned constants at the
	 * named fields.  The curated bespoke fill stays live.
	 */
	{ "mount_setattr",	4, &struct_catalog[SC_MOUNT_ATTR] },
	{ "open_tree_attr",	4, &struct_catalog[SC_MOUNT_ATTR] },
	/*
	 * sembuf is an array slot on ARG_ADDRESS at a2 of both semop and
	 * semtimedop; the per-element type is named here so future schema
	 * consumers and struct_field_for_cmp can resolve it.  The bespoke
	 * fill_sembuf_array() owns the live (nsops, sem_*) layout.
	 */
	{ "semop",		2, &struct_catalog[SC_SEMBUF] },
	{ "semtimedop",		2, &struct_catalog[SC_SEMBUF] },
	/*
	 * pollfd is an array slot on ARG_ADDRESS at a1 of both poll and
	 * ppoll; the per-element type is named here so future schema
	 * consumers and struct_field_for_cmp can resolve it.  The bespoke
	 * alloc_pollfds() owns the live (nfds, fd, events) layout.
	 */
	{ "poll",		1, &struct_catalog[SC_POLLFD] },
	{ "ppoll",		1, &struct_catalog[SC_POLLFD] },
	/*
	 * openat2(int dfd, const char *filename, struct open_how *how,
	 *         size_t usize)
	 * a3 is ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
	 * sanitise_openat2 / build_csfu_struct path keeps owning the
	 * live (flags, mode, resolve) layout and the usize bucket
	 * distribution.  Attribution-only registration lets
	 * struct_field_for_cmp steer CMP-learned constants at the named
	 * flags / resolve slot.
	 */
	{ "openat2",		3, &struct_catalog[SC_OPEN_HOW] },
	/*
	 * open_by_handle_at(int mountdirfd, struct file_handle *handle, int flags)
	 * a2 (1-indexed) is the file_handle.  Schema-fill produces a coherent
	 * (handle_bytes, handle_type) pair and exercises the kernel's
	 * handle_bytes bounds check when fuzzed past the sized buffer.
	 */
	{ "open_by_handle_at",	2, &struct_catalog[SC_FILE_HANDLE] },
	/*
	 * mq_notify(mqd_t, const struct sigevent *)
	 * a2 carries the same struct sigevent that timer_create's a2
	 * carries; the bespoke sanitise_mq_notify() keeps owning the
	 * live fill (NULL-deregister half the time, otherwise SIGEV_NONE
	 * / SIGEV_SIGNAL / SIGEV_THREAD with sigev_signo populated).
	 * Attribution-only registration lets struct_field_for_cmp steer
	 * CMP-learned constants at sigev_notify / sigev_signo rather
	 * than at a coincidentally-same-width slot.
	 */
	{ "mq_notify",		2, &struct_catalog[SC_SIGEVENT] },
	/*
	 * set_robust_list(struct robust_list_head __user *head, size_t len)
	 * a1 is ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
	 * sanitise_set_robust_list() keeps owning the live (list.next,
	 * futex_offset, list_op_pending) layout.  Attribution-only
	 * registration lets struct_field_for_cmp steer CMP-learned constants
	 * at the named fields.  get_robust_list's robust_list_head is an
	 * output (a2 is a double pointer the kernel writes), so only
	 * set_robust_list's a1 is mapped.
	 */
	{ "set_robust_list",	1, &struct_catalog[SC_ROBUST_LIST_HEAD] },
	/*
	 * rseq(struct rseq __user *rseq, u32 rseq_len, int flags, u32 sig)
	 * a1 is the INPUT struct rseq pointer; the bespoke sanitise_rseq()
	 * keeps owning the live fill (32-byte-aligned allocation, zero-
	 * init, a2 length-bucket distribution, a4 signature pin).
	 * Attribution-only registration lets struct_field_for_cmp steer
	 * CMP-learned constants at the named fields rather than at a
	 * coincidentally-same-width slot.
	 */
	{ "rseq",		1, &struct_catalog[SC_RSEQ] },
	/*
	 * utime(const char *filename, const struct utimbuf __user *times)
	 * a2 is the INPUT struct utimbuf pointer.  utime has no bespoke
	 * .sanitise -- the slot previously fell through ARG_ADDRESS with no
	 * schema-aware fill.  argtype[1] is now ARG_STRUCT_PTR_IN so the
	 * times buffer lands on a dedicated sized buffer; the catalog entry
	 * also lets struct_field_for_cmp steer CMP-learned constants at the
	 * named actime / modtime slots rather than at a coincidentally-
	 * same-width slot.
	 */
	{ "utime",		2, &struct_catalog[SC_UTIMBUF] },
	/*
	 * fcntl(int fd, int cmd, ... arg): a3 is cmd-discriminated between
	 * struct flock (fcntl_flock_cmds pool) and struct f_owner_ex
	 * (fcntl_f_owner_ex_cmds pool).  Both attribution-only; bespoke
	 * sanitise_fcntl() owns the live fill.  Unlisted cmds resolve NULL.
	 * See Documentation/struct_catalog.md.
	 */
	{
		"fcntl", 3, &struct_catalog[SC_FLOCK],
		.discrim_arg_idx	= 2,
		.discrim_values		= fcntl_flock_cmds,
		.num_discrim_values	= ARRAY_SIZE(fcntl_flock_cmds),
	},
	{
		"fcntl", 3, &struct_catalog[SC_F_OWNER_EX],
		.discrim_arg_idx	= 2,
		.discrim_values		= fcntl_f_owner_ex_cmds,
		.num_discrim_values	= ARRAY_SIZE(fcntl_f_owner_ex_cmds),
	},
	/*
	 * timeval slots on select a5 (INOUT remaining-time), futimesat a3
	 * (INPUT timeval[2], first-elem only), utimes a2 (INPUT
	 * timeval[2], first-elem only).  All attribution-only; bespoke
	 * sanitisers own the live fill.  gettimeofday's a1 not mapped:
	 * kernel-written OUTPUT with no input to attribute.  See
	 * Documentation/struct_catalog.md.
	 */
	{ "select",		5, &struct_catalog[SC_TIMEVAL] },
	{ "futimesat",		3, &struct_catalog[SC_TIMEVAL] },
	{ "utimes",		2, &struct_catalog[SC_TIMEVAL] },
	/*
	 * listns(const struct ns_id_req __user *req, u64 __user *ns_ids,
	 *        size_t nr_ns_ids, unsigned int flags)
	 * a1 is the INPUT struct ns_id_req pointer.  sanitise_listns()
	 * keeps owning the live fill via build_csfu_struct(&desc_listns)
	 * -- the csfu path stamps the versioned size word and the
	 * subsequent ns_type / ns_id / user_ns_id pickers populate the
	 * remaining slots.  Attribution-only registration lets
	 * struct_field_for_cmp steer CMP-learned constants at the named
	 * size / ns_type / ns_id / user_ns_id slots, with ns_type masked
	 * to the eight defined CLONE_NEW* selector bits.
	 */
	{ "listns",		1, &struct_catalog[SC_NS_ID_REQ] },
#ifdef USE_XATTR_ARGS
	/*
	 * setxattrat(int dfd, const char __user *pathname,
	 *            unsigned int at_flags, const char __user *name,
	 *            const struct xattr_args __user *uargs, size_t usize)
	 * getxattrat(int dfd, const char __user *pathname,
	 *            unsigned int at_flags, const char __user *name,
	 *            struct xattr_args __user *uargs, size_t usize)
	 * a5 is the INPUT struct xattr_args pointer in both cases (the
	 * kernel reads value / size / flags before any sub-buffer access
	 * even for getxattrat).  sanitise_{set,get}xattrat() keep owning
	 * the live fill via build_csfu_struct(&desc_{set,get}xattrat) and
	 * the in-line value/size/flags picker; attribution-only
	 * registration lets struct_field_for_cmp steer CMP-learned
	 * constants at the named value / size / flags slots, with flags
	 * masked to XATTR_CREATE | XATTR_REPLACE.
	 */
	{ "setxattrat",		5, &struct_catalog[SC_XATTR_ARGS] },
	{ "getxattrat",		5, &struct_catalog[SC_XATTR_ARGS] },
#endif
	/*
	 * file_setattr(int dfd, const char __user *filename,
	 *              struct file_attr __user *ufattr, size_t usize,
	 *              unsigned int at_flags)
	 * a3 is the INPUT struct file_attr pointer.  The bespoke
	 * sanitise_file_setattr() keeps owning the live fill via
	 * build_csfu_struct(&desc_file_setattr) and the curated
	 * FS_XFLAG_* pool picker; this registration is attribution-only
	 * so struct_field_for_cmp can steer CMP-learned constants at
	 * the named fa_xflags / fa_extsize / fa_nextents / fa_projid /
	 * fa_cowextsize slots rather than at a coincidentally-same-
	 * width slot.
	 *
	 * Not mapped here on purpose: file_getattr's a2 buffer is a
	 * kernel-written OUTPUT and has no input fill to attribute
	 * against.
	 */
	{ "file_setattr",	3, &struct_catalog[SC_FILE_ATTR] },
	/*
	 * landlock_add_rule a3: rule_type-discriminated between
	 * struct landlock_path_beneath_attr (LANDLOCK_RULE_PATH_BENEATH)
	 * and struct landlock_net_port_attr (LANDLOCK_RULE_NET_PORT).
	 * Both attribution-only; bespoke sanitise_landlock_add_rule()
	 * owns the live fill.  Unlisted rule_types resolve NULL.
	 * See Documentation/struct_catalog.md.
	 */
	{
		"landlock_add_rule", 3,
		&struct_catalog[SC_LANDLOCK_PATH_BENEATH_ATTR],
		.discrim_arg_idx	= 2,
		.discrim_values		= landlock_add_rule_path_beneath_rule_types,
		.num_discrim_values	= ARRAY_SIZE(landlock_add_rule_path_beneath_rule_types),
	},
	{
		"landlock_add_rule", 3,
		&struct_catalog[SC_LANDLOCK_NET_PORT_ATTR],
		.discrim_arg_idx	= 2,
		.discrim_values		= landlock_add_rule_net_port_rule_types,
		.num_discrim_values	= ARRAY_SIZE(landlock_add_rule_net_port_rule_types),
	},
	/*
	 * quotactl / quotactl_fd a4 (addr): struct if_dqblk under
	 * Q_SETQUOTA.  Packed cmd: rec->a1 (quotactl) / rec->a2
	 * (quotactl_fd) is QCMD(subcmd, type); discrim_shift =
	 * SUBCMDSHIFT strips the type byte before the match.
	 * Attribution-only; bespoke sanitisers own the live fill.
	 * Q_GET* not mapped (output-only).  Unlisted subcmds resolve
	 * NULL.  See Documentation/struct_catalog.md.
	 */
	{
		"quotactl", 4, &struct_catalog[SC_IF_DQBLK],
		.discrim_arg_idx	= 1,
		.discrim_values		= quotactl_if_dqblk_subcmds,
		.num_discrim_values	= ARRAY_SIZE(quotactl_if_dqblk_subcmds),
		.discrim_shift		= SUBCMDSHIFT,
	},
	{
		"quotactl_fd", 4, &struct_catalog[SC_IF_DQBLK],
		.discrim_arg_idx	= 2,
		.discrim_values		= quotactl_if_dqblk_subcmds,
		.num_discrim_values	= ARRAY_SIZE(quotactl_if_dqblk_subcmds),
		.discrim_shift		= SUBCMDSHIFT,
	},
	/*
	 * if_dqinfo sibling of the if_dqblk registration above: the same
	 * addr slot (quotactl a4 / quotactl_fd a4) is a struct if_dqinfo
	 * pointer under Q_SETINFO.  Same packed-discriminator extraction
	 * (discrim_shift = SUBCMDSHIFT) and same attribution-only shape
	 * as the if_dqblk pair -- the bespoke sanitisers own the live
	 * dqi_bgrace / dqi_igrace fill; this entry only steers
	 * struct_field_for_cmp().  Q_GETINFO uses if_dqinfo at the same
	 * slot but is output-only, so the pool stays at just Q_SETINFO.
	 */
	{
		"quotactl", 4, &struct_catalog[SC_IF_DQINFO],
		.discrim_arg_idx	= 1,
		.discrim_values		= quotactl_if_dqinfo_subcmds,
		.num_discrim_values	= ARRAY_SIZE(quotactl_if_dqinfo_subcmds),
		.discrim_shift		= SUBCMDSHIFT,
	},
	{
		"quotactl_fd", 4, &struct_catalog[SC_IF_DQINFO],
		.discrim_arg_idx	= 2,
		.discrim_values		= quotactl_if_dqinfo_subcmds,
		.num_discrim_values	= ARRAY_SIZE(quotactl_if_dqinfo_subcmds),
		.discrim_shift		= SUBCMDSHIFT,
	},
	/*
	 * fs_disk_quota sibling of the if_dqblk / if_dqinfo registrations
	 * above: the same addr slot (quotactl a4 / quotactl_fd a4) is a
	 * struct fs_disk_quota pointer under Q_XSETQLIM (the XFS quota
	 * set-limit command).  Same packed-discriminator extraction
	 * (discrim_shift = SUBCMDSHIFT) and same attribution-only shape
	 * as the if_dqblk / if_dqinfo pairs -- the bespoke sanitisers
	 * own the live fill; this entry only steers
	 * struct_field_for_cmp().  Q_XGETQUOTA / Q_XGETNEXTQUOTA use
	 * fs_disk_quota at the same slot but are output-only, so the
	 * pool stays at just Q_XSETQLIM.
	 */
	{
		"quotactl", 4, &struct_catalog[SC_FS_DISK_QUOTA],
		.discrim_arg_idx	= 1,
		.discrim_values		= quotactl_fs_disk_quota_subcmds,
		.num_discrim_values	= ARRAY_SIZE(quotactl_fs_disk_quota_subcmds),
		.discrim_shift		= SUBCMDSHIFT,
	},
	{
		"quotactl_fd", 4, &struct_catalog[SC_FS_DISK_QUOTA],
		.discrim_arg_idx	= 2,
		.discrim_values		= quotactl_fs_disk_quota_subcmds,
		.num_discrim_values	= ARRAY_SIZE(quotactl_fs_disk_quota_subcmds),
		.discrim_shift		= SUBCMDSHIFT,
	},
#ifdef X86
	/*
	 * modify_ldt(int func, void __user *ptr, unsigned long bytecount)
	 * a2 is a struct user_desc pointer only on the write_ldt arm
	 * (func == 1); the read arm (func == 0) hands the kernel a
	 * plain user buffer to splat the live LDT into.  The bespoke
	 * sanitise_modify_ldt() arm keeps owning the live fill (per-bit
	 * RAND_BOOL pickers for the seg_32bit / contents / read_exec_only
	 * / limit_in_pages / seg_not_present / useable / lm bitfields,
	 * rec->a3 pinned to sizeof(struct user_desc));  attribution-only
	 * registration lets struct_field_for_cmp() steer CMP-learned
	 * constants at the named entry_number / base_addr / limit slots
	 * rather than at a coincidentally-same-width slot.
	 *
	 * Discriminator pool is the single value {1}; func == 0 / 2 fall
	 * through to NULL and the bespoke arm continues to own them.
	 */
	{
		"modify_ldt", 2, &struct_catalog[SC_USER_DESC],
		.discrim_arg_idx	= 1,
		.discrim_value		= 1,
	},
#endif
	/*
	 * seccomp a3: struct sock_fprog under SECCOMP_SET_MODE_FILTER
	 * (the cBPF install arm).  Attribution-only; bespoke
	 * sanitise_seccomp() owns the live fill via bpf_gen_seccomp().
	 * Prctl PR_SET_SECCOMP shares the shape (two-key row below);
	 * setsockopt SO_ATTACH_FILTER stays bespoke (BPF arm REPLACES
	 * optval wholesale).  See Documentation/struct_catalog.md.
	 */
	{
		"seccomp", 3, &struct_catalog[SC_SOCK_FPROG],
		.discrim_arg_idx	= 1,
		.discrim_values		= seccomp_set_mode_filter_ops,
		.num_discrim_values	= ARRAY_SIZE(seccomp_set_mode_filter_ops),
	},
	/*
	 * prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, sock_fprog *) cBPF
	 * install arm.  Two-key row (option at a1, mode at a2).
	 * Attribution-only; bespoke sanitise_prctl() PR_SET_SECCOMP arm
	 * owns the live fill via bpf_gen_seccomp().
	 * See Documentation/struct_catalog.md.
	 */
	{
		"prctl", 3, &struct_catalog[SC_SOCK_FPROG],
		.discrim_arg_idx	= 1,
		.discrim_value		= PR_SET_SECCOMP,
		.discrim2_arg_idx	= 2,
		.discrim2_value		= SECCOMP_MODE_FILTER,
	},
	/*
	 * setsockopt a4 (optval): two-key (level, optname) rows resolved
	 * via struct_arg_lookup_two_key() from apply_sockopt_entry().
	 * Attribution-only; bespoke build_*() in syscalls/setsockopt.c
	 * owns selection / optlen / BPF replacement.
	 * See Documentation/struct_catalog.md.
	 */
	{
		"setsockopt", 4, &struct_catalog[SC_LINGER],
		.discrim_arg_idx	= 2,
		.discrim_value		= SOL_SOCKET,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SO_LINGER,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_TIMEVAL],
		.discrim_arg_idx	= 2,
		.discrim_value		= SOL_SOCKET,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_timeval_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_timeval_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_IP_MREQN],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_IP,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_ip_mreqn_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_ip_mreqn_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_IP_MREQ_SOURCE],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_IP,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_ip_mreq_source_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_ip_mreq_source_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_IPV6_MREQ],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_IPV6,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_ipv6_mreq_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_ipv6_mreq_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_PACKET_MREQ],
		.discrim_arg_idx	= 2,
		.discrim_value		= SOL_PACKET,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_packet_mreq_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_packet_mreq_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_GROUP_REQ],
		.discrim_arg_idx	= 2,
		.discrim_values		= setsockopt_mcast_levels,
		.num_discrim_values	= ARRAY_SIZE(setsockopt_mcast_levels),
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_mcast_join_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_mcast_join_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_GROUP_SOURCE_REQ],
		.discrim_arg_idx	= 2,
		.discrim_values		= setsockopt_mcast_levels,
		.num_discrim_values	= ARRAY_SIZE(setsockopt_mcast_levels),
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_mcast_source_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_mcast_source_optnames),
	},
#ifdef USE_TCP_REPAIR_OPT
	{
		"setsockopt", 4, &struct_catalog[SC_TCP_REPAIR_OPT],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_TCP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= TCP_REPAIR_OPTIONS,
	},
#endif
#ifdef USE_SCTP
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_INITMSG],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_INITMSG,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_RTOINFO],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_RTOINFO,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_ASSOCPARAMS],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_ASSOCINFO,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_SETADAPTATION],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_ADAPTATION_LAYER,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_ASSOC_VALUE],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_sctp_assoc_value_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_sctp_assoc_value_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_SNDINFO],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_DEFAULT_SNDINFO,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_SNDRCVINFO],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_DEFAULT_SEND_PARAM,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_EVENT_SUBSCRIBE],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_EVENTS,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_AUTHCHUNK],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_AUTH_CHUNK,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_SACK_INFO],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_DELAYED_SACK,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_AUTHKEYID],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_sctp_authkeyid_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_sctp_authkeyid_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_DEFAULT_PRINFO],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_DEFAULT_PRINFO,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_ADD_STREAMS],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_ADD_STREAMS,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_STREAM_VALUE],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_STREAM_SCHEDULER_VALUE,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_EVENT],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_EVENT,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_PADDRTHLDS],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_PEER_ADDR_THLDS,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_PADDRTHLDS_V2],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_PEER_ADDR_THLDS_V2,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_UDPENCAPS],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_REMOTE_UDP_ENCAPS_PORT,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_PADDRPARAMS],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_PEER_ADDR_PARAMS,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_PROBEINTERVAL],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_PLPMTUD_PROBE_INTERVAL,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_PRIM],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_sctp_prim_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_sctp_prim_optnames),
	},
#endif
	/*
	 * getsockopt a4 (optval): mirrors the setsockopt two-key rows
	 * for gettable (level, optname) pairs; attribution-only.
	 * Set-only optnames not mirrored (kernel does not return their
	 * payload struct on the get path).
	 * See Documentation/struct_catalog.md.
	 */
	{
		"getsockopt", 4, &struct_catalog[SC_LINGER],
		.discrim_arg_idx	= 2,
		.discrim_value		= SOL_SOCKET,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SO_LINGER,
	},
	{
		"getsockopt", 4, &struct_catalog[SC_TIMEVAL],
		.discrim_arg_idx	= 2,
		.discrim_value		= SOL_SOCKET,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_timeval_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_timeval_optnames),
	},
	/*
	 * io_cancel(aio_context_t ctx_id, struct iocb __user *iocb,
	 *           struct io_event __user *result)
	 * a2 is the INPUT struct iocb pointer.  sanitise_io_cancel() owns
	 * the live fill (memset, opcode = IOCB_CMD_PREAD, fd from
	 * get_random_fd(), aio_buf via get_writable_address, optional pool
	 * pin from OBJ_AIO_IOCB) and overwrites rec->a2 wholesale.
	 * Attribution-only registration lets struct_field_for_cmp steer
	 * KCOV-CMP learned constants at the named opcode / flags / fd
	 * slots rather than at a coincidentally-same-width slot.
	 *
	 * Not registered here on purpose: io_submit's a3 is
	 * `struct iocb __user * __user *` -- an array-of-pointers, the
	 * wrong indirection for a flat single-struct descriptor.  The
	 * io_cancel a2 slot is the real `struct iocb *`.
	 */
	{ "io_cancel",		2, &struct_catalog[SC_IOCB] },
	/*
	 * iovec is an array slot on ARG_IOVEC / ARG_IOVEC_IN at the
	 * vec / iov argument of every iovec-shaped syscall; the per-
	 * element type is named here so future schema consumers and
	 * struct_field_for_cmp() can resolve it.  The bespoke
	 * alloc_iovec() generator owns the live (iov_base, iov_len)
	 * layout, so all rows below are attribution-only.
	 *
	 * readv(int fd, const struct iovec *vec, int vlen)
	 * writev(int fd, const struct iovec *vec, int vlen)
	 * preadv(unsigned long fd, const struct iovec *vec,
	 *        unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
	 * preadv2(..., int flags)
	 * pwritev(unsigned long fd, const struct iovec *vec,
	 *         unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
	 * pwritev2(..., int flags)
	 * vmsplice(int fd, const struct iovec *iov, unsigned long nr_segs,
	 *          unsigned int flags)
	 * process_madvise(int pidfd, const struct iovec *vec, size_t vlen,
	 *                 int behavior, unsigned int flags)
	 */
	{ "readv",		2, &struct_catalog[SC_IOVEC] },
	{ "writev",		2, &struct_catalog[SC_IOVEC] },
	{ "preadv",		2, &struct_catalog[SC_IOVEC] },
	{ "preadv2",		2, &struct_catalog[SC_IOVEC] },
	{ "pwritev",		2, &struct_catalog[SC_IOVEC] },
	{ "pwritev2",		2, &struct_catalog[SC_IOVEC] },
	{ "vmsplice",		2, &struct_catalog[SC_IOVEC] },
	{ "process_madvise",	2, &struct_catalog[SC_IOVEC] },
	/*
	 * process_vm_readv(pid_t pid, const struct iovec *lvec,
	 *                  unsigned long liovcnt, const struct iovec *rvec,
	 *                  unsigned long riovcnt, unsigned long flags)
	 * process_vm_writev(pid_t pid, const struct iovec *lvec,
	 *                   unsigned long liovcnt, const struct iovec *rvec,
	 *                   unsigned long riovcnt, unsigned long flags)
	 * Both lvec (a2) and rvec (a4) are iovec arrays; map each
	 * separately so attribution covers both slots.
	 */
	{ "process_vm_readv",	2, &struct_catalog[SC_IOVEC] },
	{ "process_vm_readv",	4, &struct_catalog[SC_IOVEC] },
	{ "process_vm_writev",	2, &struct_catalog[SC_IOVEC] },
	{ "process_vm_writev",	4, &struct_catalog[SC_IOVEC] },
	/*
	 * msgsnd(int msqid, const struct msgbuf __user *msgp, size_t msgsz,
	 *        int msgflg)
	 * a2 is ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
	 * sanitise_msgsnd() keeps owning the live fill: a zmalloc'd
	 * sizeof(struct msgbuf) + msgsz buffer with mtype in [1, 255] and
	 * the variable mtext[] tail covered by the bespoke sizing.
	 * Attribution-only registration lets struct_field_for_cmp() steer
	 * CMP-learned constants at the named mtype slot rather than at a
	 * coincidentally-same-width slot.  msgrcv's a2 is a kernel-written
	 * output buffer and is intentionally not mapped.
	 */
	{ "msgsnd",		2, &struct_catalog[SC_MSGBUF] },
	/*
	 * signalfd(int ufd, const sigset_t __user *user_mask, size_t sizemask)
	 * signalfd4(int ufd, const sigset_t __user *user_mask, size_t sizemask,
	 *           int flags)
	 * a2 is ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
	 * sanitise_signalfd() / sanitise_signalfd4() keep owning the live
	 * fill: a four-way bucketed sigset_t (empty / single RT signal /
	 * classic standard-signal mix / sigfillset minus SIGKILL+SIGSTOP).
	 * Attribution-only registration lets struct_field_for_cmp() steer
	 * CMP-learned constants at the named __val slot rather than at a
	 * coincidentally-same-width neighbour.  SC_SIGSET_T is shared infra
	 * future sigset_t-taking syscalls (e.g. rt_sigsuspend) can reuse.
	 */
	{ "signalfd",		2, &struct_catalog[SC_SIGSET_T] },
	{ "signalfd4",		2, &struct_catalog[SC_SIGSET_T] },
	{ "rt_sigsuspend",	1, &struct_catalog[SC_SIGSET_T] },
	{ "rt_sigtimedwait",	1, &struct_catalog[SC_SIGSET_T] },
	{ "ppoll",		4, &struct_catalog[SC_SIGSET_T] },
	{ "epoll_pwait",	5, &struct_catalog[SC_SIGSET_T] },
	/*
	 * epoll_pwait2(int epfd, struct epoll_event __user *events,
	 *              int maxevents, const struct timespec __user *timeout,
	 *              const sigset_t __user *sigmask, size_t sigsetsize)
	 * a5 is ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
	 * sanitise_epoll_pwait2() keeps owning the live fill via
	 * pick_sigmask().  Attribution-only registration lets
	 * struct_field_for_cmp() steer CMP-learned constants at the named
	 * sigset_t __val slot rather than at a coincidentally-same-width
	 * neighbour.  a4 (timeout) is mapped to SC_TIMESPEC above and is
	 * unaffected.
	 */
	{ "epoll_pwait2",	5, &struct_catalog[SC_SIGSET_T] },
	/*
	 * lsm_set_self_attr(unsigned int attr, struct lsm_ctx __user *ctx,
	 *                   u32 size, u32 flags)
	 * a2 is ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
	 * sanitise_lsm_set_self_attr() keeps owning the live fill: a
	 * page_size+64 buffer with id drawn from {SELINUX, SMACK, APPARMOR,
	 * LANDLOCK} and size bucketed across the kernel's
	 * security_setselfattr() validation arms.  Attribution-only
	 * registration lets struct_field_for_cmp() steer CMP-learned
	 * constants at the named id / flags / len / ctx_len slots rather
	 * than at coincidentally-same-width neighbours; id is the prime
	 * dispatch target (the kernel selects a single LSM hook from it).
	 * lsm_get_self_attr's lsm_ctx a1 is a kernel-written output buffer
	 * and is intentionally not mapped.
	 */
	{ "lsm_set_self_attr",	2, &struct_catalog[SC_LSM_CTX] },
	/*
	 * kexec_load(unsigned long entry, unsigned long nr_segments,
	 *            struct kexec_segment __user *segments,
	 *            unsigned long flags)
	 * a3 is the segments array; argtype[2] is ARG_ADDRESS (not
	 * ARG_STRUCT_PTR_*), so sanitise_kexec_load() in
	 * syscalls/kexec_load.c keeps owning the live fill.  Attribution-
	 * only registration lets struct_field_for_cmp() steer CMP-learned
	 * constants at the named buf / bufsz / mem / memsz slots rather
	 * than at coincidentally-same-width neighbours.  See
	 * SC_KEXEC_SEGMENT above.
	 */
	{ "kexec_load",		3, &struct_catalog[SC_KEXEC_SEGMENT] },
	/* sentinel */
	{ NULL, 0, NULL },
};

/*
 * Composition root: the single unified table above is exposed as one
 * group.  As per-domain files carve entries out of it, each landing
 * domain adds its own extern-declared array as an additional group
 * here; the flat table shrinks in lockstep.  Consumers iterate the
 * groups via FOR_EACH_SYSCALL_STRUCT_ARG(), so the walk order and the
 * matched entries stay byte-identical to the pre-split table for any
 * (name, arg_idx) tuple.
 */
extern const struct syscall_struct_arg struct_catalog_registry_time[];
extern const struct syscall_struct_arg struct_catalog_registry_io_uring[];
extern const struct syscall_struct_arg struct_catalog_registry_sched[];

const struct syscall_struct_arg_group syscall_struct_arg_groups[] = {
	{ struct_catalog_registry_time },
	{ struct_catalog_registry_io_uring },
	{ struct_catalog_registry_sched },
	{ syscall_struct_args_all },
	{ NULL },
};

/* ------------------------------------------------------------------ */
/* Fast nr -> desc lookup table                                         */
/* ------------------------------------------------------------------ */

/*
 * desc_by_nr_64[syscall_nr][arg_idx - 1] -> slot_binding* or NULL.
 * desc_by_nr_32[syscall_nr][arg_idx - 1] -> slot_binding* or NULL.
 * Populated at init time by scanning the active syscall table.
 * Split to avoid collisions when biarch builds have different syscall
 * numbers for 32-bit and 64-bit that happen to overlap.
 *
 * Each non-NULL cell points into slot_pool[] and groups every
 * registration for that (nr, arg_idx): one optional default entry plus
 * any discriminator variants.  struct_arg_lookup() walks the variants
 * (rec required) first and falls back to the default; a slot with
 * neither a default nor a matching variant returns NULL.
 */
/*
 * Per-slot discriminated variant cap.  Bumped 8 -> 32 ahead of the
 * setsockopt (level, optname) two-key rows: arg4 will accrete one
 * binding per cataloged optval shape, and even the proof batch
 * (linger / timeval / ip_mreqn / ipv6_mreq / packet_mreq) consumes
 * five slots before any of the higher-leverage shapes (sctp / mptcp /
 * tcp_repair) land.  Init BUG()s on overflow, so the cap MUST be raised
 * before any setsockopt rows -- a deferred bump turns the first
 * registration past 8 into a hard boot failure.
 */
#define DISCRIM_VARIANTS_PER_SLOT_MAX	32

struct slot_binding {
	const struct struct_desc	*default_desc;
	const struct syscall_struct_arg	*discrim[DISCRIM_VARIANTS_PER_SLOT_MAX];
	unsigned int			 num_discrim;
};

/*
 * Slot-binding pool.  Sized for every registered (nr, arg) cell across
 * both arch tables -- syscall_struct_args[] is ~60 entries today, so 256
 * leaves growth headroom and stays comfortably under any reasonable
 * static budget.  struct_catalog_init() BUG()s if a registration
 * overflows either the pool or the per-slot variant cap rather than
 * silently dropping mappings.
 */
#define SLOT_POOL_MAX			256

static struct slot_binding slot_pool[SLOT_POOL_MAX];
static unsigned int slot_pool_used;

static const struct slot_binding *desc_by_nr_64[MAX_NR_SYSCALL][6];
static const struct slot_binding *desc_by_nr_32[MAX_NR_SYSCALL][6];

/* ------------------------------------------------------------------ */
/* API                                                                  */
/* ------------------------------------------------------------------ */

const struct struct_desc *struct_arg_lookup(unsigned int nr,
					    unsigned int arg_idx,
					    bool do32bit,
					    struct syscallrecord *rec)
{
	const struct slot_binding *b;
	unsigned int i;

	if (nr >= MAX_NR_SYSCALL || arg_idx < 1 || arg_idx > 6)
		return NULL;
	b = do32bit ? desc_by_nr_32[nr][arg_idx - 1]
		    : desc_by_nr_64[nr][arg_idx - 1];
	if (b == NULL)
		return NULL;

	/*
	 * Discriminated variants are consulted only when the caller has a
	 * live syscall record to read sibling args off.  No rec, or no
	 * discriminated entries registered, falls straight through to the
	 * default desc -- the byte-identical pre-discriminator path.
	 */
	if (rec != NULL && b->num_discrim != 0) {
		for (i = 0; i < b->num_discrim; i++) {
			const struct syscall_struct_arg *sa = b->discrim[i];
			unsigned long raw;

			if (!read_rec_arg(rec, sa->discrim_arg_idx, &raw))
				continue;
			if (!discrim_key_matches(raw, sa->discrim_shift,
						 sa->discrim_mask,
						 sa->discrim_value,
						 sa->discrim_values,
						 sa->num_discrim_values))
				continue;
			/*
			 * Key2 only participates when the entry declares one
			 * (discrim2_arg_idx != 0); single-key rows leave
			 * key2 a no-op and stay byte-identical to the
			 * pre-extension path.  Both keys must match.
			 */
			if (!discrim_key2_matches(sa, rec))
				continue;
			return sa->desc;
		}
	}
	return b->default_desc;
}

const struct struct_desc *struct_arg_lookup_two_key(const char *name,
						    unsigned int arg_idx,
						    unsigned long k1,
						    unsigned long k2)
{
	const struct syscall_struct_arg_group *g;
	const struct syscall_struct_arg *sa;

	if (name == NULL || arg_idx < 1 || arg_idx > 6)
		return NULL;

	/*
	 * Linear scan keeps the cost identical to struct_arg_lookup_by_name
	 * and avoids a second nr-indexed table just for explicit-key
	 * callers.  The registration table is small (~70 entries today); the
	 * scan runs once per apply_sockopt_entry call which already does
	 * O(table) work picking a random row.
	 *
	 * Skip rows with no second key registered: this entry point is for
	 * genuine two-key resolution -- a single-key row would resolve to
	 * different semantics on its own and a caller wanting that should
	 * use struct_arg_lookup() (rec-path) or struct_arg_lookup_by_name
	 * (discriminator-blind) instead.
	 */
	FOR_EACH_SYSCALL_STRUCT_ARG(g, sa) {
		if (sa->arg_idx != arg_idx)
			continue;
		if (sa->discrim_arg_idx == 0 || sa->discrim2_arg_idx == 0)
			continue;
		if (strcmp(sa->syscall_name, name) != 0)
			continue;
		if (!discrim_key_matches(k1, sa->discrim_shift, sa->discrim_mask,
					 sa->discrim_value, sa->discrim_values,
					 sa->num_discrim_values))
			continue;
		if (!discrim_key_matches(k2, sa->discrim2_shift,
					 sa->discrim2_mask,
					 sa->discrim2_value,
					 sa->discrim2_values,
					 sa->num_discrim2_values))
			continue;
		return sa->desc;
	}
	return NULL;
}

const struct struct_desc *struct_arg_lookup_by_name(const char *name,
						    unsigned int arg_idx)
{
	const struct syscall_struct_arg_group *g;
	const struct syscall_struct_arg *sa;
	const struct struct_desc *first = NULL;

	if (name == NULL || arg_idx < 1 || arg_idx > 6)
		return NULL;
	/*
	 * Prefer the slot's default (non-discriminated) entry; fall back to
	 * the first discriminated variant when no default is registered.
	 * Callers that need OR-across-all-variants semantics (e.g. the
	 * nested-address-scrub mask) use struct_arg_any_has_address_field()
	 * below -- single-desc returns can't represent that question.
	 */
	FOR_EACH_SYSCALL_STRUCT_ARG(g, sa) {
		if (sa->arg_idx != arg_idx)
			continue;
		if (strcmp(sa->syscall_name, name) != 0)
			continue;
		if (sa->discrim_arg_idx == 0)
			return sa->desc;
		if (first == NULL)
			first = sa->desc;
	}
	return first;
}

/*
 * Allocate (or fetch) the slot_binding cell at table[nr][arg_idx-1].
 * Pool growth is bounded by SLOT_POOL_MAX; running out is a hard
 * configuration error (caller forgot to bump the cap when extending
 * the registration table), not a runtime degradation, so BUG() rather
 * than silently dropping mappings.
 */
static struct slot_binding *
slot_binding_get(const struct slot_binding *table[MAX_NR_SYSCALL][6],
		 unsigned int nr, unsigned int arg_idx)
{
	struct slot_binding *b;

	if (table[nr][arg_idx - 1] != NULL)
		return (struct slot_binding *) table[nr][arg_idx - 1];

	if (slot_pool_used >= SLOT_POOL_MAX) {
		output(0, "struct_catalog: SLOT_POOL_MAX (%u) exhausted at "
		       "(nr=%u, arg=%u) -- raise SLOT_POOL_MAX or trim "
		       "syscall_struct_args[]\n",
		       (unsigned int) SLOT_POOL_MAX, nr, arg_idx);
		BUG("struct_catalog: SLOT_POOL_MAX exhausted");
	}
	b = &slot_pool[slot_pool_used++];
	b->default_desc = NULL;
	b->num_discrim = 0;
	table[nr][arg_idx - 1] = b;
	return b;
}

/*
 * Attach one syscall_struct_args[] entry to its (nr, arg_idx) binding.
 * Default entries write through to slot_binding::default_desc;
 * discriminated entries push into the variant list in registration
 * order so the lookup walk's first-match semantic matches the source
 * declaration order.  Multiple defaults for the same slot are a
 * registration bug; BUG() so the conflict surfaces at init rather than
 * silently leaking the later-registered desc into the lookup.
 */
static void slot_binding_attach(const struct slot_binding *table[MAX_NR_SYSCALL][6],
				unsigned int nr,
				const struct syscall_struct_arg *sa)
{
	struct slot_binding *b = slot_binding_get(table, nr, sa->arg_idx);

	if (sa->discrim_arg_idx == 0) {
		if (b->default_desc != NULL) {
			output(0, "struct_catalog: duplicate default "
			       "registration for (%s, arg %u)\n",
			       sa->syscall_name, sa->arg_idx);
			BUG("struct_catalog: duplicate default registration");
		}
		b->default_desc = sa->desc;
		return;
	}
	if (b->num_discrim >= DISCRIM_VARIANTS_PER_SLOT_MAX) {
		output(0, "struct_catalog: DISCRIM_VARIANTS_PER_SLOT_MAX (%u) "
		       "exhausted for (%s, arg %u) -- raise the cap or "
		       "collapse variants\n",
		       (unsigned int) DISCRIM_VARIANTS_PER_SLOT_MAX,
		       sa->syscall_name, sa->arg_idx);
		BUG("struct_catalog: DISCRIM_VARIANTS_PER_SLOT_MAX exhausted");
	}
	b->discrim[b->num_discrim++] = sa;
}

void struct_catalog_init(void)
{
	const struct syscall_struct_arg_group *g;
	const struct syscall_struct_arg *sa;
	unsigned int i;
	int nr;

	/*
	 * Holes are zero-init struct_desc slots with .name == NULL --
	 * a sign of a typo'd [SC_X] designator above the slot, or of an
	 * SC_X enum constant added without a matching catalog entry.
	 * Catch it on first init rather than letting the dispatch path
	 * deref a half-zeroed struct_desc.
	 */
	for (i = 0; i < SC_NR_ENTRIES; i++) {
		if (struct_catalog[i].name == NULL) {
			outputerr("struct_catalog: hole at slot %u "
				  "(missing [SC_X] designator)\n", i);
			BUG("struct_catalog: hole in catalog array");
		}
	}

	validate_syscall_struct_args();

	memset(desc_by_nr_64, 0, sizeof(desc_by_nr_64));
	memset(desc_by_nr_32, 0, sizeof(desc_by_nr_32));
	slot_pool_used = 0;

	FOR_EACH_SYSCALL_STRUCT_ARG(g, sa) {
		if (sa->arg_idx < 1 || sa->arg_idx > 6)
			continue;

		/* Search the active syscall table(s) for this name. */
		if (biarch) {
			nr = search_syscall_table(syscalls_64bit,
						  max_nr_64bit_syscalls,
						  sa->syscall_name);
			if (nr >= 0 && (unsigned int) nr < MAX_NR_SYSCALL)
				slot_binding_attach(desc_by_nr_64,
						    (unsigned int) nr, sa);

			nr = search_syscall_table(syscalls_32bit,
						  max_nr_32bit_syscalls,
						  sa->syscall_name);
			if (nr >= 0 && (unsigned int) nr < MAX_NR_SYSCALL)
				slot_binding_attach(desc_by_nr_32,
						    (unsigned int) nr, sa);
		} else {
			nr = search_syscall_table(syscalls,
						  max_nr_syscalls,
						  sa->syscall_name);
			if (nr >= 0 && (unsigned int) nr < MAX_NR_SYSCALL) {
				slot_binding_attach(desc_by_nr_64,
						    (unsigned int) nr, sa);
				slot_binding_attach(desc_by_nr_32,
						    (unsigned int) nr, sa);
			}
		}
	}

	for (i = 0; i < SC_NR_ENTRIES; i++)
		output(0, "struct catalog: registered %s (%u fields, %u bytes)\n",
		       struct_catalog[i].name,
		       struct_catalog[i].num_fields,
		       struct_catalog[i].struct_size);
}
