#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/bpf.h>
#include <linux/sockios.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include "arch.h"
#include "bpf.h"
#include "net.h"
#include "random.h"
#include "socket-family-grammar.h"
#include "trinity.h"
#include "utils.h"
#include "compat.h"

/* UAPI fallbacks for stripped sysroots without <linux/kcm.h>.  The values
 * are stable since the kernel UAPI shipped in 4.7. */
#ifndef KCMPROTO_CONNECTED
#define KCMPROTO_CONNECTED	0
#endif
#ifndef KCM_RECV_DISABLE
#define KCM_RECV_DISABLE	1
#endif
#ifndef SOL_KCM
#define SOL_KCM			281
#endif
#ifndef SIOCKCMATTACH
#define SIOCKCMATTACH		(SIOCPROTOPRIVATE + 0)
#define SIOCKCMUNATTACH		(SIOCPROTOPRIVATE + 1)
#define SIOCKCMCLONE		(SIOCPROTOPRIVATE + 2)
struct kcm_attach {
	int fd;
	int bpf_fd;
};
struct kcm_clone {
	int fd;
};
#endif

static const unsigned int kcm_opts[] = {
	KCM_RECV_DISABLE,
};

static void kcm_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	char *optval;

	so->level = SOL_KCM;

	optval = (char *) so->optval;

	so->optname = RAND_ARRAY(kcm_opts);
	so->optlen = sizeof(int);

	switch (so->optname) {
	case KCM_RECV_DISABLE:
		optval[0] = RAND_BOOL();
		break;
	default:
		break;
	}
}

static struct socket_triplet kcm_triplets[] = {
	{ .family = PF_KCM, .protocol = KCMPROTO_CONNECTED, .type = SOCK_DGRAM },
	{ .family = PF_KCM, .protocol = KCMPROTO_CONNECTED, .type = SOCK_SEQPACKET },
};

const struct netproto proto_kcm = {
	.name = "kcm",
	.setsockopt = kcm_setsockopt,
	.valid_triplets = kcm_triplets,
	.nr_triplets = ARRAY_SIZE(kcm_triplets),
};

/*
 * grammar_kcm — coherent walk for AF_KCM (Kernel Connection Multiplexer).
 *
 * KCM historically has had bug classes around BPF parser-attach timing
 * and channel teardown races.  Random per-syscall fuzzing essentially
 * never assembles the full sequence required to land on these surfaces:
 *
 *   socket(AF_KCM, SOCK_DGRAM, KCMPROTO_CONNECTED)
 *     -> KCM_RECV_DISABLE / re-enable churn (kcm_recvmsg path arming)
 *     -> SIOCKCMATTACH with a verifier-friendly cBPF/eBPF parser fd and
 *        an ESTABLISHED TCP socket as the underlying CSK transport
 *     -> SIOCKCMCLONE to spawn a sibling KCM fd referring to the same
 *        kcm_mux as the parent
 *     -> per-fd send/recv against parent + cloned channels
 *     -> close ordering race: half the walks close(parent) first, the
 *        other half close(clone) first.  Both flow through kcm_release
 *        but exercise different mux/psock teardown orderings.
 *
 * BPF parser fd lifecycle.  KCM's kcm_attach_ioctl() takes a refcount on
 * the BPF prog at attach time (bpf_prog_get_type) and drops it at psock
 * teardown.  That means the userspace BPF fd can be closed immediately
 * after attach without disturbing the kernel-side parser callback.  We
 * still cache one prog fd per child process (keyed by getpid() so a
 * post-fork child reloads instead of inheriting a parent fd that was
 * closed mid-walk) to avoid churning the BPF subsystem on every walk.
 *
 * The CSK transport requirement is the awkward part: kcm_attach_ioctl()
 * rejects with -EOPNOTSUPP unless csk->sk_protocol == IPPROTO_TCP and
 * csk->sk_state == TCP_ESTABLISHED.  We synthesise that per-walk with a
 * loopback listen+connect+accept pair, attach the connected client end,
 * then close our userspace TCP fds — KCM keeps its own ref via fget()
 * inside the attach path.  The accepted server-side fd is closed too;
 * KCM doesn't need it once the CSK is mounted.
 *
 * can_run probe: open AF_KCM once, cache the verdict.  CONFIG_AF_KCM=n
 * latches kcm_supported=0 in this child, the grammar gets filtered out
 * at sfg_pick_random_active() time before run_grammar_chain runs, and
 * the per-family unsupported latch shared with future AF_KCM users
 * stays clean.
 *
 * The childops/ layer (cgroup-attach, bpf-lifecycle, etc.) is orthogonal
 * — this grammar lives entirely inside the per-family socket-family-grammar
 * dispatcher and only touches the parent_fd that flows through the chain.
 */

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL	0x4000
#endif

/* Per-process probe + BPF cache.  -1 untested, 0 unsupported, 1 supported. */
static int kcm_supported = -1;
static int kcm_bpf_prog_fd = -1;
static pid_t kcm_bpf_owner_pid;

static int sys_bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
	return (int)syscall(__NR_bpf, cmd, attr, size);
}

/*
 * Minimal SOCKET_FILTER eBPF parser:  r0 = 4; exit;
 *
 * KCM's strparser invokes the attached program on every byte that lands
 * on the underlying TCP CSK; the return value is the number of bytes
 * consumed for the next message.  A constant 4-byte parse is enough to
 * drive the parser dispatch on every recv without depending on packet
 * shape — and is small enough to pass the verifier on every kernel that
 * supports SOCKET_FILTER (universal).
 */
static int kcm_load_parser_prog(void)
{
	struct bpf_insn insns[] = {
		EBPF_MOV64_IMM(BPF_REG_0, 4),
		EBPF_EXIT(),
	};
	union bpf_attr attr;
	char license[] = "GPL";

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
	attr.insn_cnt  = ARRAY_SIZE(insns);
	attr.insns     = (uintptr_t)insns;
	attr.license   = (uintptr_t)license;

	return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int kcm_get_parser_prog_fd(void)
{
	pid_t self = getpid();

	if (kcm_bpf_prog_fd >= 0 && kcm_bpf_owner_pid == self)
		return kcm_bpf_prog_fd;

	/* Stale cached fd from a pre-fork parent: drop the reference and
	 * reload so this child owns its own prog fd.  The kernel-side prog
	 * object stays alive as long as some task or kcm_psock still holds
	 * a ref; closing our stale userspace fd is safe. */
	if (kcm_bpf_prog_fd >= 0)
		(void) close(kcm_bpf_prog_fd);

	kcm_bpf_prog_fd = kcm_load_parser_prog();
	kcm_bpf_owner_pid = self;
	return kcm_bpf_prog_fd;
}

static bool kcm_can_run(void)
{
	int fd;

	if (kcm_supported >= 0)
		return kcm_supported == 1;

	fd = socket(PF_KCM, SOCK_DGRAM, KCMPROTO_CONNECTED);
	if (fd < 0) {
		kcm_supported = 0;
		return false;
	}
	close(fd);
	kcm_supported = 1;
	return true;
}

static void kcm_pick_triplet(struct socket_triplet *out)
{
	out->family = PF_KCM;
	out->protocol = KCMPROTO_CONNECTED;
	out->type = RAND_BOOL() ? SOCK_DGRAM : SOCK_SEQPACKET;
}

/*
 * KCM doesn't bind in the AF_INET sense — there is no kcm_bind in the
 * kernel; channel attach happens via SIOCKCMATTACH instead.  Returning 0
 * unconditionally keeps run_grammar_chain on the happy path; the real
 * channel setup runs in the data_leg below.
 */
static int kcm_bind_or_connect(__unused__ int fd,
			       __unused__ struct socket_triplet *triplet)
{
	return 0;
}

static bool kcm_needs_listen_accept(__unused__ struct socket_triplet *triplet)
{
	/* KCM channel cloning uses SIOCKCMCLONE, not listen()/accept(). */
	return false;
}

/*
 * Walk: alternate KCM_RECV_DISABLE on/off so kcm_recvmsg arms and
 * disarms in the same coherent run.  Disable side toggles
 * sk->sk_rcvtimeo behaviour and the early -EAGAIN fast-path; re-enable
 * unmasks the strparser handoff.  The default proto setsockopt walker
 * randomises this too but we want a deterministic flip pattern here so
 * every walk hits both arms of the dispatcher.
 */
static void kcm_walk_setsockopts(int fd, __unused__ struct socket_triplet *triplet,
				 unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++) {
		int v = (i & 1);

		(void) setsockopt(fd, SOL_KCM, KCM_RECV_DISABLE,
				  &v, sizeof(v));
	}
}

/*
 * Synthesise a connected loopback TCP pair.  Returns the connected
 * client-side fd in *cli (the side we feed to SIOCKCMATTACH) and the
 * accepted server-side fd in *srv (the peer that keeps the connection
 * established for KCM's TCP_ESTABLISHED check).  Caller closes both.
 */
static int kcm_make_tcp_pair(int *cli, int *srv)
{
	struct sockaddr_in sa;
	socklen_t sl;
	int ls, c, s;

	ls = socket(PF_INET, SOCK_STREAM, 0);
	if (ls < 0)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = 0;
	if (bind(ls, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		goto out_ls;
	sl = sizeof(sa);
	if (getsockname(ls, (struct sockaddr *)&sa, &sl) < 0)
		goto out_ls;
	if (listen(ls, 1) < 0)
		goto out_ls;

	c = socket(PF_INET, SOCK_STREAM, 0);
	if (c < 0)
		goto out_ls;
	if (connect(c, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(c);
		goto out_ls;
	}
	s = accept(ls, NULL, NULL);
	close(ls);
	if (s < 0) {
		close(c);
		return -1;
	}
	*cli = c;
	*srv = s;
	return 0;

out_ls:
	close(ls);
	return -1;
}

/*
 * data_leg: attach a parser, clone the channel, send/recv on both fds,
 * then close them in randomised order to race the kcm_mux teardown
 * against the per-channel kcm_sock release path.
 */
static void kcm_data_leg(int parent_fd, __unused__ int child_fd,
			 __unused__ struct socket_triplet *triplet)
{
	struct kcm_attach att = { 0 };
	struct kcm_clone clone = { 0 };
	int tcp_cli = -1, tcp_srv = -1;
	int prog_fd, clone_fd = -1;
	bool close_parent_first;
	unsigned char buf[64];

	prog_fd = kcm_get_parser_prog_fd();
	if (prog_fd < 0)
		goto race_close;

	if (kcm_make_tcp_pair(&tcp_cli, &tcp_srv) < 0)
		goto race_close;

	att.fd = tcp_cli;
	att.bpf_fd = prog_fd;
	if (ioctl(parent_fd, SIOCKCMATTACH, &att) < 0) {
		/* Attach failed (likely -EOPNOTSUPP from a kernel that
		 * doesn't support our exact CSK shape).  Drop the TCP
		 * pair and still race the close path on the bare parent
		 * fd — that exercises kcm_release without an attached
		 * psock, which is the no-channel teardown arm. */
		close(tcp_cli);
		close(tcp_srv);
		tcp_cli = tcp_srv = -1;
		goto race_close;
	}
	/* KCM took its own refs on the TCP socket; our userspace fds are
	 * no longer needed for the attach to stay live.  Closing them
	 * here also racing the strparser arming with TCP-side teardown is
	 * the point — leave that race window naturally open. */
	close(tcp_cli);
	tcp_cli = -1;

	clone.fd = -1;
	if (ioctl(parent_fd, SIOCKCMCLONE, &clone) == 0)
		clone_fd = clone.fd;

	/* Drive a quick send/recv pass on each fd so the parser fires at
	 * least once before teardown.  All four calls are non-blocking +
	 * NOSIGNAL — failure is fine, the goal is to land bytes on the
	 * kcm_recvmsg / kcm_sendmsg dispatch and let the parser observe
	 * them. */
	(void) send(parent_fd, "kcmkcmkc", 8, MSG_NOSIGNAL | MSG_DONTWAIT);
	(void) recv(parent_fd, buf, sizeof(buf), MSG_DONTWAIT);
	if (clone_fd >= 0) {
		(void) send(clone_fd, "kcmkcmkc", 8, MSG_NOSIGNAL | MSG_DONTWAIT);
		(void) recv(clone_fd, buf, sizeof(buf), MSG_DONTWAIT);
	}

race_close:
	/* Close-ordering race.  run_grammar_chain unconditionally closes
	 * parent_fd after data_leg returns, so:
	 *   close_parent_first=true  -> we close(parent) inside data_leg,
	 *                               framework's later close is a
	 *                               harmless EBADF on a freshly closed
	 *                               fd number.  Then close(clone).
	 *   close_parent_first=false -> we close(clone) inside data_leg,
	 *                               framework closes(parent) shortly
	 *                               after on return.
	 * Both orderings drive different last-ref kcm_sock release paths
	 * through kcm_done / kcm_release. */
	close_parent_first = RAND_BOOL();
	if (close_parent_first) {
		(void) close(parent_fd);
		if (clone_fd >= 0)
			(void) close(clone_fd);
	} else {
		if (clone_fd >= 0)
			(void) close(clone_fd);
		/* parent_fd left for the framework cleanup. */
	}

	if (tcp_srv >= 0)
		close(tcp_srv);
	if (tcp_cli >= 0)
		close(tcp_cli);
}

const struct socket_family_grammar grammar_kcm = {
	.family			= PF_KCM,
	.name			= "kcm",
	.can_run		= kcm_can_run,
	.pick_triplet		= kcm_pick_triplet,
	.bind_or_connect	= kcm_bind_or_connect,
	.needs_listen_accept	= kcm_needs_listen_accept,
	.walk_setsockopts	= kcm_walk_setsockopts,
	.data_leg		= kcm_data_leg,
};
