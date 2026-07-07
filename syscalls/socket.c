/*
 * SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)
 */
#include <sys/socket.h>
#include <unistd.h>
#ifdef USE_BLUETOOTH
#include <bluetooth/bluetooth.h>
#endif
#include <linux/can.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include "debug.h"
#include "net.h"
#include "objects.h"
#include "params.h"
#include "domains.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "uid.h"
#include "compat.h"

#include "kernel/socket.h"
/* ETH_P_ALL in network byte order, usable in a static initializer. */
#define ETH_P_ALL_NBO_LOCAL (((ETH_P_ALL & 0xff) << 8) | ((ETH_P_ALL >> 8) & 0xff))

/*
 * Curated table of well-known socket(2) triplets.  The kernel accepts
 * each of these on a stock distro build, so biasing draws toward this
 * table keeps the per-family valid_triplets[] paths exercised even when
 * the random-family picker would otherwise land on a sparsely populated
 * AF.  Each entry corresponds to a triplet already attested by one of
 * the net/proto-*.c valid_triplets[] arrays.
 */
static const struct socket_triplet well_known_triplets[] = {
	/* AF_INET */
	{ .family = PF_INET,     .type = SOCK_STREAM,    .protocol = 0 },
	{ .family = PF_INET,     .type = SOCK_DGRAM,     .protocol = 0 },
	{ .family = PF_INET,     .type = SOCK_STREAM,    .protocol = IPPROTO_TCP },
	{ .family = PF_INET,     .type = SOCK_DGRAM,     .protocol = IPPROTO_UDP },

	/* AF_INET6 */
	{ .family = PF_INET6,    .type = SOCK_STREAM,    .protocol = 0 },
	{ .family = PF_INET6,    .type = SOCK_DGRAM,     .protocol = 0 },
	{ .family = PF_INET6,    .type = SOCK_STREAM,    .protocol = IPPROTO_TCP },
	{ .family = PF_INET6,    .type = SOCK_DGRAM,     .protocol = IPPROTO_UDP },

	/* AF_UNIX */
	{ .family = PF_UNIX,     .type = SOCK_STREAM,    .protocol = 0 },
	{ .family = PF_UNIX,     .type = SOCK_DGRAM,     .protocol = 0 },
	{ .family = PF_UNIX,     .type = SOCK_SEQPACKET, .protocol = 0 },

	/* AF_NETLINK */
	{ .family = PF_NETLINK,  .type = SOCK_RAW,       .protocol = NETLINK_ROUTE },
	{ .family = PF_NETLINK,  .type = SOCK_DGRAM,     .protocol = NETLINK_USERSOCK },
	{ .family = PF_NETLINK,  .type = SOCK_RAW,       .protocol = NETLINK_GENERIC },
	{ .family = PF_NETLINK,  .type = SOCK_RAW,       .protocol = NETLINK_KOBJECT_UEVENT },

	/* AF_PACKET */
	{ .family = PF_PACKET,   .type = SOCK_RAW,       .protocol = ETH_P_ALL_NBO_LOCAL },
	{ .family = PF_PACKET,   .type = SOCK_DGRAM,     .protocol = ETH_P_ALL_NBO_LOCAL },

	/* AF_CAN */
	{ .family = PF_CAN,      .type = SOCK_RAW,       .protocol = CAN_RAW },

	/* AF_VSOCK */
	{ .family = PF_VSOCK,    .type = SOCK_STREAM,    .protocol = 0 },
	{ .family = PF_VSOCK,    .type = SOCK_DGRAM,     .protocol = 0 },

	/* AF_ALG */
	{ .family = PF_ALG,      .type = SOCK_SEQPACKET, .protocol = 0 },

#ifdef USE_BLUETOOTH
	/* AF_BLUETOOTH */
	{ .family = PF_BLUETOOTH, .type = SOCK_STREAM,   .protocol = BTPROTO_L2CAP },
	{ .family = PF_BLUETOOTH, .type = SOCK_STREAM,   .protocol = BTPROTO_RFCOMM },
	{ .family = PF_BLUETOOTH, .type = SOCK_RAW,      .protocol = BTPROTO_HCI },
#endif
};

/*
 * Try to pick a triplet from the well-known table whose family is not
 * currently disabled.  Returns true on success.  Bounded retry: if we
 * cannot find an enabled entry quickly, the caller falls back to the
 * generic random path.
 */
static bool pick_well_known_triplet(struct socket_triplet *st)
{
	unsigned int attempts;
	const unsigned int n = ARRAY_SIZE(well_known_triplets);

	if (n == 0)
		return false;

	for (attempts = 0; attempts < 16; attempts++) {
		const struct socket_triplet *p =
			&well_known_triplets[rnd_modulo_u32(n)];

		if (p->family >= ARRAY_SIZE(no_domains))
			continue;
		if (no_domains[p->family])
			continue;

		st->family = p->family;
		st->type = p->type;
		st->protocol = p->protocol;
		return true;
	}

	return false;
}

/*
 * Pick an arbitrary enabled family and pair it with an obviously
 * unmapped protocol number.  This deliberately steers a small slice of
 * draws into the kernel's EPROTONOSUPPORT path so the family-level
 * dispatch stays warm without starving the success path.
 */
static void pick_invalid_protocol(struct socket_triplet *st)
{
	int types[] = { SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, SOCK_SEQPACKET };
	unsigned int family;

	family = rnd_modulo_u32(TRINITY_PF_MAX);
	BUG_ON(family >= ARRAY_SIZE(no_domains));
	if (no_domains[family]) {
		family = find_next_enabled_domain(family);
		if (family == -1u)
			family = PF_INET;
	}

	st->family = family;
	st->type = RAND_ARRAY(types);
	/* High enough to be outside the standard protocol-number ranges
	 * for IPPROTO / NETLINK / BTPROTO etc, but not so wild that we miss
	 * the per-family dispatch. */
	st->protocol = 0x100 + rnd_modulo_u32(0xff00);
}

void rand_proto_type(struct socket_triplet *st)
{
	int types[] = { SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, SOCK_RDM, SOCK_SEQPACKET, SOCK_DCCP, SOCK_PACKET };

	st->type = RAND_ARRAY(types);
	st->protocol = 0;
}

static bool do_priv(struct socket_triplet *st, const struct netproto *proto)
{
	if (proto->nr_privileged_triplets != 0) {
		int r;
		r = rnd_modulo_u32(proto->nr_privileged_triplets);
		st->protocol = proto->valid_privileged_triplets[r].protocol;
		st->type = proto->valid_privileged_triplets[r].type;
		return true;
	}
	return false;
}

/* note: also called from generate_sockets() */
int sanitise_socket_triplet(struct socket_triplet *st)
{
	const struct netproto *proto;

	proto = net_protocols[st->family].proto;
	if (proto != NULL) {

		if (orig_uid != 0)
			goto do_unpriv;

		if (RAND_BOOL()) {
do_unpriv:
			if (proto->nr_triplets != 0) {
				int r;
				r = rnd_modulo_u32(proto->nr_triplets);
				st->protocol = proto->valid_triplets[r].protocol;
				st->type = proto->valid_triplets[r].type;
				return 0;
			}
		} else {
			if (do_priv(st, proto) == false)
				goto do_unpriv;
		}
	}

	/* Couldn't find func, fall back to random. */
	return -1;
}

/* note: also called from sanitise_socketcall() */
void gen_socket_args(struct socket_triplet *st)
{
	unsigned int roll;
	bool picked = false;

	if (do_specific_domain == true) {
		st->family = specific_domain;
		if (sanitise_socket_triplet(st) < 0)
			rand_proto_type(st);
		goto flags;
	}

	/*
	 * Distribution across the available shapes:
	 *   [ 0..59]  curated well-known triplet table (~60%)
	 *   [60..89]  generic random-family + sanitise_socket_triplet (~30%)
	 *   [90..99]  intentionally invalid protocol on a real family (~10%)
	 *
	 * Within the 30% generic bucket we still retain the legacy 1-in-100
	 * "pure random crap" probe so wholly bogus type/protocol bytes keep
	 * appearing in the corpus.
	 */
	roll = rnd_modulo_u32(100);

	if (roll < 60) {
		picked = pick_well_known_triplet(st);
	}

	if (!picked && roll < 90) {
		st->family = rnd_modulo_u32(TRINITY_PF_MAX);
		BUG_ON(st->family >= ARRAY_SIZE(no_domains));
		if (no_domains[st->family]) {
			st->family = find_next_enabled_domain(st->family);
			if (st->family == -1u) {
				outputerr("No available socket family found\n");
				exit(EXIT_FAILURE);
			}
		}

		if (ONE_IN(100)) {
			rand_proto_type(st);
		} else if (sanitise_socket_triplet(st) < 0) {
			rand_proto_type(st);
		}
		picked = true;
	}

	if (!picked) {
		pick_invalid_protocol(st);
	}

flags:
	/*
	 * Explicit type-flag buckets, 25% each, so SOCK_CLOEXEC and
	 * SOCK_NONBLOCK both reliably appear alone and together.  The
	 * previous independent ONE_IN(4) calls produced ~6% "both" which
	 * left the dual-flag accept4/socket path under-exercised.
	 */
	switch (rnd_modulo_u32(4)) {
	case 0:
		break;
	case 1:
		st->type |= SOCK_CLOEXEC;
		break;
	case 2:
		st->type |= SOCK_NONBLOCK;
		break;
	case 3:
		st->type |= SOCK_CLOEXEC | SOCK_NONBLOCK;
		break;
	}

	/*
	 * Small bucket of intentionally-invalid type flags so the kernel's
	 * flag validation rejection path (the SOCK_TYPE_MASK / SOCK_CLOEXEC
	 * | SOCK_NONBLOCK guard) stays exercised.
	 */
	if (ONE_IN(20))
		st->type |= 1U << (24 + rnd_modulo_u32(8));
}


static void sanitise_socket(struct syscallrecord *rec)
{
	struct socket_triplet st = { .family = 0, .type = 0, .protocol = 0 };

	gen_socket_args(&st);

	rec->a1 = st.family;
	rec->a2 = st.type;
	rec->a3 = st.protocol;
}

static void post_socket(struct syscallrecord *rec)
{
	const struct netproto *proto;
	struct object *new;
	unsigned long family = rec->a1;
	int fd = rec->retval;

	if (fd < 0)
		return;

	if (family >= TRINITY_PF_MAX) {
		close(fd);
		return;
	}

	proto = net_protocols[family].proto;
	if (proto != NULL)
		if (proto->socket_setup != NULL)
			proto->socket_setup(fd);

	new = alloc_object();
	new->sockinfo.fd = fd;
	new->sockinfo.triplet.family = family;
	new->sockinfo.triplet.type = rec->a2;
	new->sockinfo.triplet.protocol = rec->a3;
	add_object(new, OBJ_LOCAL, OBJ_FD_SOCKET);
}

struct syscallentry syscall_socket = {
	.name = "socket",
	.num_args = 3,
	.argname = { [0] = "family", [1] = "type", [2] = "protocol" },
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_SOCKET,
	.group = GROUP_NET,
	.flags = KCOV_REMOTE_HEAVY,
	.sanitise = sanitise_socket,
	.post = post_socket,
};
