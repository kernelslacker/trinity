/*
 * Per-family grammar table dispatcher.  Generalises the v1
 * socket_family_chain childop (84b298906961, AF_ALG only) and v3's
 * splice-substitution data leg (ef5622b4ac38) into a table-driven
 * walker that drives arbitrary AF_* families through coherent
 * setsockopt/bind/listen/accept/sendmsg sequences using one struct
 * socket_family_grammar entry per family.
 *
 * The registry below is empty by default — when no grammar is
 * registered the outer dispatcher in childops/socket-family-chain.c
 * falls back to run_alg_chain (the v1 path) so behaviour is identical
 * to v1+v3.  Per-family grammars land in subsequent commits and each
 * adds one entry to sfg_registry[] alongside its definition in
 * net/proto-<family>.c.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <unistd.h>

#include "arch.h"		/* page_size */
#include "net.h"
#include "random.h"
#include "shm.h"
#include "socket-family-grammar.h"
#include "trinity.h"
#include "utils.h"
#include "compat.h"		/* keep last — matches net/proto-*.c order */

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL	0x4000
#endif

/*
 * Registry filled in by per-family commits.  The trailing NULL is a
 * sentinel that lets the framework commit land before any family
 * does — sfg_pick_random_active() skips NULL entries.  When a family
 * is added it goes ABOVE the sentinel so ARRAY_SIZE() still spans
 * every real slot.
 */
static const struct socket_family_grammar * const sfg_registry[] = {
	&grammar_inet,
#ifdef USE_IPV6
	&grammar_inet6,
#endif
	&grammar_mptcp,
	&grammar_kcm,
	&grammar_rxrpc,
	&grammar_qrtr,
#ifdef USE_RDS
	&grammar_rds,
#endif
#ifdef USE_MCTP
	&grammar_mctp,
#endif
	&grammar_llc,
	&grammar_unix,
	&grammar_netlink,
	&grammar_packet,
#ifdef USE_XDP
	&grammar_xdp,
#endif

	/* Dormant stubs — sfg_always_false keeps them inert on this
	 * kernel build, but the slot is held so a user with the right
	 * CONFIG (or a future commit upgrading the stub to a real
	 * grammar) drops in without changing the registry array. */
#ifdef USE_BLUETOOTH
	&grammar_bluetooth_stub,
#endif
#ifdef USE_CAIF
	&grammar_caif_stub,
#endif
#ifdef USE_VSOCK
	&grammar_vsock_stub,
#endif
	&grammar_can_stub,
	&grammar_phonet_stub,
	&grammar_smc_stub,
	&grammar_tipc_stub,

	NULL,
};

const struct socket_family_grammar *sfg_pick_random_active(void)
{
	const struct socket_family_grammar *active[ARRAY_SIZE(sfg_registry)];
	unsigned int i, nr_active = 0;

	for (i = 0; i < ARRAY_SIZE(sfg_registry); i++) {
		const struct socket_family_grammar *sfg = sfg_registry[i];

		if (sfg == NULL)
			continue;
		if (sfg->family <= 0 || sfg->family >= TRINITY_PF_MAX)
			continue;
		if (__atomic_load_n(&shm->sfg_unsupported[sfg->family],
				    __ATOMIC_RELAXED))
			continue;
		if (sfg->can_run != NULL && !sfg->can_run())
			continue;

		active[nr_active++] = sfg;
	}

	if (nr_active == 0)
		return NULL;

	return active[rand() % nr_active];
}

bool sfg_can_run_default(int family)
{
	int fd;

	if (family <= 0 || family >= TRINITY_PF_MAX)
		return false;

	if (__atomic_load_n(&shm->sfg_unsupported[family], __ATOMIC_RELAXED))
		return false;

	/* SOCK_STREAM is the most universally supported type for the
	 * IP-style families; AF_PACKET / AF_NETLINK / AF_ALG override
	 * can_run because their natural type is different. */
	fd = socket(family, SOCK_STREAM, 0);
	if (fd < 0) {
		__atomic_store_n(&shm->sfg_unsupported[family], true,
				 __ATOMIC_RELAXED);
		return false;
	}
	close(fd);
	return true;
}

void sfg_mark_unsupported(int family)
{
	if (family <= 0 || family >= TRINITY_PF_MAX)
		return;
	__atomic_store_n(&shm->sfg_unsupported[family], true,
			 __ATOMIC_RELAXED);
}

bool sfg_always_false(void)
{
	return false;
}

void sfg_default_pick_triplet(int family, struct socket_triplet *out)
{
	const struct netproto *proto;

	out->family = family;
	out->type = SOCK_STREAM;
	out->protocol = 0;

	if (family <= 0 || family >= TRINITY_PF_MAX)
		return;

	proto = net_protocols[family].proto;
	if (proto == NULL || proto->valid_triplets == NULL ||
	    proto->nr_triplets == 0)
		return;

	*out = proto->valid_triplets[rand() % proto->nr_triplets];
}

int sfg_default_bind(int fd, struct socket_triplet *triplet)
{
	const struct netproto *proto;
	struct sockaddr *addr = NULL;
	socklen_t addrlen = 0;
	int rv = -1;

	if (triplet->family >= TRINITY_PF_MAX)
		return -1;

	proto = net_protocols[triplet->family].proto;
	if (proto == NULL || proto->gen_sockaddr == NULL)
		return -1;

	proto->gen_sockaddr(&addr, &addrlen);
	if (addr == NULL)
		return -1;

	if (bind(fd, addr, addrlen) == 0)
		rv = 0;

	free(addr);
	return rv;
}

bool sfg_default_needs_listen_accept(struct socket_triplet *triplet)
{
	return triplet->type == SOCK_STREAM ||
	       triplet->type == SOCK_SEQPACKET;
}

void sfg_default_walk_setsockopts(int fd, struct socket_triplet *triplet,
				  unsigned int n)
{
	const struct netproto *proto;
	unsigned int i;

	if (triplet->family >= TRINITY_PF_MAX)
		return;

	proto = net_protocols[triplet->family].proto;
	if (proto == NULL || proto->setsockopt == NULL)
		return;

	for (i = 0; i < n; i++) {
		struct sockopt so = { 0, 0, 0, 0 };

		so.optval = (unsigned long) zmalloc(page_size);
		so.optlen = sockoptlen(0);
		proto->setsockopt(&so, triplet);
		(void) setsockopt(fd, so.level, so.optname,
				  (const void *) so.optval, so.optlen);
		free((void *) so.optval);
	}
}

void sfg_default_data_leg(int data_fd,
			  const struct socket_family_grammar *sfg,
			  struct socket_triplet *triplet)
{
	const struct netproto *proto;
	void *payload = NULL;
	size_t payload_len = 0;
	struct iovec iov;
	struct msghdr msg;
	unsigned char rcvbuf[256];
	unsigned char cmsgbuf[CMSG_SPACE(256)];

	if (triplet->family >= TRINITY_PF_MAX)
		return;

	proto = net_protocols[triplet->family].proto;
	if (proto != NULL && proto->gen_msg != NULL) {
		proto->gen_msg(triplet, &payload, &payload_len);
	} else {
		payload_len = 16 + (rand() % 64);
		payload = zmalloc(payload_len);
		generate_rand_bytes(payload, payload_len);
	}

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = payload;
	iov.iov_len  = payload_len;
	msg.msg_iov    = &iov;
	msg.msg_iovlen = 1;

	if (sfg->gen_cmsg != NULL) {
		memset(cmsgbuf, 0, sizeof(cmsgbuf));
		sfg->gen_cmsg(data_fd, triplet, &msg, cmsgbuf, sizeof(cmsgbuf));
	}

	(void) sendmsg(data_fd, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);
	(void) recv(data_fd, rcvbuf, sizeof(rcvbuf), MSG_DONTWAIT);

	if (payload != NULL)
		free(payload);
}

bool run_grammar_chain(const struct socket_family_grammar *sfg,
		       unsigned int *err_burst)
{
	struct socket_triplet triplet = { 0, 0, 0 };
	int parent_fd = -1, child_fd = -1;
	int data_fd;
	bool listening = false;
	bool ok = false;
	unsigned int n_setsockopts;
	bool (*needs_la)(struct socket_triplet *);

	__atomic_add_fetch(&shm->stats.socket_family_grammar_runs, 1,
			   __ATOMIC_RELAXED);

	if (sfg->can_run != NULL && !sfg->can_run()) {
		sfg_mark_unsupported(sfg->family);
		(*err_burst)++;
		goto out;
	}

	if (sfg->pick_triplet != NULL)
		sfg->pick_triplet(&triplet);
	else
		sfg_default_pick_triplet(sfg->family, &triplet);

	parent_fd = socket(triplet.family, triplet.type, triplet.protocol);
	if (parent_fd < 0) {
		if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
			sfg_mark_unsupported(sfg->family);
		(*err_burst)++;
		goto out;
	}

	if (sfg->configure_pre_bind != NULL)
		sfg->configure_pre_bind(parent_fd, &triplet);

	n_setsockopts = 2 + (rand() % 5);	/* 2..6 coordinated calls */
	if (sfg->walk_setsockopts != NULL)
		sfg->walk_setsockopts(parent_fd, &triplet, n_setsockopts);
	else
		sfg_default_walk_setsockopts(parent_fd, &triplet, n_setsockopts);

	if (sfg->bind_or_connect != NULL) {
		if (sfg->bind_or_connect(parent_fd, &triplet) < 0) {
			(*err_burst)++;
			goto out;
		}
	} else {
		if (sfg_default_bind(parent_fd, &triplet) < 0) {
			(*err_burst)++;
			goto out;
		}
	}

	if (sfg->configure_post_bind != NULL)
		sfg->configure_post_bind(parent_fd, &triplet);

	needs_la = sfg->needs_listen_accept != NULL ? sfg->needs_listen_accept
						    : sfg_default_needs_listen_accept;
	if (needs_la(&triplet)) {
		if (listen(parent_fd, 4) == 0) {
			child_fd = accept(parent_fd, NULL, NULL);
			listening = (child_fd >= 0);
		}
	}

	data_fd = listening ? child_fd : parent_fd;
	if (sfg->data_leg != NULL)
		sfg->data_leg(parent_fd, data_fd, &triplet);
	else
		sfg_default_data_leg(data_fd, sfg, &triplet);

	__atomic_add_fetch(&shm->stats.socket_family_grammar_completed, 1,
			   __ATOMIC_RELAXED);
	*err_burst = 0;
	ok = true;
out:
	if (child_fd >= 0)
		close(child_fd);
	if (parent_fd >= 0)
		close(parent_fd);
	return ok;
}
