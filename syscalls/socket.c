/*
 * SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)
 */
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "debug.h"
#include "net.h"
#include "params.h"
#include "domains.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"
#include "uid.h"
#include "utils.h"
#include "compat.h"

void rand_proto_type(struct socket_triplet *st)
{
	int types[] = { SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, SOCK_RDM, SOCK_SEQPACKET, SOCK_DCCP, SOCK_PACKET };

	st->protocol = RAND_ARRAY(types);
}

static bool do_priv(struct socket_triplet *st, const struct netproto *proto)
{
	if (proto->nr_privileged_triplets != 0) {
		int r;
		r = rnd() % proto->nr_privileged_triplets;
		st->protocol = proto->valid_privileged_triplets[r].protocol;
		st->type = proto->valid_privileged_triplets[r].type;
		return TRUE;
	}
	return FALSE;
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
				r = rnd() % proto->nr_triplets;
				st->protocol = proto->valid_triplets[r].protocol;
				st->type = proto->valid_triplets[r].type;
				return 0;
			}
		} else {
			if (do_priv(st, proto) == FALSE)
				goto do_unpriv;
		}
	}

	/* Couldn't find func, fall back to random. */
	return -1;
}

/* note: also called from sanitise_socketcall() */
void gen_socket_args(struct socket_triplet *st)
{
	if (do_specific_domain == TRUE)
		st->family = specific_domain;

	else {
		st->family = rnd() % TRINITY_PF_MAX;

		/*
		 * If we get a disabled family, try to find
		 * first next allowed.
		 */
		BUG_ON(st->family >= ARRAY_SIZE(no_domains));
		if (no_domains[st->family]) {
			st->family = find_next_enabled_domain(st->family);
			if (st->family == -1u) {
				outputerr("No available socket family found\n");
				exit(EXIT_FAILURE);
			}
		}
	}

	/* sometimes, still gen rand crap */
	if (ONE_IN(100)) {
		rand_proto_type(st);
		goto done;
	}

	/* otherwise.. sanitise based on the family. */
	if (sanitise_socket_triplet(st) < 0)
		rand_proto_type(st);	/* Couldn't find func, fall back to random. */


done:
	if (ONE_IN(4))
		st->type |= SOCK_CLOEXEC;
	if (ONE_IN(4))
		st->type |= SOCK_NONBLOCK;
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
	unsigned long family = rec->a1;
	int fd = rec->retval;

	if (fd == -1)
		return;

	proto = net_protocols[family].proto;
	if (proto != NULL)
		if (proto->socket_setup != NULL)
			proto->socket_setup(fd);

	// TODO: add socket to local cache
}

struct syscallentry syscall_socket = {
	.name = "socket",
	.num_args = 3,
	.arg1name = "family",
	.arg2name = "type",
	.arg3name = "protocol",
	.sanitise = sanitise_socket,
	.post = post_socket,
};
