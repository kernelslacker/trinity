#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <linux/pfkeyv2.h>
#include "net.h"
#include "random.h"
#include "compat.h"

static void key_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr *sa;

	sa = zmalloc(sizeof(struct sockaddr));
	sa->sa_family = AF_KEY;

	*addr = sa;
	*addrlen = sizeof(struct sockaddr);
}

static void key_gen_msg(__unused__ struct socket_triplet *triplet, void **buf, size_t *len)
{
	static const __u8 types[] = {
		SADB_GETSPI, SADB_UPDATE, SADB_ADD, SADB_DELETE,
		SADB_GET, SADB_REGISTER, SADB_FLUSH, SADB_DUMP,
		SADB_X_PROMISC, SADB_X_SPDADD, SADB_X_SPDFLUSH,
	};
	static const __u8 satypes[] = {
		SADB_SATYPE_AH, SADB_SATYPE_ESP, SADB_X_SATYPE_IPCOMP,
	};
	struct sadb_msg *msg;

	msg = zmalloc(sizeof(struct sadb_msg));
	msg->sadb_msg_version = PF_KEY_V2;
	msg->sadb_msg_type = RAND_ARRAY(types);
	msg->sadb_msg_satype = RAND_ARRAY(satypes);
	msg->sadb_msg_len = sizeof(struct sadb_msg) / 8;
	msg->sadb_msg_seq = rand();
	msg->sadb_msg_pid = 0;

	*buf = msg;
	*len = sizeof(struct sadb_msg);
}

static struct socket_triplet key_triplets[] = {
	{ .family = PF_KEY, .protocol = PF_KEY_V2, .type = SOCK_RAW },
};

const struct netproto proto_key = {
	.name = "key",
	.gen_sockaddr = key_gen_sockaddr,
	.gen_msg = key_gen_msg,
	.valid_triplets = key_triplets,
	.nr_triplets = ARRAY_SIZE(key_triplets),
};
