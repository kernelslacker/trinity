#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "compat.h"

#define PF_KEY_V2	2

/* SADB message types */
#define SADB_GETSPI		1
#define SADB_UPDATE		2
#define SADB_ADD		3
#define SADB_DELETE		4
#define SADB_GET		5
#define SADB_REGISTER		7
#define SADB_FLUSH		9
#define SADB_DUMP		10
#define SADB_X_PROMISC		11
#define SADB_X_SPDADD		13
#define SADB_X_SPDFLUSH		17

/* SA types */
#define SADB_SATYPE_AH		2
#define SADB_SATYPE_ESP		3
#define SADB_X_SATYPE_IPCOMP	9

struct sadb_msg {
	__u8  sadb_msg_version;
	__u8  sadb_msg_type;
	__u8  sadb_msg_errno;
	__u8  sadb_msg_satype;
	__u16 sadb_msg_len;
	__u16 sadb_msg_reserved;
	__u32 sadb_msg_seq;
	__u32 sadb_msg_pid;
};

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
