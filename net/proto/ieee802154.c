#include <sys/socket.h>
#include <stdint.h>
#include "net.h"
#include "random.h"
#include "compat.h"
#include "rnd.h"
#include "utils.h"

/*
 * No userspace UAPI ships <linux/ieee802154.h> with the sockaddr layout
 * (the kernel keeps it in include/net/af_ieee802154.h).  Mirror the
 * on-the-wire layout the kernel reads at the bind/connect/sendmsg
 * boundary so glibc-only build hosts work.
 */
#define TRINITY_IEEE802154_ADDR_NONE	0x0
#define TRINITY_IEEE802154_ADDR_SHORT	0x2
#define TRINITY_IEEE802154_ADDR_LONG	0x3
#define TRINITY_IEEE802154_ADDR_LEN	8

struct trinity_ieee802154_addr_sa {
	int		addr_type;
	uint16_t	pan_id;
	union {
		uint8_t		hwaddr[TRINITY_IEEE802154_ADDR_LEN];
		uint16_t	short_addr;
	};
};

struct trinity_sockaddr_ieee802154 {
	sa_family_t			family;
	struct trinity_ieee802154_addr_sa addr;
};

static void ieee802154_gen_sockaddr(__unused__ struct socket_triplet *triplet,
				    struct sockaddr **addr, socklen_t *addrlen)
{
	struct trinity_sockaddr_ieee802154 *sa;

	sa = zmalloc_tracked(sizeof(*sa));
	sa->family = AF_IEEE802154;
	sa->addr.pan_id = rnd_u32() & 0xffff;

	switch (rnd_modulo_u32(3)) {
	case 0:
		sa->addr.addr_type = TRINITY_IEEE802154_ADDR_NONE;
		break;
	case 1:
		sa->addr.addr_type = TRINITY_IEEE802154_ADDR_SHORT;
		sa->addr.short_addr = rnd_u32() & 0xffff;
		break;
	default:
		sa->addr.addr_type = TRINITY_IEEE802154_ADDR_LONG;
		generate_rand_bytes(sa->addr.hwaddr, TRINITY_IEEE802154_ADDR_LEN);
		break;
	}

	*addr = (struct sockaddr *) sa;
	*addrlen = sizeof(*sa);
}

static struct socket_triplet ieee802154_triplets[] = {
	{ .family = PF_IEEE802154, .protocol = 0, .type = SOCK_DGRAM },
	{ .family = PF_IEEE802154, .protocol = 0, .type = SOCK_RAW },
};

const struct netproto proto_ieee802154 = {
	.name = "ieee802154",
	.gen_sockaddr = ieee802154_gen_sockaddr,
	.valid_triplets = ieee802154_triplets,
	.nr_triplets = ARRAY_SIZE(ieee802154_triplets),
};
