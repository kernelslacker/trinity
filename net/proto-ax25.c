#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netax25/ax25.h>
#include "net.h"
#include "random.h"
#include "utils.h"	// RAND_ARRAY
#include "compat.h"

static void ax25_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_ax25 *ax25;

	ax25 = zmalloc(sizeof(struct sockaddr_ax25));

	ax25->sax25_family = PF_AX25;
	generate_rand_bytes((unsigned char *) ax25->sax25_call.ax25_call, 7);
	ax25->sax25_ndigis = rnd();
	*addr = (struct sockaddr *) ax25;
	*addrlen = sizeof(struct sockaddr_ax25);
}

#define NR_AX25_PROTOS 13
static int ax25_protocols[NR_AX25_PROTOS] = {
	0x01,   /* ROSE */
	0x06,   /* Compressed TCP/IP packet   *//* Van Jacobsen (RFC 1144)    */
	0x07,   /* Uncompressed TCP/IP packet *//* Van Jacobsen (RFC 1144)    */
	0x08,   /* Segmentation fragment      */
	0xc3,   /* TEXTNET datagram protocol  */
	0xc4,   /* Link Quality Protocol      */
	0xca,   /* Appletalk                  */
	0xcb,   /* Appletalk ARP              */
	0xcc,   /* ARPA Internet Protocol     */
	0xcd,   /* ARPA Address Resolution    */
	0xce,   /* FlexNet                    */
	0xcf,   /* NET/ROM                    */
	0xF0    /* No layer 3 protocol impl.  */
};

static void ax25_rand_socket(struct socket_triplet *st)
{
	switch (rnd() % 3) {
	case 0: st->type = SOCK_DGRAM;
		st->protocol = 0;
		break;
	case 1: st->type = SOCK_SEQPACKET;
		st->protocol = ax25_protocols[rnd() % NR_AX25_PROTOS];
		break;
	case 2: st->type = SOCK_RAW;
		break;
	default:break;
	}
}

static const unsigned int ax25_opts[] = {
	AX25_WINDOW, AX25_T1, AX25_N2, AX25_T3,
	AX25_T2, AX25_BACKOFF, AX25_EXTSEQ, AX25_PIDINCL,
	AX25_IDLE, AX25_PACLEN, AX25_IAMDIGI,
	SO_BINDTODEVICE
};

static void ax25_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_AX25;
	so->optname = RAND_ARRAY(ax25_opts);
}

#define AX25_P_ROSE 1
#define AX25_P_NETROM 0xcf

static struct socket_triplet ax25_triplets[] = {
	{ .family = PF_AX25, .protocol = 0, .type = SOCK_DGRAM },
	{ .family = PF_AX25, .protocol = 0, .type = SOCK_RAW },
	{ .family = PF_AX25, .protocol = 0, .type = SOCK_SEQPACKET },
	{ .family = PF_AX25, .protocol = AX25_P_ROSE, .type = SOCK_SEQPACKET },
	{ .family = PF_AX25, .protocol = AX25_P_NETROM, .type = SOCK_SEQPACKET },
};

const struct netproto proto_ax25 = {
	.name = "ax25",
	.socket = ax25_rand_socket,
	.setsockopt = ax25_setsockopt,
	.gen_sockaddr = ax25_gen_sockaddr,
	.valid_triplets = ax25_triplets,
	.nr_triplets = ARRAY_SIZE(ax25_triplets),
};
