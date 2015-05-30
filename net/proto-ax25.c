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

void ax25_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_ax25 *ax25;

	ax25 = zmalloc(sizeof(struct sockaddr_ax25));

	ax25->sax25_family = PF_AX25;
	generate_rand_bytes((unsigned char *) ax25->sax25_call.ax25_call, 7);
	ax25->sax25_ndigis = rand();
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

void ax25_rand_socket(struct socket_triplet *st)
{
	switch (rand() % 3) {
	case 0: st->type = SOCK_DGRAM;
		st->protocol = 0;
		break;
	case 1: st->type = SOCK_SEQPACKET;
		st->protocol = ax25_protocols[rand() % NR_AX25_PROTOS];
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

void ax25_setsockopt(struct sockopt *so)
{
	unsigned char val;

	val = RAND_ARRAY(ax25_opts);
	so->optname = ax25_opts[val];
}
