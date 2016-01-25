#pragma once

#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <netinet/in.h>

#include "fd.h"
#include "socketinfo.h"

#define NR_SOCKET_FDS 375

extern unsigned int nr_sockets;

/* protocol decoding */
extern unsigned int specific_domain;

extern int server_port;
extern char server_addr[INET6_ADDRSTRLEN];

/* glibc headers might be older than the kernel, so chances are we know
 * about more protocols than glibc does. So we define our own PF_MAX */
#define TRINITY_PF_MAX 41

#define TYPE_MAX 10
#define PROTO_MAX 256

#define PF_NOHINT (-1)

struct sock_option {
	unsigned int name;
	unsigned int len;
};

struct sockopt {
	unsigned int level;
	unsigned long optname;
	unsigned long optval;
	unsigned long optlen;
};

struct netproto {
	const char *name;
	void (*socket)(struct socket_triplet *st);
	void (*setsockopt)(struct sockopt *so, struct socket_triplet *triplet);
	void (*gen_sockaddr)(struct sockaddr **addr, socklen_t *addrlen);
};

struct protoptr {
	struct netproto *proto;
};
extern const struct protoptr net_protocols[PF_MAX];

const struct fd_provider socket_fd_provider;

struct socketinfo * get_rand_socketinfo(void);
int fd_from_socketinfo(struct socketinfo *si);

void generate_sockaddr(struct sockaddr **addr, socklen_t *addrlen, int pf);

unsigned int sockoptlen(unsigned int len);
void do_setsockopt(struct sockopt *so, struct socket_triplet *triplet);

void rand_proto_type(struct socket_triplet *st);
int sanitise_socket_triplet(struct socket_triplet *st);
void gen_socket_args(struct socket_triplet *st);

/* Ethernet */
int get_random_ether_type(void);

/* ipv4 */
in_addr_t random_ipv4_address(void);

extern struct netproto proto_ipv4;
extern struct netproto proto_inet6;
extern struct netproto proto_pppol2tp;
extern struct netproto proto_unix;
extern struct netproto proto_caif;
extern struct netproto proto_alg;
extern struct netproto proto_nfc;
extern struct netproto proto_ax25;
extern struct netproto proto_ipx;
extern struct netproto proto_appletalk;
extern struct netproto proto_atmpvc;
extern struct netproto proto_atmsvc;
extern struct netproto proto_x25;
extern struct netproto proto_rose;
extern struct netproto proto_decnet;
extern struct netproto proto_llc;
extern struct netproto proto_netlink;
extern struct netproto proto_packet;
extern struct netproto proto_econet;
extern struct netproto proto_irda;
extern struct netproto proto_can;
extern struct netproto proto_tipc;
extern struct netproto proto_phonet;
extern struct netproto proto_rds;
extern struct netproto proto_bluetooth;
extern struct netproto proto_netrom;
extern struct netproto proto_netbeui;
extern struct netproto proto_iucv;
extern struct netproto proto_rxrpc;
extern struct netproto proto_phonet;

/* bpf */
void bpf_gen_filter(unsigned long **addr, unsigned long *addrlen);
void bpf_gen_seccomp(unsigned long **addr, unsigned long *addrlen);

/* ip setsockopt functions */
void socket_setsockopt(struct sockopt *so, struct socket_triplet *triplet);
void tcp_setsockopt(struct sockopt *so, struct socket_triplet *triplet);
void udp_setsockopt(struct sockopt *so, struct socket_triplet *triplet);
void udplite_setsockopt(struct sockopt *so, struct socket_triplet *triplet);
void icmpv6_setsockopt(struct sockopt *so, struct socket_triplet *triplet);
void sctp_setsockopt(struct sockopt *so, struct socket_triplet *triplet);
void raw_setsockopt(struct sockopt *so, struct socket_triplet *triplet);
void dccp_setsockopt(struct sockopt *so, struct socket_triplet *triplet);


/* protocol definitions */
#define SOL_TCP 6
#define SOL_SCTP 132
#define SOL_UDPLITE 136
#define SOL_NETBEUI 267
#define SOL_LLC 268
#define SOL_DCCP 269
#define SOL_NETLINK 270
#define SOL_RXRPC 272
#define SOL_PPPOL2TP 273
#define SOL_BLUETOOTH 274
#define SOL_PNPIPE 275
#define SOL_RDS 276
#define SOL_IUCV 277
#define SOL_CAIF 278
#define SOL_ALG 279
#define SOL_NFC 280

#ifndef AF_IB
#define AF_IB 27
#define PF_IB 27
#endif
#ifndef AF_MPLS
#define AF_MPLS 28
#define PF_MPLS 28
#endif
