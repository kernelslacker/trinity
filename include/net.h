#pragma once

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "fd.h"
#include "syscall.h"
#include "socketinfo.h"

extern unsigned int nr_sockets;

/* protocol decoding */
extern unsigned int specific_domain;

/* glibc headers might be older than the kernel, so chances are we know
 * about more protocols than glibc does. So we define our own PF_MAX */
#define TRINITY_PF_MAX 45

#define PF_NOHINT (-1)

struct sock_option {
	const unsigned int name;
	const unsigned int len;
};

struct sockopt {
	unsigned int level;
	unsigned long optname;
	unsigned long optval;
	unsigned long optlen;
};

struct netproto {
	const char *name;
	struct socket_triplet *valid_triplets;
	struct socket_triplet *valid_privileged_triplets;
	void (*socket_setup)(int fd);
	void (*setsockopt)(struct sockopt *so, struct socket_triplet *triplet);
	void (*gen_sockaddr)(struct sockaddr **addr, socklen_t *addrlen);
	void (*gen_packet)(struct socket_triplet *st, void **ptr, size_t *len);
	unsigned int nr_triplets;
	unsigned int nr_privileged_triplets;
};

struct protoptr {
	const struct netproto *proto;
};
extern const struct protoptr net_protocols[TRINITY_PF_MAX];

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

extern const struct netproto proto_ipv4;
extern const struct netproto proto_inet6;
extern const struct netproto proto_pppol2tp;
extern const struct netproto proto_unix;
extern const struct netproto proto_caif;
extern const struct netproto proto_alg;
extern const struct netproto proto_nfc;
extern const struct netproto proto_ax25;
extern const struct netproto proto_ipx;
extern const struct netproto proto_appletalk;
extern const struct netproto proto_atmpvc;
extern const struct netproto proto_atmsvc;
extern const struct netproto proto_x25;
extern const struct netproto proto_rose;
extern const struct netproto proto_llc;
extern const struct netproto proto_netlink;
extern const struct netproto proto_packet;
extern const struct netproto proto_econet;
extern const struct netproto proto_irda;
extern const struct netproto proto_can;
extern const struct netproto proto_tipc;
extern const struct netproto proto_phonet;
extern const struct netproto proto_rds;
extern const struct netproto proto_bluetooth;
extern const struct netproto proto_netrom;
extern const struct netproto proto_netbeui;
extern const struct netproto proto_iucv;
extern const struct netproto proto_rxrpc;
extern const struct netproto proto_phonet;
extern const struct netproto proto_kcm;
extern const struct netproto proto_qipcrtr;
extern const struct netproto proto_smc;
extern const struct netproto proto_xdp;

/* bpf */
void bpf_gen_filter(unsigned long **addr, unsigned long *addrlen);
void bpf_gen_seccomp(unsigned long **addr, unsigned long *addrlen);

/* ip setsockopt functions */
void tcp_setsockopt(struct sockopt *so, struct socket_triplet *triplet);
void udp_setsockopt(struct sockopt *so, struct socket_triplet *triplet);
void udplite_setsockopt(struct sockopt *so, struct socket_triplet *triplet);
void icmpv6_setsockopt(struct sockopt *so, struct socket_triplet *triplet);
void sctp_setsockopt(struct sockopt *so, struct socket_triplet *triplet);
void raw_setsockopt(struct sockopt *so, struct socket_triplet *triplet);
void dccp_setsockopt(struct sockopt *so, struct socket_triplet *triplet);
