#ifndef _NET_H
#define _NET_H 1

#include <netinet/in.h>

extern unsigned int nr_sockets;
void open_sockets(void);
void generate_sockaddr(unsigned long *addr, unsigned long *addrlen, int pf);

/* protocol decoding */
extern unsigned int specific_proto;
const char * get_proto_name(unsigned int proto);
void find_specific_proto(const char *protoarg);


/* glibc headers might be older than the kernel, so chances are we know
 * about more protocols than glibc does. So we define our own PF_MAX */
#define TRINITY_PF_MAX 41

#define TYPE_MAX 10
#define PROTO_MAX 256

#define PF_NOHINT (-1)

struct proto_type {
	unsigned int protocol;
	unsigned int type;
};

struct sockopt {
	unsigned int level;
	unsigned long optname;
	unsigned long optval;
	unsigned long optlen;
};

/* ipv4 */
in_addr_t random_ipv4_address(void);
void gen_ipv4(unsigned long *addr, unsigned long *addrlen);
void inet_rand_socket(struct proto_type *pt);
void ip_setsockopt(struct sockopt *so);

/* ipv6 */
void gen_ipv6(unsigned long *addr, unsigned long *addrlen);
void inet6_rand_socket(struct proto_type *pt);

/* pppox */
void gen_pppox(unsigned long *addr, unsigned long *addrlen);

/* unix */
void gen_unixsock(unsigned long *addr, unsigned long *addrlen);
void unix_rand_socket(struct proto_type *pt);

/* bpf */
void gen_bpf(unsigned long *addr, unsigned long *addrlen);
void gen_seccomp_bpf(unsigned long *addr, unsigned long *addrlen);

/* caif */
void gen_caif(unsigned long *addr, unsigned long *addrlen);
void caif_rand_socket(struct proto_type *pt);

/* alg */
void gen_alg(unsigned long *addr, unsigned long *addrlen);

/* nfc */
void gen_nfc(unsigned long *addr, unsigned long *addrlen);
void nfc_rand_socket(struct proto_type *pt);

/* ax25 */
void gen_ax25(unsigned long *addr, unsigned long *addrlen);
void ax25_rand_socket(struct proto_type *pt);

/* ipx */
void gen_ipx(unsigned long *addr, unsigned long *addrlen);
void ipx_rand_socket(struct proto_type *pt);

/* appletalk */
void gen_appletalk(unsigned long *addr, unsigned long *addrlen);
void appletalk_rand_socket(struct proto_type *pt);

/* atm */
void gen_atmpvc(unsigned long *addr, unsigned long *addrlen);
void gen_atmsvc(unsigned long *addr, unsigned long *addrlen);

/* x25 */
void gen_x25(unsigned long *addr, unsigned long *addrlen);
void x25_rand_socket(struct proto_type *pt);

/* rose */
void gen_rose(unsigned long *addr, unsigned long *addrlen);

/* decnet */
void gen_decnet(unsigned long *addr, unsigned long *addrlen);
void decnet_rand_socket(struct proto_type *pt);

/* llc */
void gen_llc(unsigned long *addr, unsigned long *addrlen);
void llc_rand_socket(struct proto_type *pt);

/* netlink */
void gen_netlink(unsigned long *addr, unsigned long *addrlen);
void netlink_rand_socket(struct proto_type *pt);

/* packet */
void gen_packet(unsigned long *addr, unsigned long *addrlen);
void packet_rand_socket(struct proto_type *pt);

/* econet */
void gen_econet(unsigned long *addr, unsigned long *addrlen);

/* irda */
void gen_irda(unsigned long *addr, unsigned long *addrlen);
void irda_rand_socket(struct proto_type *pt);

/* can */
void gen_can(unsigned long *addr, unsigned long *addrlen);
void can_rand_socket(struct proto_type *pt);

/* tipc */
void gen_tipc(unsigned long *addr, unsigned long *addrlen);
void tipc_rand_socket(struct proto_type *pt);

/* phonet */
void gen_phonet(unsigned long *addr, unsigned long *addrlen);
void phonet_rand_socket(struct proto_type *pt);

/* rds */
void rds_rand_socket(struct proto_type *pt);

/* setsockopt functions */
void socket_setsockopt(struct sockopt *so);
void tcp_setsockopt(struct sockopt *so);
void udp_setsockopt(struct sockopt *so);
void inet6_setsockopt(struct sockopt *so);
void icmpv6_setsockopt(struct sockopt *so);
void sctp_setsockopt(struct sockopt *so);
void udplite_setsockopt(struct sockopt *so);
void raw_setsockopt(struct sockopt *so);
void ipx_setsockopt(struct sockopt *so);
void ax25_setsockopt(struct sockopt *so);
void atalk_setsockopt(struct sockopt *so);
void netrom_setsockopt(struct sockopt *so);
void rose_setsockopt(struct sockopt *so);
void decnet_setsockopt(struct sockopt *so);
void x25_setsockopt(struct sockopt *so);
void packet_setsockopt(struct sockopt *so);
void atm_setsockopt(struct sockopt *so);
void aal_setsockopt(struct sockopt *so);
void irda_setsockopt(struct sockopt *so);
void netbeui_setsockopt(struct sockopt *so);
void llc_setsockopt(struct sockopt *so);
void dccp_setsockopt(struct sockopt *so);
void netlink_setsockopt(struct sockopt *so);
void tipc_setsockopt(struct sockopt *so);
void rxrpc_setsockopt(struct sockopt *so);
void pppol2tp_setsockopt(struct sockopt *so);
void bluetooth_setsockopt(struct sockopt *so);
void pnpipe_setsockopt(struct sockopt *so);
void rds_setsockopt(struct sockopt *so);
void iucv_setsockopt(struct sockopt *so);
void caif_setsockopt(struct sockopt *so);
void alg_setsockopt(struct sockopt *so);
void nfc_setsockopt(struct sockopt *so);

#endif	/* _NET_H */
