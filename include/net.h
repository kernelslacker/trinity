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

/* ipv4 */
in_addr_t random_ipv4_address(void);
void gen_ipv4(unsigned long *addr, unsigned long *addrlen);
void inet_rand_socket(struct proto_type *pt);

/* ipv6 */
void gen_ipv6(unsigned long *addr, unsigned long *addrlen);
void inet6_rand_socket(struct proto_type *pt);

/* pppox */
void gen_pppox(unsigned long *addr, unsigned long *addrlen);

/* unix */
void gen_unixsock(unsigned long *addr, unsigned long *addrlen);

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

/* rose */
void gen_rose(unsigned long *addr, unsigned long *addrlen);

/* decnet */
void gen_decnet(unsigned long *addr, unsigned long *addrlen);
void decnet_rand_socket(struct proto_type *pt);

/* llc */
void gen_llc(unsigned long *addr, unsigned long *addrlen);

/* netlink */
void gen_netlink(unsigned long *addr, unsigned long *addrlen);

/* packet */
void gen_packet(unsigned long *addr, unsigned long *addrlen);

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

/* phonet */
void gen_phonet(unsigned long *addr, unsigned long *addrlen);

/* setsockopt routines */
void ip_setsockopt(int childno);

#endif	/* _NET_H */
