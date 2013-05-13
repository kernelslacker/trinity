#ifndef _NET_H
#define _NET_H 1

#include <netinet/in.h>

extern unsigned int nr_sockets;
extern unsigned int specific_proto;
void open_sockets(void);
void find_specific_proto(const char *protoarg);
void generate_sockaddr(unsigned long *addr, unsigned long *addrlen, int pf);

/* glibc headers might be older than the kernel, so chances are we know
 * about more protocols than glibc does. So we define our own PF_MAX */
#define TRINITY_PF_MAX 41

#define TYPE_MAX 10
#define PROTO_MAX 256

#define PF_NOHINT (-1)

/* ipv4 */
in_addr_t random_ipv4_address(void);
void gen_ipv4(unsigned long *addr, unsigned long *addrlen);

/* ipv6 */
void gen_ipv6(unsigned long *addr, unsigned long *addrlen);

/* pppox */
void gen_pppox(unsigned long *addr, unsigned long *addrlen);

/* unix */
void gen_unixsock(unsigned long *addr, unsigned long *addrlen);

/* caif */
void gen_caif(unsigned long *addr, unsigned long *addrlen);

/* alg */
void gen_alg(unsigned long *addr, unsigned long *addrlen);

/* nfc */
void gen_nfc(unsigned long *addr, unsigned long *addrlen);

/* ax25 */
void gen_ax25(unsigned long *addr, unsigned long *addrlen);

/* ipx */
void gen_ipx(unsigned long *addr, unsigned long *addrlen);

/* appletalk */
void gen_appletalk(unsigned long *addr, unsigned long *addrlen);

/* atmpvc */
void gen_atmpvc(unsigned long *addr, unsigned long *addrlen);

/* x25 */
void gen_x25(unsigned long *addr, unsigned long *addrlen);

/* rose */
void gen_rose(unsigned long *addr, unsigned long *addrlen);

/* decnet */
void gen_decnet(unsigned long *addr, unsigned long *addrlen);

/* llc */
void gen_llc(unsigned long *addr, unsigned long *addrlen);

/* netlink */
void gen_netlink(unsigned long *addr, unsigned long *addrlen);

/* packet */
void gen_packet(unsigned long *addr, unsigned long *addrlen);

/* econet */
void gen_econet(unsigned long *addr, unsigned long *addrlen);

#endif	/* _NET_H */
