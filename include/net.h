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

#endif	/* _NET_H */
