#ifndef _NET_H
#define _NET_H 1

extern unsigned int nr_sockets;
extern unsigned int specific_proto;
void open_sockets(void);
void find_specific_proto(const char *protoarg);
/* glibc headers might be older than the kernel, so chances are we know
 * about more protocols than glibc does. So we define our own PF_MAX */
#define TRINITY_PF_MAX 41

#define TYPE_MAX 10
#define PROTO_MAX 256

#endif	/* _NET_H */
