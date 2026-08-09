#ifndef NET_NETLINK_RTNL_ACK_ORACLE_H
#define NET_NETLINK_RTNL_ACK_ORACLE_H

#include <stddef.h>

/*
 * rtnl_ack_oracle_probe - send msg_buf on a private NETLINK_ROUTE socket
 * with NLM_F_ACK forced and record the kernel's NLMSG_ERROR verdict in
 * shm->stats.rtnl_ack_oracle.  See net/netlink/rtnl-ack-oracle.c for
 * the full design rationale.
 */
void rtnl_ack_oracle_probe(unsigned short nlmsg_type,
			   const void *msg_buf, size_t msg_len);

#endif /* NET_NETLINK_RTNL_ACK_ORACLE_H */
