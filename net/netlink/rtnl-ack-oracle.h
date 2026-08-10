#ifndef NET_NETLINK_RTNL_ACK_ORACLE_H
#define NET_NETLINK_RTNL_ACK_ORACLE_H

#include <stddef.h>

/*
 * rtnl_oracle_sample - called from netlink_gen_msg() after build_one_nlmsg()
 * returns the final (possibly nlmsg_len-corrupted) buffer.
 *
 * On 1-in-RTNL_ACK_ORACLE_SAMPLE_RATE calls it ORs NLM_F_ACK into the
 * nlmsghdr flags in-place and marks internal state so rtnl_oracle_drain()
 * knows to recv after the real sendmsg completes.  No private socket is
 * opened; no send occurs here.
 *
 * @nlmsg_type: the RTM_* type of the first nlmsghdr (before any
 *   nlmsg_len corruption arm fires).
 * @msg:        the generated message buffer; must be at least
 *              NLMSG_HDRLEN bytes long.
 */
void rtnl_oracle_sample(unsigned short nlmsg_type, unsigned char *msg);

/*
 * rtnl_oracle_drain - called from the proto->post_send hook after the
 * real sendmsg syscall has returned.
 *
 * If rtnl_oracle_sample() marked this message for sampling it performs
 * up to RTNL_ACK_ORACLE_DRAIN_MAX MSG_DONTWAIT recvs on @fd looking for
 * NLMSG_ERROR, then classifies the kernel's verdict into the per-outcome
 * histogram in shm->stats.rtnl_ack_oracle.  Returns immediately (< 1 us)
 * if the message was not sampled.
 *
 * @fd: the fuzz socket file descriptor on which sendmsg was just called.
 */
void rtnl_oracle_drain(int fd);

#endif /* NET_NETLINK_RTNL_ACK_ORACLE_H */
