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
 * rtnl_oracle_abort - cancel a pending sample on a path that cannot drain.
 *
 * Called when gen_msg was taken but post_send will never run (e.g. the
 * grammar-path bare sendmsg in sfg_default_data_leg).  Undoes the in-place
 * NLM_F_ACK annotation and rolls the sampling counter back so the budget
 * slot is not wasted on a non-drainable path.  No-ops if not active.
 */
void rtnl_oracle_abort(void);

/*
 * rtnl_oracle_drain - called from the proto->post_send hook after the
 * real sendmsg syscall has returned.
 *
 * If rtnl_oracle_sample() marked this message for sampling it performs
 * up to RTNL_ACK_ORACLE_DRAIN_MAX MSG_DONTWAIT|MSG_TRUNC recv() calls on
 * @fd.  Each datagram may contain multiple messages; every message is
 * walked with NLMSG_OK/NLMSG_NEXT looking for NLMSG_ERROR, then the
 * kernel's verdict is classified into the per-outcome histogram in
 * shm->stats.rtnl_ack_oracle.  Returns immediately (< 1 us) if the
 * message was not sampled.
 *
 * @fd:      the fuzz socket fd on which sendmsg was just called.
 * @send_ok: 1 if sendmsg returned >= 0 (message reached kernel),
 *           0 if sendmsg returned -1 (failure before the message left
 *           userspace); the latter increments send_fail without recv.
 */
void rtnl_oracle_drain(int fd, int send_ok);

#endif /* NET_NETLINK_RTNL_ACK_ORACLE_H */
