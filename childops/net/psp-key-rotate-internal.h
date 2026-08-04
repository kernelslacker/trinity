/*
 * psp-key-rotate-internal.h
 *
 * Shared declarations split out of childops/net/psp-key-rotate.c so that
 * the PSP netlink command builders, key lifecycle setup, traffic/race
 * loop, and devlink port churn sub-mode can each live in their own
 * translation unit and compile in parallel with the rest of the module.
 * This header is private to the sibling TUs that make up psp-key-rotate
 * -- do not include it from anywhere else.
 *
 * Contents:
 *   - the cross-TU macro budgets that the phases must keep in lock-step
 *     (outer-loop budget knobs, per-syscall timeout, wall-clock cap);
 *   - the shared per-process state promoted from file-static in the
 *     original monolithic psp-key-rotate.c to external linkage so the
 *     split phases can read/write it (the per-grandchild
 *     ns_unsupported_psp_key_rotate latch);
 *   - two small helpers as static inline so each sibling TU can call
 *     them at the same cost the original file-local functions had,
 *     without incurring any cross-TU indirect call or a duplicate
 *     definition;
 *   - forward declarations for the per-phase entry points, deliberately
 *     widened from file-static to external linkage so the top-level
 *     coordinator in psp-key-rotate.c can drive them across the TU
 *     boundary.
 *
 * The __has_include gate on <linux/genetlink.h>, <linux/if_link.h>, and
 * <linux/rtnetlink.h> lives in the including .c files -- this header is
 * only pulled in from the gated arm and never on the fallback-stub arm.
 */

#ifndef CHILDOPS_PSP_KEY_ROTATE_INTERNAL_H
#define CHILDOPS_PSP_KEY_ROTATE_INTERNAL_H

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include <linux/netlink.h>

#include "childops-genl.h"

/* Outer churn-loop budget knobs. */
#define PKR_OUTER_BASE			4U
#define PKR_OUTER_FLOOR			8U
#define PKR_OUTER_CAP			16U
#define PKR_WALL_CAP_NS			(200ULL * 1000ULL * 1000ULL)
#define PKR_TIMEO_MS			100

/*
 * Cross-TU state promoted from file-static in the monolithic
 * psp-key-rotate.c.  See the lifecycle comments at the definition in
 * the corresponding phase TU for the latching rules.
 *
 *   ns_unsupported_psp_key_rotate: per-grandchild latched gate.
 *     Inherited as false at grandchild fork time and flipped on the
 *     first config-absent rejection (genl_open of the PSP family,
 *     PSP_CMD_DEV_GET, or initial KEY_ROTATE) seen inside
 *     iter_one_in_ns().  Dies with the grandchild on _exit(); each
 *     subsequent grandchild re-discovers the latch in its own fresh
 *     netns.
 */
extern bool ns_unsupported_psp_key_rotate;

static inline void apply_timeouts(int s)
{
	struct timeval tv;

	tv.tv_sec  = 0;
	tv.tv_usec = PKR_TIMEO_MS * 1000;
	(void)setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	(void)setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static inline bool errno_is_unsupported(int e)
{
	return e == EPERM || e == ENOSYS || e == EOPNOTSUPP ||
	       e == ENOPROTOOPT || e == EAFNOSUPPORT ||
	       e == EPROTONOSUPPORT || e == ENODEV;
}

/*
 * Cross-TU phase entry points.  Each declaration widens its
 * definition's linkage from file-static (in the pre-carve monolithic
 * TU) to external so the top-level coordinator in psp-key-rotate.c can
 * call it across the TU boundary.  See the definition site for the
 * per-function contract.  struct timespec is forward-referenced so this
 * header does not need to pull in <time.h> transitively.
 */
struct timespec;
struct genl_ctx;

/* PSP netlink command builders -- psp-key-rotate-cmd.c */
int psp_key_rotate_cmd(struct genl_ctx *ctx, uint32_t dev_id);
int psp_tx_assoc_cmd(struct genl_ctx *ctx, uint32_t dev_id, int sockfd);
int psp_dev_get_probe(struct genl_ctx *ctx);

/* Key lifecycle -- psp-key-rotate-lifecycle.c */
struct nl_ctx;
int psp_key_rotate_iter_setup(struct nl_ctx *rtnl, unsigned long *dc);
int psp_key_rotate_iter_family_resolve(struct genl_ctx *psp_ctx,
				       uint32_t *dev_id_out,
				       unsigned long *dc);
int psp_key_rotate_iter_socket_install(struct genl_ctx *psp_ctx,
				       uint32_t dev_id,
				       unsigned long *dc);

/* Traffic + race loop -- psp-key-rotate-traffic.c */
void psp_key_rotate_iter_traffic(int sockfd,
				 struct genl_ctx *psp_ctx,
				 uint32_t dev_id,
				 const struct timespec *t_outer,
				 unsigned long *dc);
void psp_key_rotate_iter_teardown(unsigned int iter_idx, int sockfd,
				  struct genl_ctx *psp_ctx,
				  struct nl_ctx *rtnl,
				  unsigned long *dc);

/* devlink port churn sub-mode -- psp-key-rotate-devlink-port.c */
extern bool ns_unsupported_psp_devlink_port;
void iter_devlink_port_churn(unsigned int iter_idx,
			     const struct timespec *t_outer);

#endif /* CHILDOPS_PSP_KEY_ROTATE_INTERNAL_H */
