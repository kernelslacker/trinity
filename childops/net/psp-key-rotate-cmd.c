/*
 * psp-key-rotate-cmd - PSP genetlink command builders carved out of
 * childops/net/psp-key-rotate.c.  Owns the three request wire builders
 * that the lifecycle setup, the traffic/race loop, and the devlink
 * port-churn sub-mode all issue:
 *
 *   psp_key_rotate_cmd    - PSP_CMD_KEY_ROTATE (rotate the active key
 *                           generation on a psp_dev);
 *   psp_tx_assoc_cmd      - PSP_CMD_TX_ASSOC (bind a TCP socket fd to
 *                           the current generation on a psp_dev, both
 *                           the initial bind and the mid-flow "spi
 *                           switch" re-bind);
 *   psp_dev_get_probe     - PSP_CMD_DEV_GET (dev enumeration probe,
 *                           consumed for its reply not its payload).
 *
 * Each is a straight PUT + nla_put_* + genl_send_recv fragment against
 * the shared PSP genetlink family context; they never touch the
 * per-grandchild latch or any file-static state and can be called from
 * any of the sibling TUs.
 */

#if __has_include(<linux/genetlink.h>) && \
	__has_include(<linux/if_link.h>) && \
	__has_include(<linux/rtnetlink.h>)

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <linux/genetlink.h>
#include <linux/netlink.h>

#include "childops-genl.h"

#include "kernel/psp.h"

#include "psp-key-rotate-internal.h"

/* Issue PSP_CMD_KEY_ROTATE for @dev_id.  Returns 0 on success, -errno
 * (or -EIO on send/recv failure) otherwise. */
int psp_key_rotate_cmd(struct genl_ctx *ctx, uint32_t dev_id)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	size_t off;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx,
			   nl_seq_next(&ctx->nl),
			   PSP_CMD_KEY_ROTATE, 0);
	if (!off)
		return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf), PSP_A_DEV_ID, dev_id);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (uint32_t)off;
	return genl_send_recv(ctx, buf, off);
}

/* Issue PSP_CMD_TX_ASSOC binding @sockfd to @dev_id.  Returns 0 on
 * success, -errno on failure.  Mid-flow re-issue is the "spi switch"
 * path under spec naming. */
int psp_tx_assoc_cmd(struct genl_ctx *ctx,
		     uint32_t dev_id, int sockfd)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	size_t off;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx,
			   nl_seq_next(&ctx->nl),
			   PSP_CMD_TX_ASSOC, 0);
	if (!off)
		return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf), PSP_A_ASSOC_DEV_ID, dev_id);
	if (!off)
		return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf), PSP_A_ASSOC_VERSION, 0U);
	if (!off)
		return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf),
			  PSP_A_ASSOC_SOCK_FD, (uint32_t)sockfd);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (uint32_t)off;
	return genl_send_recv(ctx, buf, off);
}

/* Issue a single PSP_CMD_DEV_GET on @ctx as a structural probe; the
 * reply is consumed but not parsed.  Returns the underlying
 * genl_send_recv() rc. */
int psp_dev_get_probe(struct genl_ctx *ctx)
{
	unsigned char buf[NLMSG_HDRLEN + GENL_HDRLEN];
	struct nlmsghdr *nlh;
	size_t off;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx,
			   nl_seq_next(&ctx->nl),
			   PSP_CMD_DEV_GET, 0);
	if (!off)
		return -EIO;
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (uint32_t)off;
	return genl_send_recv(ctx, buf, off);
}

#endif /* __has_include gate matches psp-key-rotate.c */
