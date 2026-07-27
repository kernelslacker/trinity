/*
 * pkt-builder delivery dispatcher.
 *
 * Carved out of pkt-builder.c so the main file stays focused on the
 * manifest table and public push/emit surface.  The delivery paths
 * (AF_PACKET, raw IPv4/IPv6, loopback UDP) and the per-frame skip
 * calculation live here; the public API contract is unchanged
 * (pktb_ctx_init / pktb_ctx_close / pktb_deliver stay declared in
 * include/pkt-builder.h).
 */

#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include "pkt-builder.h"
#include "pkt-builder-internal.h"

/*
 * ==== Delivery =========================================================
 */

void pktb_ctx_init(struct pktb_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->af_packet_fd   = -1;
	ctx->raw_ipv4_fd    = -1;
	ctx->raw_ipv6_fd    = -1;
	ctx->loopback_udp_fd = -1;
	ctx->lo_ifindex     = 0;
}

void pktb_ctx_close(struct pktb_ctx *ctx)
{
	if (ctx->af_packet_fd >= 0)   { close(ctx->af_packet_fd);   ctx->af_packet_fd = -1; }
	if (ctx->raw_ipv4_fd >= 0)    { close(ctx->raw_ipv4_fd);    ctx->raw_ipv4_fd = -1; }
	if (ctx->raw_ipv6_fd >= 0)    { close(ctx->raw_ipv6_fd);    ctx->raw_ipv6_fd = -1; }
	if (ctx->loopback_udp_fd >= 0){ close(ctx->loopback_udp_fd); ctx->loopback_udp_fd = -1; }
}

static int ensure_lo_ifindex(struct pktb_ctx *ctx)
{
	unsigned int idx;

	if (ctx->lo_ifindex > 0)
		return ctx->lo_ifindex;
	idx = if_nametoindex("lo");
	if (idx == 0)
		idx = 1;
	ctx->lo_ifindex = (int)idx;
	return ctx->lo_ifindex;
}

static int deliver_af_packet(struct pktb_ctx *ctx, const struct pktb_frame *f)
{
	struct sockaddr_ll sll;
	ssize_t rc;

	if (ctx->af_packet_fd < 0) {
		int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC,
				htons(ETH_P_ALL));
		if (fd < 0) {
			ctx->disabled = true;
			return -3;
		}
		ctx->af_packet_fd = fd;
	}
	if (ensure_lo_ifindex(ctx) <= 0)
		return -1;

	memset(&sll, 0, sizeof(sll));
	sll.sll_family   = AF_PACKET;
	sll.sll_ifindex  = ctx->lo_ifindex;
	sll.sll_halen    = 6;
	memcpy(sll.sll_addr, f->dst_mac, 6);

	rc = sendto(ctx->af_packet_fd, f->buf, f->len, 0,
		    (struct sockaddr *)&sll, sizeof(sll));
	return rc > 0 ? (int)rc : -1;
}

static int deliver_raw_ipv4(struct pktb_ctx *ctx, const struct pktb_frame *f,
			    uint16_t skip_bytes)
{
	struct sockaddr_in dst;
	ssize_t rc;
	uint32_t daddr_be = htonl(f->inner_daddr != 0 ?
				  f->inner_daddr : 0x7f000001U);
	const uint8_t *payload = f->buf + skip_bytes;
	size_t plen;

	if (skip_bytes > f->len)
		return -2;
	plen = f->len - skip_bytes;
	if (plen == 0)
		return -2;

	if (ctx->raw_ipv4_fd < 0) {
		int fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
		int one = 1;

		if (fd < 0) {
			ctx->disabled = true;
			return -3;
		}
		(void)setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
		ctx->raw_ipv4_fd = fd;
	}

	memset(&dst, 0, sizeof(dst));
	dst.sin_family      = AF_INET;
	dst.sin_addr.s_addr = daddr_be;

	rc = sendto(ctx->raw_ipv4_fd, payload, plen, MSG_DONTWAIT,
		    (struct sockaddr *)&dst, sizeof(dst));
	return rc > 0 ? (int)rc : -1;
}

static int deliver_raw_ipv6(struct pktb_ctx *ctx, const struct pktb_frame *f,
			    uint16_t skip_bytes)
{
	struct sockaddr_in6 dst;
	ssize_t rc;
	const uint8_t *payload = f->buf + skip_bytes;
	size_t plen;

	if (skip_bytes > f->len)
		return -2;
	plen = f->len - skip_bytes;
	if (plen == 0)
		return -2;

	if (ctx->raw_ipv6_fd < 0) {
		int fd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);

		if (fd < 0) {
			ctx->disabled = true;
			return -3;
		}
		ctx->raw_ipv6_fd = fd;
	}

	memset(&dst, 0, sizeof(dst));
	dst.sin6_family = AF_INET6;
	dst.sin6_addr.s6_addr[15] = 0x01;

	rc = sendto(ctx->raw_ipv6_fd, payload, plen, MSG_DONTWAIT,
		    (struct sockaddr *)&dst, sizeof(dst));
	return rc > 0 ? (int)rc : -1;
}

static int deliver_loopback_udp(struct pktb_ctx *ctx, const struct pktb_frame *f,
				uint16_t skip_bytes)
{
	struct sockaddr_in dst;
	ssize_t rc;
	const uint8_t *payload;
	size_t plen;

	if (skip_bytes > f->len)
		return -2;
	payload = f->buf + skip_bytes;
	plen = f->len - skip_bytes;
	if (plen == 0)
		return -2;

	if (ctx->loopback_udp_fd < 0) {
		int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);

		if (fd < 0) {
			ctx->disabled = true;
			return -3;
		}
		ctx->loopback_udp_fd = fd;
	}

	memset(&dst, 0, sizeof(dst));
	dst.sin_family      = AF_INET;
	dst.sin_addr.s_addr = htonl(0x7f000001U);
	dst.sin_port        = htons(UDP_PORT_VXLAN);

	rc = sendto(ctx->loopback_udp_fd, payload, plen, MSG_DONTWAIT,
		    (struct sockaddr *)&dst, sizeof(dst));
	return rc > 0 ? (int)rc : -1;
}

/*
 * When delivery is RAW_IPV4/6 (kernel prepends the L2), skip the L2
 * layers already in the frame so the raw socket doesn't double-encap.
 * Ditto for LOOPBACK_UDP delivery, which strips everything down to
 * the innermost VXLAN/GENEVE header + inner payload the kernel would
 * see on a real ingress.
 */
static uint16_t skip_for_delivery(const struct pktb_frame *f,
				  enum pktb_delivery via)
{
	uint16_t skip = 0;
	uint8_t li;

	for (li = 0; li < f->n_layers; li++) {
		const struct pktb_layer_inst *L = &f->layers[li];

		switch (via) {
		case PKTB_DELIVER_RAW_IPV4:
			if (L->kind == PKTB_LAYER_ETH ||
			    L->kind == PKTB_LAYER_VLAN_SINGLE ||
			    L->kind == PKTB_LAYER_VLAN_DOUBLE) {
				skip = (uint16_t)(L->offset + L->len);
				continue;
			}
			return skip;
		case PKTB_DELIVER_RAW_IPV6:
			if (L->kind == PKTB_LAYER_ETH ||
			    L->kind == PKTB_LAYER_VLAN_SINGLE ||
			    L->kind == PKTB_LAYER_VLAN_DOUBLE) {
				skip = (uint16_t)(L->offset + L->len);
				continue;
			}
			return skip;
		case PKTB_DELIVER_LOOPBACK_UDP:
			if (L->kind == PKTB_LAYER_ETH ||
			    L->kind == PKTB_LAYER_VLAN_SINGLE ||
			    L->kind == PKTB_LAYER_VLAN_DOUBLE ||
			    L->kind == PKTB_LAYER_IP4 ||
			    L->kind == PKTB_LAYER_IP6 ||
			    L->kind == PKTB_LAYER_UDP_ENCAP) {
				skip = (uint16_t)(L->offset + L->len);
				continue;
			}
			return skip;
		default:
			return 0;
		}
	}
	return skip;
}

int pktb_deliver(struct pktb_ctx *ctx, const struct pktb_frame *f)
{
	const struct pktb_layer_manifest *outer;
	enum pktb_delivery via;
	uint16_t skip;

	if (ctx->disabled)
		return -3;
	if (f->n_layers == 0 || f->len == 0 || f->len > PKTB_FRAME_MAX)
		return -2;

	outer = pktb_manifest(f->layers[0].kind);
	if (outer == NULL)
		return -2;

	via = outer->delivery;
	skip = skip_for_delivery(f, via);

	switch (via) {
	case PKTB_DELIVER_AF_PACKET:    return deliver_af_packet(ctx, f);
	case PKTB_DELIVER_RAW_IPV4:     return deliver_raw_ipv4(ctx, f, skip);
	case PKTB_DELIVER_RAW_IPV6:     return deliver_raw_ipv6(ctx, f, skip);
	case PKTB_DELIVER_LOOPBACK_UDP: return deliver_loopback_udp(ctx, f, skip);
	case PKTB_DELIVER_NONE:         return -2;
	}
	return -2;
}
