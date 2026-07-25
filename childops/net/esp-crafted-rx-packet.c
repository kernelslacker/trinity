/*
 * esp-crafted-rx: single-frame IPv4(ESP) / IPv6(ESP) builders used by
 * the linear-inner burst.  Fragmented-inner and stacked-ESP builders
 * live in sibling TUs.
 */

#include <netinet/ip.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "random.h"

#include "childops/net/esp-crafted-rx-internal.h"

/*
 * Build an IPv4(ESP) frame with a truncated inner payload of the
 * given proto.  Returns the total wire length ready for sendto().
 * Layout:
 *   [outer IPv4 (20)]
 *   [ESP header (8): SPI + seq]
 *   [inner payload of trunc_len bytes -- shorter than the parser's
 *    nominal minimum for the picked inner_proto]
 *   [ESP trailer (2): pad_len=0, next_header=inner_proto]
 */
size_t esprx_build_v4_frame(uint8_t *buf, __be32 spi, __u32 seq,
			    uint8_t inner_proto, uint8_t trunc_len)
{
	struct iphdr *iph;
	size_t off;
	size_t esp_hdr_start;
	size_t inner_start;

	if (trunc_len > ESPRX_INNER_NOMINAL)
		trunc_len = ESPRX_INNER_NOMINAL;

	memset(buf, 0, ESPRX_PKT_MAX);
	iph = (struct iphdr *)buf;
	iph->version  = 4;
	iph->ihl      = 5;
	iph->ttl      = 64;
	iph->protocol = IPPROTO_ESP;
	iph->saddr    = ESPRX_V4_SADDR_BE;
	iph->daddr    = ESPRX_V4_DADDR_BE;
	off = sizeof(*iph);

	esp_hdr_start = off;
	*(__be32 *)(buf + off + 0) = spi;
	*(__be32 *)(buf + off + 4) = htonl(seq);
	off += 8;
	(void)esp_hdr_start;

	inner_start = off;
	if (trunc_len > 0) {
		uint8_t stub[ESPRX_INNER_NOMINAL];

		generate_rand_bytes(stub, trunc_len);
		memcpy(buf + inner_start, stub, trunc_len);
		off += trunc_len;
	}

	/* ESP trailer: pad_len=0, next_header=inner_proto.  Kernel reads
	 * these two bytes from the tail of the decrypted plaintext to
	 * determine what proto to walk next; without them the RX done
	 * path has nothing plausible to hand to the inner parser. */
	buf[off + 0] = 0;
	buf[off + 1] = inner_proto;
	off += 2;

	iph->tot_len = htons((uint16_t)off);
	iph->check   = 0;
	iph->check   = esprx_ip_csum16(iph, sizeof(*iph));

	return off;
}

/*
 * Build an IPv6(ESP) frame.  Same shape as the v4 builder but with an
 * outer IPv6 header (40 bytes, next_header=IPPROTO_ESP, payload_length
 * covers ESP header + inner + trailer).  IPv6 has no header checksum.
 */
size_t esprx_build_v6_frame(uint8_t *buf, __be32 spi, __u32 seq,
			    uint8_t inner_proto, uint8_t trunc_len)
{
	size_t off;
	uint16_t payload_len;

	if (trunc_len > ESPRX_INNER_NOMINAL)
		trunc_len = ESPRX_INNER_NOMINAL;

	memset(buf, 0, ESPRX_PKT_MAX);

	/* IPv6 fixed header: version=6, next_header=ESP, hop_limit=64.
	 * saddr and daddr both ::1 -- single-address loopback is enough
	 * for a private-netns RX-only op. */
	buf[0]  = 0x60;
	buf[6]  = IPPROTO_ESP;
	buf[7]  = 64;
	buf[8 + 15]  = 1;	/* saddr = ::1 */
	buf[24 + 15] = 1;	/* daddr = ::1 */
	off = 40;

	*(__be32 *)(buf + off + 0) = spi;
	*(__be32 *)(buf + off + 4) = htonl(seq);
	off += 8;

	if (trunc_len > 0) {
		uint8_t stub[ESPRX_INNER_NOMINAL];

		generate_rand_bytes(stub, trunc_len);
		memcpy(buf + off, stub, trunc_len);
		off += trunc_len;
	}

	buf[off + 0] = 0;
	buf[off + 1] = inner_proto;
	off += 2;

	payload_len = (uint16_t)(off - 40);
	buf[4] = (uint8_t)(payload_len >> 8);
	buf[5] = (uint8_t)payload_len;

	return off;
}
