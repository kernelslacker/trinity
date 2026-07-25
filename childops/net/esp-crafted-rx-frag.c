/*
 * esp-crafted-rx: fragmented-inner emitter.  Composes a large
 * ESP-encapsulated blob (SPI + seq + 1 KiB inner + trailer) and
 * slices it across two IP fragments so IP defrag reassembles into a
 * non-linear skb; ESP decrypt then walks that skb via skb_cow_data()
 * into a scatter-gather crypto request and, on completion, the
 * esp_ssg_unref() cleanup path runs over managed frag pages.
 */

#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "random.h"
#include "rnd.h"
#include "shm.h"

#include "childops/net/esp-crafted-rx-internal.h"

/*
 * Compose an ESP-encapsulated blob (SPI + seq + inner payload + ESP
 * trailer) for the fragmented emitter to slice across IP fragments.
 * Total length is fixed at ESPRX_FRAG_ESP_LEN so the caller can pick
 * the fragment offsets without re-inspecting the blob.  Inner bytes are
 * random; trailer pads to 0 with next_header carrying the picked inner
 * proto so the reassembled ESP payload has a plausible trailer on the
 * decrypt done path.
 */
void build_esp_blob(uint8_t *esp, __be32 spi, __u32 seq,
		    uint8_t inner_proto)
{
	*(__be32 *)(esp + 0) = spi;
	*(__be32 *)(esp + 4) = htonl(seq);
	generate_rand_bytes(esp + 8, ESPRX_FRAG_INNER);
	esp[8 + ESPRX_FRAG_INNER + 0] = 0;
	esp[8 + ESPRX_FRAG_INNER + 1] = inner_proto;
}

/*
 * Emit one IPv4 fragment carrying `slice_len` bytes of an ESP blob.
 * Protocol stays IPPROTO_ESP on every fragment; IP defrag reassembles
 * by id + saddr + daddr + proto and only then hands the reassembled
 * datagram to the ESP protocol handler.
 */
size_t build_v4_esp_fragment(uint8_t *buf, uint16_t ident,
			     uint16_t frag_off_units, bool more,
			     const uint8_t *esp_slice, size_t slice_len)
{
	struct iphdr *iph = (struct iphdr *)buf;
	uint16_t frag_off_word = frag_off_units & 0x1fffU;

	if (more)
		frag_off_word |= 0x2000U;	/* IP_MF */

	memset(buf, 0, sizeof(*iph));
	iph->version  = 4;
	iph->ihl      = 5;
	iph->ttl      = 64;
	iph->protocol = IPPROTO_ESP;
	iph->saddr    = ESPRX_V4_SADDR_BE;
	iph->daddr    = ESPRX_V4_DADDR_BE;
	iph->id       = htons(ident);
	iph->frag_off = htons(frag_off_word);
	iph->tot_len  = htons((uint16_t)(sizeof(*iph) + slice_len));

	memcpy(buf + sizeof(*iph), esp_slice, slice_len);

	iph->check = esprx_ip_csum16(iph, sizeof(*iph));
	return sizeof(*iph) + slice_len;
}

/*
 * Emit one IPv6 fragment carrying `slice_len` bytes of an ESP blob.
 * Outer IPv6 next_header points to a Fragment header (44); the Fragment
 * header's next_header carries IPPROTO_ESP so the reassembled datagram
 * lands on the ESP6 protocol handler.  Offset is in 8-byte units per
 * RFC 8200.
 */
size_t build_v6_esp_fragment(uint8_t *buf, uint32_t ident,
			     uint16_t frag_off_units, bool more,
			     const uint8_t *esp_slice, size_t slice_len)
{
	uint16_t frag_off_word;
	uint16_t payload_len;

	memset(buf, 0, 40U + 8U);
	buf[0] = 0x60;
	buf[6] = 44;			/* next_header = Fragment */
	buf[7] = 64;
	buf[8 + 15]  = 1;		/* saddr = ::1 */
	buf[24 + 15] = 1;		/* daddr = ::1 */

	buf[40] = IPPROTO_ESP;		/* fragment: next_header */
	buf[41] = 0;			/* reserved */
	frag_off_word = (uint16_t)((frag_off_units << 3) & 0xfff8U);
	if (more)
		frag_off_word |= 1U;
	buf[42] = (uint8_t)(frag_off_word >> 8);
	buf[43] = (uint8_t)(frag_off_word & 0xff);
	buf[44] = (uint8_t)(ident >> 24);
	buf[45] = (uint8_t)(ident >> 16);
	buf[46] = (uint8_t)(ident >>  8);
	buf[47] = (uint8_t)(ident      );

	memcpy(buf + 48, esp_slice, slice_len);

	payload_len = (uint16_t)(8U + slice_len);
	buf[4] = (uint8_t)(payload_len >> 8);
	buf[5] = (uint8_t)(payload_len & 0xff);

	return 48U + slice_len;
}

/*
 * Emit a large ESP-encapsulated datagram (SPI + seq + 1 KiB inner +
 * trailer) split across two IP fragments to the SA's family.  IP defrag
 * reassembles into a non-linear skb, which ESP decrypt turns into a
 * scatter-gather crypto request; the SG teardown then runs
 * esp_ssg_unref() over managed frag pages.  SPI matches the installed
 * SA most of the time and misses occasionally, mirroring the single-
 * frame path's SPI-lookup mix.
 */
void esp_crafted_rx_send_frag_pair(struct esp_crafted_rx_iter_ctx *ctx,
				   int fd)
{
	static const struct {
		uint16_t off_units;
		size_t   esp_off;
		size_t   len;
		bool     more;
	} slices[2] = {
		{ 0U,
		  0U,
		  ESPRX_FRAG_SLICE1,
		  true },
		{ (uint16_t)(ESPRX_FRAG_SLICE1 / 8U),
		  ESPRX_FRAG_SLICE1,
		  ESPRX_FRAG_ESP_LEN - ESPRX_FRAG_SLICE1,
		  false },
	};
	uint8_t esp[ESPRX_FRAG_ESP_LEN];
	uint8_t frame[ESPRX_FRAG_FRAME_MAX];
	__be32 spi;
	__u32 seq;
	uint8_t inner_proto;
	unsigned int i;

	spi = ONE_IN(8)
		? htonl((rand32() % ESPRX_SPI_RANGE) + ESPRX_SPI_MIN)
		: ctx->spi;
	seq         = esprx_pick_esp_seq();
	inner_proto = esprx_pick_inner_proto();

	build_esp_blob(esp, spi, seq, inner_proto);

	if (ctx->v6) {
		struct sockaddr_in6 dst;
		uint32_t ident = rand32();

		memset(&dst, 0, sizeof(dst));
		dst.sin6_family = AF_INET6;
		dst.sin6_addr.s6_addr[15] = 1;

		for (i = 0; i < 2; i++) {
			size_t frame_len = build_v6_esp_fragment(frame, ident,
					slices[i].off_units, slices[i].more,
					esp + slices[i].esp_off, slices[i].len);

			if (sendto(fd, frame, frame_len, MSG_DONTWAIT,
				   (struct sockaddr *)&dst, sizeof(dst)) > 0)
				__atomic_add_fetch(&shm->stats.esp_crafted_rx.packet_sent_ok,
						   1, __ATOMIC_RELAXED);
		}
	} else {
		struct sockaddr_in dst;
		uint16_t ident = (uint16_t)rand32();

		memset(&dst, 0, sizeof(dst));
		dst.sin_family      = AF_INET;
		dst.sin_addr.s_addr = ESPRX_V4_DADDR_BE;

		for (i = 0; i < 2; i++) {
			size_t frame_len = build_v4_esp_fragment(frame, ident,
					slices[i].off_units, slices[i].more,
					esp + slices[i].esp_off, slices[i].len);

			if (sendto(fd, frame, frame_len, MSG_DONTWAIT,
				   (struct sockaddr *)&dst, sizeof(dst)) > 0)
				__atomic_add_fetch(&shm->stats.esp_crafted_rx.packet_sent_ok,
						   1, __ATOMIC_RELAXED);
		}
	}
}
