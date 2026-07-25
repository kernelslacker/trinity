/*
 * esp-crafted-rx: small stateless helpers shared across the split
 * translation units.  Kept together so the builders and the burst
 * dispatcher can pull the same csum + pickers without dragging in
 * the SA / netlink surface.
 */

#include <netinet/ip.h>
#include <stdint.h>
#include <sys/types.h>

#include "random.h"
#include "rnd.h"

#include "childops/net/esp-crafted-rx-internal.h"

/*
 * IPv4 header checksum, standard one's-complement over the 20-byte
 * header.  Kept local so this file has no dependency on utils/csum
 * plumbing.  Mirrors ip_gre-churn.c / sctp-chunk-rx.c.
 */
__u16 esprx_ip_csum16(const void *data, size_t len)
{
	const __u16 *p = data;
	__u32 s = 0;

	while (len > 1) {
		s += *p++;
		len -= 2;
	}
	if (len)
		s += *(const __u8 *)p;
	while (s >> 16)
		s = (s & 0xffff) + (s >> 16);
	return (__u16)~s;
}

/*
 * Draw the inner protocol byte for a crafted frame.  Weighting keeps
 * TCP/UDP/ICMP in the mix (each maps to its own kernel parser entry
 * on the post-decap path) plus an escape hatch of random bytes for
 * the unknown-protocol branch.
 */
uint8_t esprx_pick_inner_proto(void)
{
	uint32_t roll = rnd_modulo_u32(8);

	switch (roll) {
	case 0: case 1: case 2: return IPPROTO_TCP;
	case 3: case 4:         return IPPROTO_UDP;
	case 5:                 return IPPROTO_ICMP;
	default:                return (uint8_t)rnd_modulo_u32(256);
	}
}

/*
 * Draw an inner-payload length shorter than the nominal parser read
 * for that proto, so the post-decap header walk over-reads.  Values
 * span {0, 1, 4, 8, 16} -- 0 leaves the parser reading the ESP
 * trailer bytes as if they were an inner header; 4/8/16 are common
 * short-header sizes that slice a real fixed header off mid-field.
 */
uint8_t esprx_pick_inner_trunc_len(void)
{
	uint32_t roll = rnd_modulo_u32(5);

	switch (roll) {
	case 0:  return 0U;
	case 1:  return 1U;
	case 2:  return 4U;
	case 3:  return 8U;
	default: return 16U;
	}
}

/*
 * Draw an ESP sequence number.  Rotates {0, 1, small random, large
 * random} to walk the replay-window edges the kernel checks before
 * the ICV verify.  Zero is included even though the kernel typically
 * treats seq=0 as invalid -- the reject path itself is worth
 * exercising.
 */
__u32 esprx_pick_esp_seq(void)
{
	switch (rnd_modulo_u32(4)) {
	case 0:  return 0U;
	case 1:  return 1U;
	case 2:  return rand32() & 0xffffU;
	default: return rand32();
	}
}
