/*
 * Structured payload builders for the common (level, optname) shapes.
 *
 * Each builder writes a sane-ish value of the optname's documented
 * ABI shape into `buf` (always backed by the page_size allocation
 * created in do_setsockopt) and returns the byte length the kernel
 * expects.  Biasing draws toward these entries lets per-protocol
 * copy_from_user / option-dispatch code run on well-formed inputs
 * instead of failing at the size check.
 *
 * RNG comes from trinity's rnd_* helpers exclusively; libc rand() is
 * not used.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <string.h>
#include "config.h"
#ifdef USE_SCTP
#include <linux/sctp.h>
#endif
#include "name-pool.h"
#include "random.h"
#include "rnd.h"
#include "utils.h"	// ARRAY_SIZE
#include "setsockopt-internal.h"

socklen_t build_int_bool(void *buf)
{
	*(int *)buf = (int)(rnd_u32() & 1);
	return sizeof(int);
}

socklen_t build_int_rand(void *buf)
{
	*(int *)buf = (int) rnd_u32();
	return sizeof(int);
}

socklen_t build_int_small_positive(void *buf)
{
	*(int *)buf = 1 + (int) rnd_modulo_u32(255);
	return sizeof(int);
}

socklen_t build_linger(void *buf)
{
	struct linger *l = buf;

	l->l_onoff = (int)(rnd_u32() & 1);
	l->l_linger = (int) rnd_modulo_u32(60);
	return sizeof(struct linger);
}

socklen_t build_timeval(void *buf)
{
	struct timeval *tv = buf;

	tv->tv_sec = (long) rnd_modulo_u32(30);
	tv->tv_usec = (long) rnd_modulo_u32(1000000);
	return sizeof(struct timeval);
}

socklen_t build_ip_mreqn(void *buf)
{
	struct ip_mreqn *m = buf;

	/* 224.0.0.x range — locally-scoped multicast. */
	m->imr_multiaddr.s_addr = htonl(0xe0000000 | rnd_modulo_u32(0x0fffffff));
	m->imr_address.s_addr = htonl(INADDR_ANY);
	m->imr_ifindex = 0;
	return sizeof(struct ip_mreqn);
}

socklen_t build_ipv6_mreq(void *buf)
{
	struct ipv6_mreq *m = buf;
	uint8_t *addr = (uint8_t *) &m->ipv6mr_multiaddr;

	memset(addr, 0, 16);
	addr[0] = 0xff;
	addr[1] = 0x02;
	addr[15] = (uint8_t)(1u + rnd_modulo_u32(0xfe));
	m->ipv6mr_interface = 0;
	return sizeof(struct ipv6_mreq);
}

socklen_t build_packet_mreq(void *buf)
{
	struct packet_mreq *m = buf;
	unsigned int i;

	m->mr_ifindex = 1;
	m->mr_type = (unsigned short)(1u + rnd_modulo_u32(4));
	m->mr_alen = 6;
	for (i = 0; i < sizeof(m->mr_address); i++)
		m->mr_address[i] = (unsigned char)(rnd_u32() & 0xff);
	return sizeof(struct packet_mreq);
}

#ifdef USE_SCTP
socklen_t build_sctp_initmsg(void *buf)
{
	memset(buf, 0, sizeof(struct sctp_initmsg));
	return sizeof(struct sctp_initmsg);
}

socklen_t build_sctp_rtoinfo(void *buf)
{
	memset(buf, 0, sizeof(struct sctp_rtoinfo));
	return sizeof(struct sctp_rtoinfo);
}

socklen_t build_sctp_assocparams(void *buf)
{
	memset(buf, 0, sizeof(struct sctp_assocparams));
	return sizeof(struct sctp_assocparams);
}

socklen_t build_sctp_setadaptation(void *buf)
{
	memset(buf, 0, sizeof(struct sctp_setadaptation));
	return sizeof(struct sctp_setadaptation);
}

socklen_t build_sctp_assoc_value(void *buf)
{
	memset(buf, 0, sizeof(struct sctp_assoc_value));
	return sizeof(struct sctp_assoc_value);
}

socklen_t build_sctp_sndinfo(void *buf)
{
	memset(buf, 0, sizeof(struct sctp_sndinfo));
	return sizeof(struct sctp_sndinfo);
}

socklen_t build_sctp_sndrcvinfo(void *buf)
{
	memset(buf, 0, sizeof(struct sctp_sndrcvinfo));
	return sizeof(struct sctp_sndrcvinfo);
}

socklen_t build_sctp_events(void *buf)
{
	memset(buf, 0, sizeof(struct sctp_event_subscribe));
	return sizeof(struct sctp_event_subscribe);
}

socklen_t build_sctp_authchunk(void *buf)
{
	memset(buf, 0, sizeof(struct sctp_authchunk));
	return sizeof(struct sctp_authchunk);
}

socklen_t build_sctp_sackinfo(void *buf)
{
	memset(buf, 0, sizeof(struct sctp_sack_info));
	return sizeof(struct sctp_sack_info);
}

socklen_t build_sctp_authkeyid(void *buf)
{
	memset(buf, 0, sizeof(struct sctp_authkeyid));
	return sizeof(struct sctp_authkeyid);
}

socklen_t build_sctp_default_prinfo(void *buf)
{
	memset(buf, 0, sizeof(struct sctp_default_prinfo));
	return sizeof(struct sctp_default_prinfo);
}

socklen_t build_sctp_add_streams(void *buf)
{
	memset(buf, 0, sizeof(struct sctp_add_streams));
	return sizeof(struct sctp_add_streams);
}

socklen_t build_sctp_stream_value(void *buf)
{
	memset(buf, 0, sizeof(struct sctp_stream_value));
	return sizeof(struct sctp_stream_value);
}

socklen_t build_sctp_event(void *buf)
{
	memset(buf, 0, sizeof(struct sctp_event));
	return sizeof(struct sctp_event);
}

socklen_t build_sctp_paddrthlds(void *buf)
{
	memset(buf, 0, sizeof(struct sctp_paddrthlds));
	return sizeof(struct sctp_paddrthlds);
}

socklen_t build_sctp_paddrthlds_v2(void *buf)
{
	memset(buf, 0, sizeof(struct sctp_paddrthlds_v2));
	return sizeof(struct sctp_paddrthlds_v2);
}

socklen_t build_sctp_udpencaps(void *buf)
{
	memset(buf, 0, sizeof(struct sctp_udpencaps));
	return sizeof(struct sctp_udpencaps);
}

socklen_t build_sctp_paddrparams(void *buf)
{
	memset(buf, 0, sizeof(struct sctp_paddrparams));
	return sizeof(struct sctp_paddrparams);
}

socklen_t build_sctp_probeinterval(void *buf)
{
	memset(buf, 0, sizeof(struct sctp_probeinterval));
	return sizeof(struct sctp_probeinterval);
}

socklen_t build_sctp_prim(void *buf)
{
	memset(buf, 0, sizeof(struct sctp_prim));
	return sizeof(struct sctp_prim);
}
#endif

socklen_t build_string_ifname(void *buf)
{
	static const char *names[] = { "lo", "eth0", "wlan0", "" };
	const char *n;
	size_t len;

	/*
	 * Minority arm draws from the shared NAME_KIND_NETDEV pool so an
	 * SO_BINDTODEVICE optval can pin to an ifname a concurrent
	 * childop just planted (altname-thrash, l2tp-ifname-race, ...) --
	 * exercising the dev-by-name resolve path and the bound-socket
	 * vs netdev-teardown race the static names never reach.  Majority
	 * arm keeps the well-known names so existing coverage stays warm;
	 * empty-pool draws fall through to the same path.
	 */
	if (ONE_IN(2)) {
		size_t got = name_pool_draw_mutated(NAME_KIND_NETDEV,
						    (char *)buf, IFNAMSIZ);

		if (got > 0) {
			if (got >= IFNAMSIZ)
				got = IFNAMSIZ - 1;
			((char *)buf)[got] = '\0';
			return (socklen_t)(got + 1);
		}
		/* empty pool -- fall through to static names */
	}

	n = names[rnd_modulo_u32(ARRAY_SIZE(names))];
	len = strlen(n);

	memcpy(buf, n, len);
	((char *)buf)[len] = '\0';
	return (socklen_t)(len + 1);
}
