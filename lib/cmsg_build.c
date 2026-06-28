/*
 * cmsg_build() — fuzz-side cmsg ancillary-data builder.
 *
 * See include/cmsg_build.h for the rationale.  Each kind populates
 * cmsg_level / cmsg_type / cmsg_len and a payload of the matching
 * shape, drawn from the writable pool so the kernel can write back
 * (SCM_RIGHTS scm_detach_fds patches cmsg_len in place on receive)
 * and the iov scrub pass leaves the mapping alone.  Payload values
 * mix valid and reserved-bit choices from the trinity RNG -- the
 * kernel parser is what we care about reaching, not realism.
 *
 * Extended kinds (IP_PKTINFO, IPV6_RTHDR, SCM_TXTIME, ...) and the
 * multi-cmsg packer fire only when the cmsg-richness lever is ON;
 * the OFF path through pick_cmsg_kind() draws from the original
 * base-5 modulo with a single rnd_modulo_u32 call so the RNG stream
 * is byte-identical to a build without the lever.
 */

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/udp.h>
#include <string.h>
#include <sys/types.h>

#include "cmsg-richness.h"
#include "cmsg_build.h"
#include "compat.h"
#include "fd.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

/* Older libcs miss a few of these; the kernel uapi headers above
 * normally provide them, but be defensive. */
#ifndef SCM_TIMESTAMPING
#define SCM_TIMESTAMPING	37
#endif
#ifndef SO_TXTIME
#define SO_TXTIME		61
#endif
#ifndef SCM_TXTIME
#define SCM_TXTIME		SO_TXTIME
#endif
#ifndef SOL_IP
#define SOL_IP			0
#endif
#ifndef SOL_IPV6
#define SOL_IPV6		41
#endif
#ifndef SOL_TLS
#define SOL_TLS			282
#endif
#ifndef TLS_SET_RECORD_TYPE
#define TLS_SET_RECORD_TYPE	1
#endif

enum cmsg_richness_mode cmsg_richness_mode = CMSG_RICHNESS_OFF;

enum cmsg_kind pick_cmsg_kind(unsigned int family)
{
	enum cmsg_kind pool[NR_CMSG_KINDS];
	unsigned int n = 0;

	/*
	 * OFF path: a single rnd_modulo_u32 over the original 5 base
	 * kinds.  No reference to @family, no second RNG draw, no path
	 * divergence from the pre-lever build.
	 */
	if (__atomic_load_n(&cmsg_richness_mode, __ATOMIC_RELAXED) ==
	    CMSG_RICHNESS_OFF)
		return (enum cmsg_kind) rnd_modulo_u32(NR_CMSG_KINDS_BASE);

	/*
	 * Multi-cmsg arm fires first under the ON branch.  The sentinel
	 * dispatches into cmsg_build's multi packer, which re-derives
	 * the per-family eligible set internally.
	 */
	if (ONE_IN(4))
		return CMSG_KIND_MULTI;

	/*
	 * Family-gated eligible single-cmsg pool.  SOL_SOCKET-level
	 * kinds (SCM_TIMESTAMPING, SCM_TXTIME) are accepted by the
	 * generic cmsg parser regardless of the family, but the per-
	 * proto post-parse gates reject mismatches anyway, so widen
	 * only to the families where the kind is plausibly meaningful
	 * rather than EINVAL-ing immediately.
	 */
	pool[n++] = CMSG_KIND_SO_TIMESTAMPING;

	if (family == AF_UNIX) {
		pool[n++] = CMSG_KIND_SCM_RIGHTS;
		pool[n++] = CMSG_KIND_SCM_CREDENTIALS;
	}
	if (family == AF_PACKET)
		pool[n++] = CMSG_KIND_PACKET_AUXDATA;
	if (family == AF_INET || family == AF_INET6)
		pool[n++] = CMSG_KIND_UDP_GSO;
	if (family == AF_INET) {
		pool[n++] = CMSG_KIND_IP_PKTINFO;
		pool[n++] = CMSG_KIND_IP_TOS;
		pool[n++] = CMSG_KIND_IP_TTL;
		pool[n++] = CMSG_KIND_IP_RETOPTS;
	}
	if (family == AF_INET6) {
		pool[n++] = CMSG_KIND_IPV6_PKTINFO;
		pool[n++] = CMSG_KIND_IPV6_TCLASS;
		pool[n++] = CMSG_KIND_IPV6_HOPLIMIT;
		pool[n++] = CMSG_KIND_IPV6_RTHDR;
	}
	if (family == AF_INET || family == AF_INET6 ||
	    family == AF_PACKET || family == AF_UNIX)
		pool[n++] = CMSG_KIND_SCM_TXTIME;
	/*
	 * TLS records flow over INET / INET6 stream sockets after the
	 * upper-layer ULP swap; the cmsg level / type are the gate the
	 * kernel actually checks.
	 */
	if (family == AF_INET || family == AF_INET6)
		pool[n++] = CMSG_KIND_TLS_SET_RECORD_TYPE;

	if (n == 0)
		return (enum cmsg_kind) rnd_modulo_u32(NR_CMSG_KINDS_BASE);

	return pool[rnd_modulo_u32(n)];
}

static int build_scm_rights(struct msghdr *m)
{
	struct cmsghdr *cmsg;
	unsigned int nfds = RAND_BOOL() ? 1 : 2;
	size_t plen = nfds * sizeof(int);
	int fds[2];
	unsigned int i;

	void *buf = get_writable_struct(CMSG_SPACE(plen));
	if (buf == NULL)
		return -1;
	memset(buf, 0, CMSG_SPACE(plen));

	m->msg_control = buf;
	m->msg_controllen = CMSG_SPACE(plen);
	cmsg = CMSG_FIRSTHDR(m);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(plen);
	for (i = 0; i < nfds; i++)
		fds[i] = get_random_fd();
	memcpy(CMSG_DATA(cmsg), fds, plen);
	return 0;
}

static int build_scm_credentials(struct msghdr *m)
{
	struct cmsghdr *cmsg;
	struct ucred uc;
	size_t plen = sizeof(uc);

	void *buf = get_writable_struct(CMSG_SPACE(plen));
	if (buf == NULL)
		return -1;
	memset(buf, 0, CMSG_SPACE(plen));

	uc.pid = ONE_IN(8) ? (pid_t) rand32() : getpid();
	uc.uid = ONE_IN(8) ? (uid_t) rand32() : getuid();
	uc.gid = ONE_IN(8) ? (gid_t) rand32() : getgid();

	m->msg_control = buf;
	m->msg_controllen = CMSG_SPACE(plen);
	cmsg = CMSG_FIRSTHDR(m);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_CREDENTIALS;
	cmsg->cmsg_len = CMSG_LEN(plen);
	memcpy(CMSG_DATA(cmsg), &uc, plen);
	return 0;
}

static int build_so_timestamping(struct msghdr *m)
{
	struct cmsghdr *cmsg;
	uint32_t flags;
	size_t plen = sizeof(flags);

	void *buf = get_writable_struct(CMSG_SPACE(plen));
	if (buf == NULL)
		return -1;
	memset(buf, 0, CMSG_SPACE(plen));

	/* Mix of valid SOF_TIMESTAMPING_* bits and reserved high bits. */
	flags = rand32();

	m->msg_control = buf;
	m->msg_controllen = CMSG_SPACE(plen);
	cmsg = CMSG_FIRSTHDR(m);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_TIMESTAMPING;
	cmsg->cmsg_len = CMSG_LEN(plen);
	memcpy(CMSG_DATA(cmsg), &flags, plen);
	return 0;
}

static int build_packet_auxdata(struct msghdr *m)
{
	struct cmsghdr *cmsg;
	size_t plen = sizeof(struct tpacket_auxdata);

	/* Payload zero-filled; AF_PACKET writes this out on recv, on
	 * sendmsg the per-proto cmsg-type sieve rejects it. */
	void *buf = get_writable_struct(CMSG_SPACE(plen));
	if (buf == NULL)
		return -1;
	memset(buf, 0, CMSG_SPACE(plen));

	m->msg_control = buf;
	m->msg_controllen = CMSG_SPACE(plen);
	cmsg = CMSG_FIRSTHDR(m);
	cmsg->cmsg_level = SOL_PACKET;
	cmsg->cmsg_type = PACKET_AUXDATA;
	cmsg->cmsg_len = CMSG_LEN(plen);
	return 0;
}

static int build_udp_gso(struct msghdr *m)
{
	static const uint16_t gso_choices[] = {
		0, 1, 64, 1448, 4096, 32768, 65535,
	};
	struct cmsghdr *cmsg;
	uint16_t gso;
	size_t plen = sizeof(gso);

	void *buf = get_writable_struct(CMSG_SPACE(plen));
	if (buf == NULL)
		return -1;
	memset(buf, 0, CMSG_SPACE(plen));

	gso = gso_choices[rnd_modulo_u32(sizeof(gso_choices) /
					 sizeof(gso_choices[0]))];

	m->msg_control = buf;
	m->msg_controllen = CMSG_SPACE(plen);
	cmsg = CMSG_FIRSTHDR(m);
	cmsg->cmsg_level = SOL_UDP;
	cmsg->cmsg_type = UDP_SEGMENT;
	cmsg->cmsg_len = CMSG_LEN(plen);
	memcpy(CMSG_DATA(cmsg), &gso, plen);
	return 0;
}

/*
 * Per-kind payload fillers.  Each writes plen bytes at @dst; the
 * caller has already zeroed the surrounding cmsg slot, so a filler
 * that only sets a prefix leaves the rest zero rather than carrying
 * stale writable-pool bytes into the kernel copy.
 */
static void fill_ip_pktinfo(void *dst)
{
	struct in_pktinfo pi;

	memset(&pi, 0, sizeof(pi));
	pi.ipi_ifindex = (int) rand32();
	pi.ipi_spec_dst.s_addr = rand32();
	pi.ipi_addr.s_addr = rand32();
	memcpy(dst, &pi, sizeof(pi));
}

static void fill_ipv6_pktinfo(void *dst)
{
	struct in6_pktinfo pi;
	unsigned int i;

	memset(&pi, 0, sizeof(pi));
	for (i = 0; i < sizeof(pi.ipi6_addr.s6_addr) / sizeof(uint32_t); i++)
		((uint32_t *) pi.ipi6_addr.s6_addr)[i] = rand32();
	pi.ipi6_ifindex = (int) rand32();
	memcpy(dst, &pi, sizeof(pi));
}

static void fill_int_small(void *dst)
{
	/* IP_TOS / IPV6_TCLASS are u8-effective; mask to surface the
	 * kernel's u8 truncation path. */
	int v = (int) (rand32() & 0xff);
	memcpy(dst, &v, sizeof(v));
}

static void fill_int_ttl(void *dst)
{
	/* IP_TTL / IPV6_HOPLIMIT: -1 means "use default"; valid range
	 * is 0..255.  Mix with random ints to exercise the validator. */
	int v;

	if (ONE_IN(4))
		v = -1;
	else
		v = (int) (rand32() & 0xff);
	memcpy(dst, &v, sizeof(v));
}

static void fill_u64_txtime(void *dst)
{
	/*
	 * SCM_TXTIME carries a u64 transmit-deadline in ns relative to
	 * the SO_TXTIME clockid.  Random nanosecond values exercise the
	 * deadline validator on both the EDF and FIFO arms.
	 */
	uint64_t v = ((uint64_t) rand32() << 32) | rand32();
	memcpy(dst, &v, sizeof(v));
}

static void fill_tls_record_type(void *dst)
{
	/* TLS_SET_RECORD_TYPE is a single-byte record type
	 * (0..255).  The kernel parser checks the well-known
	 * 20/21/22/23 values; reserved values exercise the reject
	 * arm. */
	*(unsigned char *) dst = (unsigned char) (rand32() & 0xff);
}

static void fill_scm_credentials(void *dst)
{
	struct ucred uc;

	uc.pid = ONE_IN(8) ? (pid_t) rand32() : getpid();
	uc.uid = ONE_IN(8) ? (uid_t) rand32() : getuid();
	uc.gid = ONE_IN(8) ? (gid_t) rand32() : getgid();
	memcpy(dst, &uc, sizeof(uc));
}

static void fill_so_timestamping(void *dst)
{
	uint32_t flags = rand32();
	memcpy(dst, &flags, sizeof(flags));
}

static int build_one_int(struct msghdr *m, int level, int type,
			 void (*fill)(void *))
{
	struct cmsghdr *cmsg;
	size_t plen = sizeof(int);

	void *buf = get_writable_struct(CMSG_SPACE(plen));
	if (buf == NULL)
		return -1;
	memset(buf, 0, CMSG_SPACE(plen));

	m->msg_control = buf;
	m->msg_controllen = CMSG_SPACE(plen);
	cmsg = CMSG_FIRSTHDR(m);
	cmsg->cmsg_level = level;
	cmsg->cmsg_type = type;
	cmsg->cmsg_len = CMSG_LEN(plen);
	fill(CMSG_DATA(cmsg));
	return 0;
}

static int build_ip_pktinfo(struct msghdr *m)
{
	struct cmsghdr *cmsg;
	size_t plen = sizeof(struct in_pktinfo);

	void *buf = get_writable_struct(CMSG_SPACE(plen));
	if (buf == NULL)
		return -1;
	memset(buf, 0, CMSG_SPACE(plen));

	m->msg_control = buf;
	m->msg_controllen = CMSG_SPACE(plen);
	cmsg = CMSG_FIRSTHDR(m);
	cmsg->cmsg_level = SOL_IP;
	cmsg->cmsg_type = IP_PKTINFO;
	cmsg->cmsg_len = CMSG_LEN(plen);
	fill_ip_pktinfo(CMSG_DATA(cmsg));
	return 0;
}

static int build_ipv6_pktinfo(struct msghdr *m)
{
	struct cmsghdr *cmsg;
	size_t plen = sizeof(struct in6_pktinfo);

	void *buf = get_writable_struct(CMSG_SPACE(plen));
	if (buf == NULL)
		return -1;
	memset(buf, 0, CMSG_SPACE(plen));

	m->msg_control = buf;
	m->msg_controllen = CMSG_SPACE(plen);
	cmsg = CMSG_FIRSTHDR(m);
	cmsg->cmsg_level = SOL_IPV6;
	cmsg->cmsg_type = IPV6_PKTINFO;
	cmsg->cmsg_len = CMSG_LEN(plen);
	fill_ipv6_pktinfo(CMSG_DATA(cmsg));
	return 0;
}

/*
 * IP_RETOPTS carries an IP options blob -- 0..40 bytes of opaque
 * bytes from the user, with the kernel parsing each option TLV.
 * Random bytes drive the option-walker; the well-known LSRR / SSRR /
 * RR option types are at the front of the choices so the parser
 * sees both valid and reserved tags.
 */
static int build_ip_retopts(struct msghdr *m)
{
	static const uint8_t lead[] = {
		0,    /* EOL */
		1,    /* NOP */
		7,    /* RR (length+) */
		131,  /* LSRR */
		137,  /* SSRR */
		148,  /* RA */
	};
	struct cmsghdr *cmsg;
	size_t plen = RAND_RANGE(4, 40);
	unsigned int i;
	uint8_t *p;

	void *buf = get_writable_struct(CMSG_SPACE(plen));
	if (buf == NULL)
		return -1;
	memset(buf, 0, CMSG_SPACE(plen));

	m->msg_control = buf;
	m->msg_controllen = CMSG_SPACE(plen);
	cmsg = CMSG_FIRSTHDR(m);
	cmsg->cmsg_level = SOL_IP;
	cmsg->cmsg_type = IP_RETOPTS;
	cmsg->cmsg_len = CMSG_LEN(plen);

	p = (uint8_t *) CMSG_DATA(cmsg);
	p[0] = lead[rnd_modulo_u32(sizeof(lead) / sizeof(lead[0]))];
	for (i = 1; i < plen; i++)
		p[i] = (uint8_t) rand32();
	return 0;
}

/*
 * IPV6_RTHDR carries a routing header -- ip6_rthdr is 8 bytes plus
 * an optional type-specific tail.  Keep the payload bounded so the
 * kernel parser's length check is reached with both valid and
 * reserved type/segleft tuples.
 */
static int build_ipv6_rthdr(struct msghdr *m)
{
	struct cmsghdr *cmsg;
	uint8_t *p;
	/*
	 * ip6r_len is in 8-octet units, excluding the first 8 bytes;
	 * total = 8 * (1 + ip6r_len).  Pick from {8, 16, 24, 32} so the
	 * parser sees both the minimal and small-tail shapes.
	 */
	unsigned int len_units = rnd_modulo_u32(4);
	size_t plen = 8 * (1 + len_units);

	void *buf = get_writable_struct(CMSG_SPACE(plen));
	if (buf == NULL)
		return -1;
	memset(buf, 0, CMSG_SPACE(plen));

	m->msg_control = buf;
	m->msg_controllen = CMSG_SPACE(plen);
	cmsg = CMSG_FIRSTHDR(m);
	cmsg->cmsg_level = SOL_IPV6;
	cmsg->cmsg_type = IPV6_RTHDR;
	cmsg->cmsg_len = CMSG_LEN(plen);

	p = (uint8_t *) CMSG_DATA(cmsg);
	p[0] = (uint8_t) rand32();		/* ip6r_nxt */
	p[1] = (uint8_t) len_units;		/* ip6r_len in 8-octet units */
	p[2] = ONE_IN(2) ? 0 : (uint8_t) rand32();  /* ip6r_type */
	p[3] = (uint8_t) rand32();		/* ip6r_segleft */
	/* tail (p[4..plen-1]) stays zero from the memset above */
	return 0;
}

static int build_scm_txtime(struct msghdr *m)
{
	struct cmsghdr *cmsg;
	size_t plen = sizeof(uint64_t);

	void *buf = get_writable_struct(CMSG_SPACE(plen));
	if (buf == NULL)
		return -1;
	memset(buf, 0, CMSG_SPACE(plen));

	m->msg_control = buf;
	m->msg_controllen = CMSG_SPACE(plen);
	cmsg = CMSG_FIRSTHDR(m);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_TXTIME;
	cmsg->cmsg_len = CMSG_LEN(plen);
	fill_u64_txtime(CMSG_DATA(cmsg));
	return 0;
}

static int build_tls_set_record_type(struct msghdr *m)
{
	struct cmsghdr *cmsg;
	size_t plen = sizeof(unsigned char);

	void *buf = get_writable_struct(CMSG_SPACE(plen));
	if (buf == NULL)
		return -1;
	memset(buf, 0, CMSG_SPACE(plen));

	m->msg_control = buf;
	m->msg_controllen = CMSG_SPACE(plen);
	cmsg = CMSG_FIRSTHDR(m);
	cmsg->cmsg_level = SOL_TLS;
	cmsg->cmsg_type = TLS_SET_RECORD_TYPE;
	cmsg->cmsg_len = CMSG_LEN(plen);
	fill_tls_record_type(CMSG_DATA(cmsg));
	return 0;
}

/*
 * Multi-cmsg packer.  Picks 2-3 distinct entries from a per-family
 * fixed-shape pool (variable-length kinds like IP_RETOPTS and
 * IPV6_RTHDR are excluded to keep the packer's size accounting
 * trivial), sizes the buffer by the SUM of CMSG_SPACE(plen) across
 * the chosen entries, and walks CMSG_FIRSTHDR -> CMSG_NXTHDR with
 * the spec-required CMSG_LEN(plen) per entry.  The whole buffer is
 * zero-filled up front so padding and any unused tail carry no
 * stale writable-pool bytes into the kernel copy.
 */
struct multi_entry {
	int level;
	int type;
	size_t plen;
	void (*fill)(void *dst);	/* NULL => leave zero (e.g. PACKET_AUXDATA) */
};

static unsigned int build_multi_pool(unsigned int family,
				     struct multi_entry *pool,
				     unsigned int cap)
{
	unsigned int n = 0;

#define PUSH(L, T, S, F)						\
	do {								\
		if (n < cap) {						\
			pool[n].level = (L);				\
			pool[n].type = (T);				\
			pool[n].plen = (S);				\
			pool[n].fill = (F);				\
			n++;						\
		}							\
	} while (0)

	/* SOL_SOCKET-level entries available widely. */
	PUSH(SOL_SOCKET, SCM_TIMESTAMPING, sizeof(uint32_t),
	     fill_so_timestamping);
	if (family == AF_INET || family == AF_INET6 ||
	    family == AF_PACKET || family == AF_UNIX)
		PUSH(SOL_SOCKET, SCM_TXTIME, sizeof(uint64_t),
		     fill_u64_txtime);

	if (family == AF_UNIX) {
		/*
		 * SCM_RIGHTS in the multi-pack uses the same get_random_fd
		 * shape as the single-cmsg builder; capped at one fd to
		 * keep plen bounded.  Filler is NULL -- the slot stays
		 * zero from the memset, then we patch the fd into CMSG_DATA
		 * below.
		 */
		PUSH(SOL_SOCKET, SCM_RIGHTS, sizeof(int), NULL);
		PUSH(SOL_SOCKET, SCM_CREDENTIALS, sizeof(struct ucred),
		     fill_scm_credentials);
	}
	if (family == AF_PACKET)
		PUSH(SOL_PACKET, PACKET_AUXDATA,
		     sizeof(struct tpacket_auxdata), NULL);
	if (family == AF_INET) {
		PUSH(SOL_IP, IP_PKTINFO, sizeof(struct in_pktinfo),
		     fill_ip_pktinfo);
		PUSH(SOL_IP, IP_TOS, sizeof(int), fill_int_small);
		PUSH(SOL_IP, IP_TTL, sizeof(int), fill_int_ttl);
	}
	if (family == AF_INET6) {
		PUSH(SOL_IPV6, IPV6_PKTINFO, sizeof(struct in6_pktinfo),
		     fill_ipv6_pktinfo);
		PUSH(SOL_IPV6, IPV6_TCLASS, sizeof(int), fill_int_small);
		PUSH(SOL_IPV6, IPV6_HOPLIMIT, sizeof(int), fill_int_ttl);
	}
#undef PUSH

	return n;
}

static int build_cmsg_multi(struct msghdr *m, unsigned int family)
{
	struct multi_entry pool[16];
	struct multi_entry chosen[3];
	struct cmsghdr *cmsg;
	unsigned int n, count, i, j;
	size_t total = 0;
	void *buf;

	n = build_multi_pool(family, pool, sizeof(pool) / sizeof(pool[0]));
	if (n < 2)
		return -1;

	count = RAND_RANGE(2, 3);
	if (count > n)
		count = n;

	/*
	 * Sample @count distinct entries without replacement via the
	 * standard Fisher-Yates prefix swap.  Working on @pool in place
	 * is fine -- the pool is a local stack array, used once and
	 * thrown away.  Total cmsg-buffer size is the SUM of
	 * CMSG_SPACE(plen) across the chosen entries -- never the
	 * largest single payload -- so CMSG_NXTHDR has room to advance.
	 */
	for (i = 0; i < count; i++) {
		j = i + rnd_modulo_u32(n - i);
		chosen[i] = pool[j];
		pool[j] = pool[i];
		total += CMSG_SPACE(chosen[i].plen);
	}

	buf = get_writable_struct(total);
	if (buf == NULL)
		return -1;
	memset(buf, 0, total);

	m->msg_control = buf;
	m->msg_controllen = total;

	cmsg = CMSG_FIRSTHDR(m);
	for (i = 0; i < count && cmsg != NULL; i++) {
		cmsg->cmsg_level = chosen[i].level;
		cmsg->cmsg_type = chosen[i].type;
		cmsg->cmsg_len = CMSG_LEN(chosen[i].plen);
		if (chosen[i].level == SOL_SOCKET &&
		    chosen[i].type == SCM_RIGHTS) {
			int fd = get_random_fd();
			memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
		} else if (chosen[i].fill != NULL) {
			chosen[i].fill(CMSG_DATA(cmsg));
		}
		cmsg = CMSG_NXTHDR(m, cmsg);
	}
	return 0;
}

int cmsg_build(struct msghdr *m, enum cmsg_kind k, unsigned int family)
{
	switch (k) {
	case CMSG_KIND_SCM_RIGHTS:	return build_scm_rights(m);
	case CMSG_KIND_SCM_CREDENTIALS:	return build_scm_credentials(m);
	case CMSG_KIND_SO_TIMESTAMPING:	return build_so_timestamping(m);
	case CMSG_KIND_PACKET_AUXDATA:	return build_packet_auxdata(m);
	case CMSG_KIND_UDP_GSO:		return build_udp_gso(m);
	case CMSG_KIND_IP_PKTINFO:	return build_ip_pktinfo(m);
	case CMSG_KIND_IPV6_PKTINFO:	return build_ipv6_pktinfo(m);
	case CMSG_KIND_IP_TOS:
		return build_one_int(m, SOL_IP, IP_TOS, fill_int_small);
	case CMSG_KIND_IP_TTL:
		return build_one_int(m, SOL_IP, IP_TTL, fill_int_ttl);
	case CMSG_KIND_IP_RETOPTS:	return build_ip_retopts(m);
	case CMSG_KIND_IPV6_TCLASS:
		return build_one_int(m, SOL_IPV6, IPV6_TCLASS, fill_int_small);
	case CMSG_KIND_IPV6_HOPLIMIT:
		return build_one_int(m, SOL_IPV6, IPV6_HOPLIMIT, fill_int_ttl);
	case CMSG_KIND_IPV6_RTHDR:	return build_ipv6_rthdr(m);
	case CMSG_KIND_SCM_TXTIME:	return build_scm_txtime(m);
	case CMSG_KIND_TLS_SET_RECORD_TYPE:
		return build_tls_set_record_type(m);
	case CMSG_KIND_MULTI:		return build_cmsg_multi(m, family);
	default:
		return -1;
	}
}
