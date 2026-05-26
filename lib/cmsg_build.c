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
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_packet.h>
#include <linux/udp.h>
#include <netinet/in.h>

#include "cmsg_build.h"
#include "fd.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

/* Older libcs miss a few of these; the kernel uapi headers above
 * normally provide them, but be defensive. */
#ifndef SCM_TIMESTAMPING
#define SCM_TIMESTAMPING	37
#endif
#ifndef SOL_UDP
#define SOL_UDP			17
#endif
#ifndef UDP_SEGMENT
#define UDP_SEGMENT		103
#endif

enum cmsg_kind pick_cmsg_kind(void)
{
	return (enum cmsg_kind) rnd_modulo_u32(NR_CMSG_KINDS);
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

int cmsg_build(struct msghdr *m, enum cmsg_kind k)
{
	switch (k) {
	case CMSG_KIND_SCM_RIGHTS:	return build_scm_rights(m);
	case CMSG_KIND_SCM_CREDENTIALS:	return build_scm_credentials(m);
	case CMSG_KIND_SO_TIMESTAMPING:	return build_so_timestamping(m);
	case CMSG_KIND_PACKET_AUXDATA:	return build_packet_auxdata(m);
	case CMSG_KIND_UDP_GSO:		return build_udp_gso(m);
	default:
		return -1;
	}
}
