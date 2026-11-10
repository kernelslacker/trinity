/*
 * Self-check for the args the ioctl group sanitisers build: what they draw
 * has to be what the kernel's own checks take, and the draw has to reach all
 * of it.  The drm group's client caps and object types, the ext group's new
 * requests, the userfaultfd group's handshake and the socket group's tunnel
 * and bridge requests are covered.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_bridge.h>
#include <linux/if_tunnel.h>
#include <linux/ip6_tunnel.h>
#include <linux/sockios.h>

#ifdef USE_DRM
#include <drm/drm.h>
#include <drm/drm_mode.h>
#endif
#include <linux/hidraw.h>
#include <linux/input.h>
#include <linux/joystick.h>

#include "arch.h"		/* page_size */
#include "debug.h"		/* BUG */
#include "efault_cache.h"
#include "fake_ioctls.h"
#include "ioctls.h"		/* struct ioctl_group */
#include "kernel/ext4.h"
#include "kernel/userfaultfd.h"
#include "sanitise.h"		/* writable pool */
#include "syscall.h"		/* struct syscallrecord */
#include "utils-macros.h"	/* ARRAY_SIZE */

#define ROUNDS		4000

extern bool fake_rand_bitmask_draws;		/* genl_ops_test.c */

/*
 * What the sanitiser that returned @p reserved for it, as the bytes from @p
 * to what the writable pool hands out next, when nothing else was drawn in
 * between.  The pool wraps once in a long while, which leaves no answer.
 */
static size_t reserved_after(const void *p)
{
	const char *next = get_writable_address(1);

	if (next <= (const char *) p)
		return SIZE_MAX;
	return (size_t) (next - (const char *) p);
}

#ifdef USE_DRM
/*
 * drm_setclientcap() in drivers/gpu/drm/drm_ioctl.c switches on caps 1 to 7
 * and answers any other -EINVAL, and every cap but DRM_CLIENT_CAP_ATOMIC
 * answers a value above 1 the same.  A draw that never names one of the seven
 * leaves its branch unreached, and one past them, or a value the checks
 * refuse, reaches only the refusal.
 */
#define DRM_LAST_CLIENT_CAP	7

static void drm_draws_every_client_cap(void)
{
	static struct syscallrecord rec;
	const struct ioctl_group *grp = fake_ioctl_group("drm");
	unsigned int seen[DRM_LAST_CLIENT_CAP + 1] = { 0 };
	unsigned int i;

	if (grp == NULL)
		BUG("ioctl args: the drm group is not linked");

	for (i = 0; i < ROUNDS; i++) {
		struct drm_set_client_cap *p;

		memset(&rec, 0, sizeof(rec));
		fake_ioctl_request = DRM_IOCTL_SET_CLIENT_CAP;
		grp->sanitise(grp, &rec);

		p = (struct drm_set_client_cap *) rec.a3;
		if (rec.a3 == FAKE_IOCTL_JUNK_ARG)
			BUG("ioctl args: DRM_IOCTL_SET_CLIENT_CAP got no struct");
		if (p->capability < 1 || p->capability > DRM_LAST_CLIENT_CAP) {
			fprintf(stderr, "client cap %llu\n",
				(unsigned long long) p->capability);
			BUG("ioctl args: a client cap the kernel does not know");
		}
		if (p->value > 1)
			BUG("ioctl args: a client cap value the kernel refuses");
		seen[p->capability]++;
	}

	for (i = 1; i <= DRM_LAST_CLIENT_CAP; i++) {
		if (seen[i] == 0) {
			fprintf(stderr, "client cap %u\n", i);
			BUG("ioctl args: a client cap the kernel takes is never drawn");
		}
	}
}
/*
 * drm_mode_object_find() matches an object by id and, unless the type is
 * DRM_MODE_OBJECT_ANY, by type, so a type no object carries is answered
 * -ENOENT before anything else is looked at.  The ioctls that name an
 * object take a type from the kernel's own list, never a random word.  The
 * last is DRM_MODE_OBJECT_COLOROP, which an installed drm_mode.h may lack.
 */
static const __u32 drm_object_types[] = {
	DRM_MODE_OBJECT_CRTC,
	DRM_MODE_OBJECT_CONNECTOR,
	DRM_MODE_OBJECT_ENCODER,
	DRM_MODE_OBJECT_MODE,
	DRM_MODE_OBJECT_PROPERTY,
	DRM_MODE_OBJECT_FB,
	DRM_MODE_OBJECT_BLOB,
	DRM_MODE_OBJECT_PLANE,
	0xfafafafa,
};

static unsigned int object_type_index(__u32 type)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(drm_object_types); i++)
		if (drm_object_types[i] == type)
			return i;
	return ARRAY_SIZE(drm_object_types);
}

static void drm_object_ioctls_name_a_known_object_type(void)
{
	static struct syscallrecord rec;
	const struct ioctl_group *grp = fake_ioctl_group("drm");
	unsigned int seen_get[ARRAY_SIZE(drm_object_types)] = { 0 };
	unsigned int seen_set[ARRAY_SIZE(drm_object_types)] = { 0 };
	unsigned int i;

	if (grp == NULL)
		BUG("ioctl args: the drm group is not linked");

	for (i = 0; i < ROUNDS; i++) {
		struct drm_mode_obj_get_properties *get;
		struct drm_mode_obj_set_property *set;

		memset(&rec, 0, sizeof(rec));
		fake_ioctl_request = DRM_IOCTL_MODE_OBJ_GETPROPERTIES;
		grp->sanitise(grp, &rec);
		if (rec.a3 == FAKE_IOCTL_JUNK_ARG)
			BUG("ioctl args: MODE_OBJ_GETPROPERTIES got no struct");
		get = (struct drm_mode_obj_get_properties *) rec.a3;
		if (object_type_index(get->obj_type) == ARRAY_SIZE(drm_object_types))
			BUG("ioctl args: MODE_OBJ_GETPROPERTIES names a type no object has");
		seen_get[object_type_index(get->obj_type)]++;

		memset(&rec, 0, sizeof(rec));
		fake_ioctl_request = DRM_IOCTL_MODE_OBJ_SETPROPERTY;
		grp->sanitise(grp, &rec);
		if (rec.a3 == FAKE_IOCTL_JUNK_ARG)
			BUG("ioctl args: MODE_OBJ_SETPROPERTY got no struct");
		set = (struct drm_mode_obj_set_property *) rec.a3;
		if (object_type_index(set->obj_type) == ARRAY_SIZE(drm_object_types))
			BUG("ioctl args: MODE_OBJ_SETPROPERTY names a type no object has");
		seen_set[object_type_index(set->obj_type)]++;
	}

	for (i = 0; i < ARRAY_SIZE(drm_object_types); i++) {
		if (seen_get[i] == 0 || seen_set[i] == 0) {
			fprintf(stderr, "object type %#x\n", drm_object_types[i]);
			BUG("ioctl args: a drm object type is never drawn");
		}
	}
}
#endif /* USE_DRM */

static const struct ioctl_group *ext_group(void)
{
	const struct ioctl_group *grp = fake_ioctl_group("ext[234]");

	if (grp == NULL)
		BUG("ioctl args: the ext group is not linked");
	return grp;
}

/* Draw one struct from the ext group's sanitiser for @request. */
static unsigned long ext_arg(const struct ioctl_group *grp,
			     unsigned long request)
{
	static struct syscallrecord rec;

	memset(&rec, 0, sizeof(rec));
	fake_ioctl_request = request;
	grp->sanitise(grp, &rec);
	if (rec.a3 == FAKE_IOCTL_JUNK_ARG)
		BUG("ioctl args: an ext request got no struct");
	return rec.a3;
}

/*
 * ext4_ioctl_shutdown() takes the filesystem down, and ext4_ioctl_setuuid()
 * and ext4_ioctl_set_tune_sb() rewrite its superblock.  The group never
 * lists them: a table entry gets the picker's args, and for SHUTDOWN, an
 * _IOR() request whose buffer is not filled, a recycled zero is the valid
 * "going down" flag.  The group holds its cmds, so a pin or a substitution
 * cannot hand one the args built for another.
 */
static void ext_lists_no_cmd_that_rewrites_the_fs(void)
{
	static const unsigned int never[] = {
		EXT4_IOC_SHUTDOWN,
		EXT4_IOC_SETFSUUID,
		EXT4_IOC_SET_TUNE_SB_PARAM,
	};
	const struct ioctl_group *grp = ext_group();
	size_t i, j;

	if (!grp->cmd_held)
		BUG("ioctl args: the ext group lets a pin move a cmd onto another's args");
	for (i = 0; i < grp->ioctls_cnt; i++)
		for (j = 0; j < ARRAY_SIZE(never); j++)
			if (grp->ioctls[i].request == never[j]) {
				fprintf(stderr, "%s\n", grp->ioctls[i].name);
				BUG("ioctl args: the ext group lists a cmd that rewrites the filesystem");
			}
}

/*
 * ext4_ioctl_getuuid() answers a length of 0 with the uuid's size, a length
 * under 16 or any flag -EINVAL, and otherwise copies 16 bytes out after the
 * 8-byte header, which struct fsuuid's flexible array leaves out of the
 * encoded size.  So the struct is made 24 bytes long, and the length takes
 * each of the four shapes.
 */
static void ext_getfsuuid_args_fit_the_copy(void)
{
	const struct ioctl_group *grp = ext_group();
	unsigned int zero = 0, shorter = 0, exact = 0, longer = 0, flagged = 0;
	unsigned int i;

	for (i = 0; i < ROUNDS; i++) {
		struct fsuuid *u = (struct fsuuid *) ext_arg(grp, EXT4_IOC_GETFSUUID);
		size_t need = sizeof(*u) + 16;

		if (reserved_after(u) < need)
			BUG("ioctl args: EXT4_IOC_GETFSUUID's buffer is shorter than the uuid copy");
		if (u->fsu_len == 0)
			zero++;
		else if (u->fsu_len < 16)
			shorter++;
		else if (u->fsu_len == 16)
			exact++;
		else
			longer++;
		if (u->fsu_flags != 0)
			flagged++;
	}

	if (zero == 0 || shorter == 0 || exact == 0 || longer == 0)
		BUG("ioctl args: a length shape of EXT4_IOC_GETFSUUID is never drawn");
	/* Exact is five draws in eight, and the other three each one in eight. */
	if (exact < ROUNDS * 5 / 8 - ROUNDS / 8)
		BUG("ioctl args: EXT4_IOC_GETFSUUID mostly asks for a length the kernel refuses");
	/* A flag is one call in sixteen; none of them reaches the copy. */
	if (flagged == 0 || flagged > ROUNDS / 8)
		BUG("ioctl args: EXT4_IOC_GETFSUUID flags are not drawn about one call in sixteen");
}

/*
 * ext4_ioctl_get_es_cache() reads the fiemap header and fills as many extents
 * after it as fm_extent_count allows, which the encoded size, the header's,
 * does not cover: the struct is made as long as the count it carries needs.
 * A length of 0 is -EINVAL, a flag but SYNC and CACHE is -EBADR, so most
 * calls carry neither, and the count takes 0 and some nonzero value, the
 * one that reaches the copy-out of the extents.
 */
#define ES_CACHE_COUNT_MAX	32

static void ext_get_es_cache_args_fit_the_extents(void)
{
	const struct ioctl_group *grp = ext_group();
	unsigned int none = 0, some = 0, no_length = 0, odd_flags = 0;
	unsigned int i;

	for (i = 0; i < ROUNDS; i++) {
		struct fiemap *fm = (struct fiemap *) ext_arg(grp, EXT4_IOC_GET_ES_CACHE);
		size_t need = sizeof(*fm) + (size_t) fm->fm_extent_count *
			      sizeof(struct fiemap_extent);

		if (fm->fm_extent_count > ES_CACHE_COUNT_MAX)
			BUG("ioctl args: EXT4_IOC_GET_ES_CACHE asks for more extents than it makes room for");
		if (reserved_after(fm) < need)
			BUG("ioctl args: EXT4_IOC_GET_ES_CACHE's buffer is shorter than its extent count");
		if (fm->fm_extent_count == 0)
			none++;
		else
			some++;
		if (fm->fm_length == 0)
			no_length++;
		if (fm->fm_flags & ~(FIEMAP_FLAG_SYNC | FIEMAP_FLAG_CACHE))
			odd_flags++;
	}

	if (none == 0 || some == 0)
		BUG("ioctl args: EXT4_IOC_GET_ES_CACHE never draws a count of 0 or a nonzero one");
	if (no_length > ROUNDS / 4)
		BUG("ioctl args: EXT4_IOC_GET_ES_CACHE mostly asks for a length of 0");
	if (odd_flags > ROUNDS / 4)
		BUG("ioctl args: EXT4_IOC_GET_ES_CACHE mostly sets a flag the kernel refuses");
}

/*
 * ext4_ioctl_checkpoint() flushes the journal, and with ZEROOUT or DISCARD
 * zeroes or discards all of it, all on the real filesystem the testfile is
 * on.  A word that is valid, no unknown bit and not both of the two, must
 * carry DRY_RUN, which makes the kernel return once it has checked; the
 * rest are refused by those checks.  Each valid shape has to turn up.
 */
static void ext_checkpoint_never_flushes_the_journal(void)
{
	const struct ioctl_group *grp = ext_group();
	unsigned int dry = 0, dry_discard = 0, dry_zeroout = 0, refused = 0;
	unsigned int i;

	for (i = 0; i < ROUNDS; i++) {
		__u32 flags = *(__u32 *) ext_arg(grp, EXT4_IOC_CHECKPOINT);
		bool valid = !(flags & ~EXT4_IOC_CHECKPOINT_FLAG_VALID) &&
			     !((flags & EXT4_IOC_CHECKPOINT_FLAG_DISCARD) &&
			       (flags & EXT4_IOC_CHECKPOINT_FLAG_ZEROOUT));

		if (!valid) {
			refused++;
			continue;
		}
		if (!(flags & EXT4_IOC_CHECKPOINT_FLAG_DRY_RUN)) {
			fprintf(stderr, "flags %#x\n", flags);
			BUG("ioctl args: EXT4_IOC_CHECKPOINT is drawn with flags that flush the journal");
		}
		if (flags == EXT4_IOC_CHECKPOINT_FLAG_DRY_RUN)
			dry++;
		else if (flags == (EXT4_IOC_CHECKPOINT_FLAG_DRY_RUN |
				   EXT4_IOC_CHECKPOINT_FLAG_DISCARD))
			dry_discard++;
		else
			dry_zeroout++;
	}

	if (dry == 0 || dry_discard == 0 || dry_zeroout == 0 || refused == 0)
		BUG("ioctl args: a flag shape of EXT4_IOC_CHECKPOINT is never drawn");
}

/*
 * The hidraw, input and joystick groups list their variable-length cmds
 * with a length of 0 and rewrite a2 to a random length after the pick,
 * whose a3 was built for the size-0 request: a scalar the kernel's copy
 * of the new length then faults on.  A rewritten request that encodes a
 * size has to get a writable buffer of it, as ioctl_arg_for_request()
 * builds, and the length has to stay inside _IOC_SIZE, since one that
 * spills into the direction bits misses the handler's exact match.
 * input's EVIOCGBIT draws its event index unbounded one time in ten, on
 * purpose, which can change any field, hence eight in ten.  The fd is
 * -1, so a request that falls through to the EFAULT probe does not
 * probe the test's own stdin.
 */
#define REWRITE_ROUNDS	400

static const struct ioctl_group *group_listing(unsigned int request)
{
	const struct ioctl_group *const *grps;
	unsigned int n, g;
	size_t i;

	grps = fake_ioctl_groups(&n);
	for (g = 0; g < n; g++)
		for (i = 0; i < grps[g]->ioctls_cnt; i++)
			if (grps[g]->ioctls[i].request == request)
				return grps[g];
	return NULL;
}

static void size_rewrites_rebuild_the_arg(void)
{
	static const unsigned int listed[] = {
		HIDIOCGRAWNAME(0), EVIOCGNAME(0), JSIOCGNAME(0),
	};
	static struct syscallrecord rec;
	unsigned int g;

	for (g = 0; g < ARRAY_SIZE(listed); g++) {
		const struct ioctl_group *grp = group_listing(listed[g]);
		size_t i;

		if (grp == NULL)
			BUG("ioctl args: a size-rewriting group is not linked");

		for (i = 0; i < grp->ioctls_cnt; i++) {
			const struct ioctl *ioc = &grp->ioctls[i];
			unsigned int rewritten = 0, kept_dir = 0;
			int round;

			if (_IOC_DIR(ioc->request) == _IOC_NONE ||
			    _IOC_SIZE(ioc->request) != 0)
				continue;

			for (round = 0; round < REWRITE_ROUNDS; round++) {
				unsigned long size;

				memset(&rec, 0, sizeof(rec));
				rec.a1 = (unsigned long) -1;
				fake_ioctl_request = ioc->request;
				grp->sanitise(grp, &rec);
				if (rec.a2 == ioc->request)
					continue;
				rewritten++;
				if (_IOC_DIR(rec.a2) != _IOC_DIR(ioc->request))
					continue;
				kept_dir++;
				size = _IOC_SIZE(rec.a2);
				if (_IOC_TYPE(rec.a2) == 0 || size == 0)
					continue;
				if (size > page_size)
					size = page_size;
				if (!range_in_writable_pool(rec.a3, size)) {
					fprintf(stderr, "%s: a3 %#lx is no buffer for the rewritten request %#lx\n",
						ioc->name, rec.a3, rec.a2);
					BUG("ioctl args: a size rewrite kept the size-0 request's arg");
				}
			}

			if (rewritten == 0) {
				fprintf(stderr, "%s: never rewritten\n", ioc->name);
				BUG("ioctl args: a size-0 cmd is never given a length");
			}
			if (kept_dir < rewritten * 8 / 10) {
				fprintf(stderr, "%s: %u of %u rewrites kept the direction\n",
					ioc->name, kept_dir, rewritten);
				BUG("ioctl args: a size rewrite spills into the direction bits");
			}
		}
	}
}

/*
 * A request whose number encodes no size, as the legacy raw constants do,
 * goes to the EFAULT probe, and when the probe finds that the kernel
 * dereferences the arg, the arg has to be memory it can copy to and from:
 * a scalar is refused EFAULT on every call, the probe's verdict standing
 * for the whole run.  SIOCGIFFLAGS on a socket copies a struct ifreq from
 * the arg, so the probe calls it a pointer.
 */
static void size0_pointer_requests_get_a_buffer(void)
{
	const struct ioctl_group *grp = group_listing(SIOCGIFFLAGS);
	int fd, round;

	if (grp == NULL)
		BUG("ioctl args: the socket group is not linked");

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		printf("(no AF_INET socket, size-0 pointer check skipped) ");
		return;
	}
	if (ioctl_efault_classify(grp, fd, SIOCGIFFLAGS) != IOCTL_ARG_POINTER)
		BUG("ioctl args: the probe does not call SIOCGIFFLAGS a pointer");

	for (round = 0; round < 16; round++) {
		unsigned long arg = ioctl_arg_for_request(grp, fd, SIOCGIFFLAGS);

		if (!range_in_writable_pool(arg, page_size)) {
			fprintf(stderr, "SIOCGIFFLAGS: arg %#lx is no buffer\n", arg);
			BUG("ioctl args: a size-0 request the probe calls a pointer got no buffer");
		}
	}
	close(fd);
}

/*
 * The kernel arms a uffd once, with the first UFFDIO_API that succeeds,
 * and nothing reads these fds: one armed without UFFD_FEATURE_SIGBUS
 * leaves a later fault on a range it registered asleep in
 * handle_userfault() until the watchdog.  userfaultfd() pools its fds
 * unarmed, so the group's handshake may be the one that arms them.
 */
static void userfaultfd_api_always_asks_sigbus(void)
{
	static struct syscallrecord rec;
	const struct ioctl_group *grp = fake_ioctl_group("userfaultfd");
	unsigned int i, others = 0;

	if (grp == NULL)
		BUG("ioctl args: the userfaultfd group is not linked");

	fake_rand_bitmask_draws = true;
	for (i = 0; i < ROUNDS; i++) {
		const struct uffdio_api *ua;

		memset(&rec, 0, sizeof(rec));
		fake_ioctl_request = UFFDIO_API;
		grp->sanitise(grp, &rec);
		if (rec.a3 == FAKE_IOCTL_JUNK_ARG)
			BUG("ioctl args: UFFDIO_API got no struct");

		ua = (const struct uffdio_api *) rec.a3;
		if (!(ua->features & UFFD_FEATURE_SIGBUS))
			BUG("ioctl args: a UFFDIO_API handshake without UFFD_FEATURE_SIGBUS");
		if (ua->features & ~(__u64) UFFD_FEATURE_SIGBUS)
			others++;
	}
	fake_rand_bitmask_draws = false;
	if (others == 0)
		BUG("ioctl args: UFFDIO_API never asks for a feature past SIGBUS");
}

/*
 * The fallback device each tunnel module makes in every netns, the parm its
 * handler reads (ip_tunnel_siocdevprivate(), ip6_tnl_siocdevprivate(),
 * ip6gre_tunnel_siocdevprivate(), vti6_siocdevprivate()), and what its add
 * and change take: the protocols ipip_tunnel_ioctl_verify_protocol(),
 * ipgre_tunnel_ctl(), vti_tunnel_ctl() and ipip6_valid_ip_proto() allow, or
 * the IPv6 protos (MPLS left out); ip6gre reads none.  vti alone does not
 * refuse fragment bits, and the GRE kinds refuse GRE_VERSION and
 * GRE_ROUTING.
 */
enum tunnel_parm_model { MODEL_IP, MODEL_IP6, MODEL_IP6_2 };

static const struct {
	const char *fallback;
	enum tunnel_parm_model parm;
	unsigned char protos[3];
	unsigned int n_protos;	/* 0: any */
	bool frag_checked;
	bool gre;
} tunnel_models[] = {
	{ "tunl0",	MODEL_IP,	{ 0, IPPROTO_IPIP }, 2, true, false },
	{ "gre0",	MODEL_IP,	{ IPPROTO_GRE }, 1, true, true },
	{ "ip_vti0",	MODEL_IP,	{ IPPROTO_IPIP }, 1, false, false },
	{ "sit0",	MODEL_IP,	{ 0, IPPROTO_IPIP, IPPROTO_IPV6 }, 3, true, false },
	{ "ip6tnl0",	MODEL_IP6,	{ 0, IPPROTO_IPIP, IPPROTO_IPV6 }, 3, false, false },
	{ "ip6gre0",	MODEL_IP6_2,	{ 0 }, 0, false, true },
	{ "ip6_vti0",	MODEL_IP6_2,	{ 0, IPPROTO_IPV6 }, 2, false, false },
};

#define TUNNEL_ROUNDS	2000

/* The name a tunnel cmd's add makes on each kind's fallback, learned. */
static char tunnel_names[ARRAY_SIZE(tunnel_models)][IFNAMSIZ];

/* The tunnel model whose fallback, or whose learned tunnel, is @name. */
static int tunnel_model(const char *name)
{
	unsigned int m;

	for (m = 0; m < ARRAY_SIZE(tunnel_models); m++)
		if (strcmp(name, tunnel_models[m].fallback) == 0 ||
		    (tunnel_names[m][0] != '\0' &&
		     strcmp(name, tunnel_names[m]) == 0))
			return m;
	return -1;
}

static bool tunnel_proto_taken(unsigned int m, unsigned char proto)
{
	unsigned int i;

	if (tunnel_models[m].n_protos == 0)
		return true;
	for (i = 0; i < tunnel_models[m].n_protos; i++)
		if (tunnel_models[m].protos[i] == proto)
			return true;
	return false;
}

/* The parm's name, or NULL when it runs past IFNAMSIZ. */
static const char *tunnel_parm_name(unsigned int m, const void *data)
{
	const char *name = data;	/* each parm opens with it */

	(void) m;
	return memchr(name, '\0', IFNAMSIZ) != NULL ? name : NULL;
}

/* Whether model @m's add and change take the parm at @data. */
static bool tunnel_parm_taken(unsigned int m, const void *data)
{
	const struct ip6_tnl_parm2 *p62 = data;
	const struct ip6_tnl_parm *p6 = data;
	const struct ip_tunnel_parm *p = data;

	if (tunnel_parm_name(m, data) == NULL)
		return false;
	switch (tunnel_models[m].parm) {
	case MODEL_IP:
		if (p->iph.version != 4 || p->iph.ihl != 5 ||
		    !tunnel_proto_taken(m, p->iph.protocol))
			return false;
		if (tunnel_models[m].frag_checked &&
		    (p->iph.frag_off & htons(~0x4000)))
			return false;
		return !tunnel_models[m].gre ||
		       !((p->i_flags | p->o_flags) & (GRE_VERSION | GRE_ROUTING));
	case MODEL_IP6:
		return tunnel_proto_taken(m, p6->proto);
	case MODEL_IP6_2:
		if (!tunnel_proto_taken(m, p62->proto))
			return false;
		return !tunnel_models[m].gre ||
		       !((p62->i_flags | p62->o_flags) & (GRE_VERSION | GRE_ROUTING));
	}
	return false;
}

/* Draw one arg of @cmd from the socket group; NULL when it kept the
 * picker's. */
static const void *socket_request(const struct ioctl_group *grp,
				  unsigned long cmd)
{
	static struct syscallrecord rec;

	memset(&rec, 0, sizeof(rec));
	fake_ioctl_request = cmd;
	grp->sanitise(grp, &rec);
	if (rec.a3 == FAKE_IOCTL_JUNK_ARG)
		return NULL;
	return (const void *) rec.a3;
}

/* The bridge the socket group's SIOCBRADDBR makes, learned. */
static char bridge_name[IFNAMSIZ];

/*
 * br_dev_siocdevprivate(): a BRCTL_ cmd it handles, a timer inside what
 * br_set_hello_time(), br_set_max_age() and, with STP on,
 * br_set_forward_delay() take (1 to 10, 6 to 40 and 2 to 30 seconds, in
 * clock ticks of USER_HZ, 100), a port that is an ifindex, and somewhere for
 * BRCTL_GET_BRIDGE_INFO to copy to.
 */
static bool bridge_args_taken(const unsigned long *args)
{
	switch (args[0]) {
	case BRCTL_SET_BRIDGE_FORWARD_DELAY:
		return args[1] >= 200 && args[1] <= 3000;
	case BRCTL_SET_BRIDGE_HELLO_TIME:
		return args[1] >= 100 && args[1] <= 1000;
	case BRCTL_SET_BRIDGE_MAX_AGE:
		return args[1] >= 600 && args[1] <= 4000;
	case BRCTL_SET_AGEING_TIME:
	case BRCTL_SET_BRIDGE_STP_STATE:
	case BRCTL_SET_BRIDGE_PRIORITY:
		return true;
	case BRCTL_ADD_IF:
	case BRCTL_DEL_IF:
	case BRCTL_GET_BRIDGE_INFO:
		return args[1] != 0;
	}
	return false;
}

/*
 * br_ioctl_stub() reads IFNAMSIZ bytes of name for SIOCBRADDBR and
 * SIOCBRDELBR, and an ifreq naming a bridge, with the port's ifindex, for
 * SIOCBRADDIF and SIOCBRDELIF.  The group builds each seven times in eight,
 * and every one names the bridge its add makes, so the add, the ports and
 * the delete meet one device.
 */
static void socket_bridge_requests_name_one_bridge(void)
{
	static const unsigned long cmds[] = {
		SIOCBRADDBR, SIOCBRDELBR, SIOCBRADDIF, SIOCBRDELIF,
	};
	const struct ioctl_group *grp = fake_ioctl_group("[socket]");
	unsigned int built = 0, drawn = 0;
	unsigned int c, i;

	if (grp == NULL)
		BUG("ioctl args: the socket group is not linked");

	for (c = 0; c < ARRAY_SIZE(cmds); c++) {
		for (i = 0; i < TUNNEL_ROUNDS; i++) {
			const char *arg = socket_request(grp, cmds[c]);
			const char *name = arg;

			drawn++;
			if (arg == NULL)
				continue;
			built++;
			if (cmds[c] == SIOCBRADDIF || cmds[c] == SIOCBRDELIF) {
				const struct ifreq *ifr = (const void *) arg;

				name = ifr->ifr_name;
				if (ifr->ifr_ifindex <= 0)
					BUG("ioctl args: a bridge port is no ifindex");
			}
			if (memchr(name, '\0', IFNAMSIZ) == NULL || name[0] == '\0')
				BUG("ioctl args: a bridge request names no bridge");
			if (bridge_name[0] == '\0')
				strcpy(bridge_name, name);
			else if (strcmp(name, bridge_name) != 0)
				BUG("ioctl args: two bridge requests name two bridges");
		}
	}
	if (built < drawn * 0.80 || built > drawn * 0.95) {
		fprintf(stderr, "bridge cmds: %u of %u built\n", built, drawn);
		BUG("ioctl args: the bridge cmds are not mostly built");
	}
}

/*
 * dev_ioctl() finds the device a tunnel cmd acts on by ifr_name, and its
 * handler reads the parm of its kind behind ifr_data.  The group builds
 * the request seven times in eight.  One in eight of those names the
 * bridge, whose handler takes the old bridge ioctls through any
 * SIOCDEVPRIVATE cmd; the rest name a fallback device half the time and
 * the tunnel an add on that kind's fallback names the rest, so that the
 * add, the change and the delete meet one device.  The parm takes the
 * kind's add and change seven times in eight, and names that tunnel 15
 * times in 16 of those.  Over thousands of requests the bounds are many
 * standard deviations out.
 */
static void socket_tunnel_requests_name_their_device(void)
{
	static const unsigned long cmds[] = {
		SIOCGETTUNNEL, SIOCADDTUNNEL, SIOCDELTUNNEL, SIOCCHGTUNNEL,
	};
	const struct ioctl_group *grp = fake_ioctl_group("[socket]");
	unsigned int built = 0, drawn = 0, fallbacks = 0, bridged = 0;
	unsigned int changes = 0, taken = 0, named = 0;
	unsigned int c, i;

	if (grp == NULL)
		BUG("ioctl args: the socket group is not linked");

	/* Learn the tunnel each kind's add makes from its fallback's adds. */
	for (i = 0; i < TUNNEL_ROUNDS; i++) {
		const struct ifreq *ifr = socket_request(grp, SIOCADDTUNNEL);
		const char *name;
		int m;

		if (ifr == NULL || memchr(ifr->ifr_name, '\0', IFNAMSIZ) == NULL)
			continue;
		for (m = 0; m < (int) ARRAY_SIZE(tunnel_models); m++)
			if (strcmp(ifr->ifr_name, tunnel_models[m].fallback) == 0)
				break;
		if (m == (int) ARRAY_SIZE(tunnel_models) ||
		    !tunnel_parm_taken(m, ifr->ifr_data))
			continue;
		name = tunnel_parm_name(m, ifr->ifr_data);
		if (name[0] != '\0' && tunnel_names[m][0] == '\0')
			strcpy(tunnel_names[m], name);
	}

	for (c = 0; c < ARRAY_SIZE(cmds); c++) {
		for (i = 0; i < TUNNEL_ROUNDS; i++) {
			const struct ifreq *ifr = socket_request(grp, cmds[c]);
			const char *name;
			int m;

			drawn++;
			if (ifr == NULL)
				continue;
			built++;
			if (strncmp(ifr->ifr_name, bridge_name, IFNAMSIZ) == 0) {
				bridged++;
				if (ifr->ifr_data == NULL ||
				    !bridge_args_taken((const void *) ifr->ifr_data))
					BUG("ioctl args: an old bridge ioctl the bridge refuses");
				continue;
			}
			if (memchr(ifr->ifr_name, '\0', IFNAMSIZ) == NULL ||
			    (m = tunnel_model(ifr->ifr_name)) < 0) {
				fprintf(stderr, "ifr_name %.16s\n", ifr->ifr_name);
				BUG("ioctl args: a tunnel request names no tunnel device");
			}
			if (ifr->ifr_data == NULL)
				BUG("ioctl args: a tunnel request carries no parm");
			fallbacks += strcmp(ifr->ifr_name,
					    tunnel_models[m].fallback) == 0;
			if (cmds[c] != SIOCADDTUNNEL && cmds[c] != SIOCCHGTUNNEL)
				continue;
			changes++;
			if (!tunnel_parm_taken(m, ifr->ifr_data))
				continue;
			taken++;
			name = tunnel_parm_name(m, ifr->ifr_data);
			named += strcmp(name, tunnel_names[m]) == 0;
		}
	}

	if (built < drawn * 0.80 || built > drawn * 0.95 ||
	    bridged < built * 0.08 || bridged > built * 0.18 ||
	    fallbacks < (built - bridged) * 0.40 ||
	    fallbacks > (built - bridged) * 0.60 ||
	    taken < changes * 0.80 || named < taken * 0.85) {
		fprintf(stderr, "tunnel cmds: %u of %u built, %u name the bridge, "
			"%u a fallback, %u of %u adds and changes taken, "
			"%u of those name the tunnel\n", built, drawn, bridged,
			fallbacks, taken, changes, named);
		BUG("ioctl args: the tunnel requests are not ones the tunnel handlers take");
	}
}

void ioctl_args_self_check(void);
void ioctl_args_self_check(void)
{
	if (get_writable_struct(1) == NULL)
		writable_pool_init();

#ifdef USE_DRM
	drm_draws_every_client_cap();
	drm_object_ioctls_name_a_known_object_type();
#endif
	ext_lists_no_cmd_that_rewrites_the_fs();
	ext_getfsuuid_args_fit_the_copy();
	ext_get_es_cache_args_fit_the_extents();
	ext_checkpoint_never_flushes_the_journal();
	size_rewrites_rebuild_the_arg();
	size0_pointer_requests_get_a_buffer();
	userfaultfd_api_always_asks_sigbus();
	socket_bridge_requests_name_one_bridge();
	socket_tunnel_requests_name_their_device();
}
