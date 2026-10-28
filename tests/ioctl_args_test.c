/*
 * Self-check for the args the ioctl group sanitisers build: what they draw
 * has to be what the kernel's own checks take, and the draw has to reach all
 * of it.  The drm group's client caps and object types, and the ext group's
 * new requests, are covered.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef USE_DRM
#include <drm/drm.h>
#include <drm/drm_mode.h>
#endif

#include "debug.h"		/* BUG */
#include "fake_ioctls.h"
#include "ioctls.h"		/* struct ioctl_group */
#include "kernel/ext4.h"
#include "sanitise.h"		/* writable pool */
#include "syscall.h"		/* struct syscallrecord */
#include "utils-macros.h"	/* ARRAY_SIZE */

#define ROUNDS		4000

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
}
