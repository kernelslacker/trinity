/*
 * Self-check for the args the ioctl group sanitisers build: what they draw
 * has to be what the kernel's own checks take, and the draw has to reach all
 * of it.  The drm group's client caps are the first.
 */

#include <stdio.h>
#include <string.h>

#ifdef USE_DRM
#include <drm/drm.h>
#include <drm/drm_mode.h>
#endif

#include "debug.h"		/* BUG */
#include "fake_ioctls.h"
#include "ioctls.h"		/* struct ioctl_group */
#include "sanitise.h"		/* writable pool */
#include "syscall.h"		/* struct syscallrecord */
#include "utils-macros.h"	/* ARRAY_SIZE */

#define ROUNDS		4000

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
 * object take a type from the kernel's own list, never a random word.
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

void ioctl_args_self_check(void);
void ioctl_args_self_check(void)
{
	if (get_writable_struct(1) == NULL)
		writable_pool_init();

#ifdef USE_DRM
	drm_draws_every_client_cap();
	drm_object_ioctls_name_a_known_object_type();
#endif
}
