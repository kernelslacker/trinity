/*
 * Self-check for the args the ioctl group sanitisers build: what they draw
 * has to be what the kernel's own checks take, and the draw has to reach all
 * of it.  The drm group's client caps are the first.
 */

#include <stdio.h>
#include <string.h>

#ifdef USE_DRM
#include <drm/drm.h>
#endif

#include "debug.h"		/* BUG */
#include "fake_ioctls.h"
#include "ioctls.h"		/* struct ioctl_group */
#include "sanitise.h"		/* writable pool */
#include "syscall.h"		/* struct syscallrecord */

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
#endif /* USE_DRM */

void ioctl_args_self_check(void);
void ioctl_args_self_check(void)
{
	if (get_writable_struct(1) == NULL)
		writable_pool_init();

#ifdef USE_DRM
	drm_draws_every_client_cap();
#endif
}
