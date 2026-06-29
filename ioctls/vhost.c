
#ifdef USE_VHOST
#include <linux/vhost.h>
#include <linux/vhost_types.h>
#include <string.h>

#include "arch.h"
#include "ioctls.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

static const struct ioctl vhost_ioctls[] = {
	IOCTL(VHOST_GET_FEATURES),
	IOCTL(VHOST_SET_FEATURES),
	IOCTL(VHOST_SET_OWNER),
	IOCTL(VHOST_RESET_OWNER),
	IOCTL(VHOST_SET_MEM_TABLE),
	IOCTL(VHOST_SET_LOG_BASE),
	IOCTL(VHOST_SET_LOG_FD),
	IOCTL(VHOST_SET_VRING_NUM),
	IOCTL(VHOST_SET_VRING_ADDR),
	IOCTL(VHOST_SET_VRING_BASE),
	IOCTL(VHOST_GET_VRING_BASE),
	IOCTL(VHOST_SET_VRING_KICK),
	IOCTL(VHOST_SET_VRING_CALL),
	IOCTL(VHOST_SET_VRING_ERR),
	IOCTL(VHOST_NET_SET_BACKEND),
#ifdef VHOST_GET_BACKEND_FEATURES
	IOCTL(VHOST_GET_BACKEND_FEATURES),
#endif
#ifdef VHOST_SET_BACKEND_FEATURES
	IOCTL(VHOST_SET_BACKEND_FEATURES),
#endif
#ifdef VHOST_NEW_WORKER
	IOCTL(VHOST_NEW_WORKER),
#endif
#ifdef VHOST_FREE_WORKER
	IOCTL(VHOST_FREE_WORKER),
#endif
#ifdef VHOST_ATTACH_VRING_WORKER
	IOCTL(VHOST_ATTACH_VRING_WORKER),
#endif
#ifdef VHOST_GET_VRING_WORKER
	IOCTL(VHOST_GET_VRING_WORKER),
#endif
#ifdef VHOST_SET_FORK_FROM_OWNER
	IOCTL(VHOST_SET_FORK_FROM_OWNER),
#endif
#ifdef VHOST_SCSI_SET_ENDPOINT
	IOCTL(VHOST_SCSI_SET_ENDPOINT),
#endif
#ifdef VHOST_SCSI_CLEAR_ENDPOINT
	IOCTL(VHOST_SCSI_CLEAR_ENDPOINT),
#endif
#ifdef VHOST_SCSI_GET_ABI_VERSION
	IOCTL(VHOST_SCSI_GET_ABI_VERSION),
#endif
#ifdef VHOST_SCSI_SET_EVENTS_MISSED
	IOCTL(VHOST_SCSI_SET_EVENTS_MISSED),
#endif
#ifdef VHOST_SCSI_GET_EVENTS_MISSED
	IOCTL(VHOST_SCSI_GET_EVENTS_MISSED),
#endif
#ifdef VHOST_VSOCK_SET_GUEST_CID
	IOCTL(VHOST_VSOCK_SET_GUEST_CID),
#endif
#ifdef VHOST_VSOCK_SET_RUNNING
	IOCTL(VHOST_VSOCK_SET_RUNNING),
#endif
};

/*
 * Plausible u32 vring index.  The kernel rejects index >= dev->nvqs early,
 * so cap to the largest count any in-tree vhost device exposes (vhost-scsi
 * uses VHOST_SCSI_MAX_VQ today; 4 covers net/vsock and most scsi configs).
 */
static unsigned int vhost_rand_vq_index(void)
{
	return rnd_modulo_u32(4);
}

static void sanitise_vhost_vring_state_num(struct syscallrecord *rec)
{
	struct vhost_vring_state *s;

	s = (struct vhost_vring_state *) get_writable_struct(sizeof(*s));
	if (!s)
		return;
	memset(s, 0, sizeof(*s));
	s->index = vhost_rand_vq_index();
	/*
	 * The kernel demands is_power_of_2(num) && num <= 0xffff.  Occasionally
	 * leave num at 0 so we still exercise the rejection path.
	 */
	if (RAND_BOOL())
		s->num = 0;
	else
		s->num = 1u << (1 + rnd_modulo_u32(15));
	rec->a3 = (unsigned long) s;
}

static void sanitise_vhost_vring_state_base(struct syscallrecord *rec)
{
	struct vhost_vring_state *s;

	s = (struct vhost_vring_state *) get_writable_struct(sizeof(*s));
	if (!s)
		return;
	memset(s, 0, sizeof(*s));
	s->index = vhost_rand_vq_index();
	s->num = rand32() & 0xffff;
	rec->a3 = (unsigned long) s;
}

static void sanitise_vhost_vring_addr(struct syscallrecord *rec)
{
	struct vhost_vring_addr *a;

	a = (struct vhost_vring_addr *) get_writable_struct(sizeof(*a));
	if (!a)
		return;
	memset(a, 0, sizeof(*a));
	a->index = vhost_rand_vq_index();
	a->flags = RAND_BOOL() ? 0 : (1u << VHOST_VRING_F_LOG);
	a->desc_user_addr  = (__u64)(unsigned long) get_writable_struct(page_size);
	a->used_user_addr  = (__u64)(unsigned long) get_writable_struct(page_size);
	a->avail_user_addr = (__u64)(unsigned long) get_writable_struct(page_size);
	a->log_guest_addr  = (__u64)(unsigned long) get_writable_struct(page_size);
	rec->a3 = (unsigned long) a;
}

static void sanitise_vhost_vring_file(struct syscallrecord *rec)
{
	struct vhost_vring_file *f;

	f = (struct vhost_vring_file *) get_writable_struct(sizeof(*f));
	if (!f)
		return;
	memset(f, 0, sizeof(*f));
	f->index = vhost_rand_vq_index();
	/*
	 * fd == -1 is the documented deassign/disable sentinel for vhost
	 * eventfd/backend slots.  Never hand in a real backend or tap fd
	 * here: the device must stay inert on a shared host.
	 */
	f->fd = -1;
	rec->a3 = (unsigned long) f;
}

static void sanitise_vhost_features(struct syscallrecord *rec)
{
	/*
	 * VHOST_SET_FEATURES / VHOST_SET_BACKEND_FEATURES are _IOW of a
	 * __u64 passed by value, not by pointer.  Bias toward a plausible
	 * supported subset so the negotiation path is reached, but
	 * occasionally hand over fully random bits to keep the reject path
	 * live too.
	 */
	if (RAND_BOOL())
		rec->a3 = 0;
	else if (RAND_BOOL())
		rec->a3 = rand64() & ((1ULL << VHOST_F_LOG_ALL) |
				      (1ULL << VHOST_NET_F_VIRTIO_NET_HDR));
	else
		rec->a3 = rand64();
}

static void vhost_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case VHOST_SET_VRING_NUM:
		sanitise_vhost_vring_state_num(rec);
		break;
	case VHOST_SET_VRING_BASE:
	case VHOST_GET_VRING_BASE:
		sanitise_vhost_vring_state_base(rec);
		break;
	case VHOST_SET_VRING_ADDR:
		sanitise_vhost_vring_addr(rec);
		break;
	case VHOST_SET_VRING_KICK:
	case VHOST_SET_VRING_CALL:
	case VHOST_SET_VRING_ERR:
	case VHOST_NET_SET_BACKEND:
		sanitise_vhost_vring_file(rec);
		break;
	case VHOST_SET_FEATURES:
#ifdef VHOST_SET_BACKEND_FEATURES
	case VHOST_SET_BACKEND_FEATURES:
#endif
		sanitise_vhost_features(rec);
		break;
	default:
		break;
	}
}

static const char *const vhost_devs[] = {
	"vhost-net",
	"vhost-vsock",
};

static const struct ioctl_group vhost_grp = {
	.devtype = DEV_MISC,
	.devs = vhost_devs,
	.devs_cnt = ARRAY_SIZE(vhost_devs),
	.sanitise = vhost_sanitise,
	.ioctls = vhost_ioctls,
	.ioctls_cnt = ARRAY_SIZE(vhost_ioctls),
};

REG_IOCTL_GROUP(vhost_grp)
#endif /* USE_VHOST */
