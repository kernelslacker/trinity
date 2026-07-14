
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

/*
 * Compile-time: every fixed-shape VHOST_* command the sanitisers
 * below fill must have sizeof(struct) matching the _IOC_SIZE encoded
 * in its request bits.  A mismatch means <linux/vhost.h> or
 * <linux/vhost_types.h> moved under us and the sanitiser is
 * memset()ing / stamping into a buffer the kernel copies less of
 * than we prepared (under-encoded) or reads past (over-encoded).
 * VHOST_SET_VRING_NUM, VHOST_SET_VRING_BASE and VHOST_GET_VRING_BASE
 * all take struct vhost_vring_state; VHOST_SET_VRING_KICK,
 * VHOST_SET_VRING_CALL, VHOST_SET_VRING_ERR and VHOST_NET_SET_BACKEND
 * all take struct vhost_vring_file.  Each command gets its own assert
 * -- the sides can drift independently in a header refactor.
 *
 * VHOST_GET_FEATURES, VHOST_SET_FEATURES, VHOST_GET_BACKEND_FEATURES,
 * VHOST_SET_BACKEND_FEATURES, VHOST_VSOCK_SET_GUEST_CID and
 * VHOST_SET_LOG_BASE encode a bare __u64; VHOST_SET_LOG_FD,
 * VHOST_SCSI_GET_ABI_VERSION and VHOST_VSOCK_SET_RUNNING encode a
 * bare int; VHOST_SCSI_SET_EVENTS_MISSED and
 * VHOST_SCSI_GET_EVENTS_MISSED encode a bare __u32;
 * VHOST_SET_FORK_FROM_OWNER encodes a bare __u8; VHOST_SET_OWNER and
 * VHOST_RESET_OWNER are _IO() with no arg; VHOST_SET_MEM_TABLE
 * carries struct vhost_memory with a trailing flex array of
 * vhost_memory_region.  All are intentionally absent -- asserting
 * sizeof(struct) against a scalar, a zero _IOC_SIZE or a flex-tail
 * prefix would be the wrong shape of check.
 */
IOCTL_SIZE_ASSERT(VHOST_SET_VRING_NUM, struct vhost_vring_state);
IOCTL_SIZE_ASSERT(VHOST_SET_VRING_BASE, struct vhost_vring_state);
IOCTL_SIZE_ASSERT(VHOST_GET_VRING_BASE, struct vhost_vring_state);
#ifdef VHOST_SET_VRING_BUSYLOOP_TIMEOUT
IOCTL_SIZE_ASSERT(VHOST_SET_VRING_BUSYLOOP_TIMEOUT, struct vhost_vring_state);
#endif
#ifdef VHOST_GET_VRING_BUSYLOOP_TIMEOUT
IOCTL_SIZE_ASSERT(VHOST_GET_VRING_BUSYLOOP_TIMEOUT, struct vhost_vring_state);
#endif
IOCTL_SIZE_ASSERT(VHOST_SET_VRING_ADDR, struct vhost_vring_addr);
IOCTL_SIZE_ASSERT(VHOST_SET_VRING_KICK, struct vhost_vring_file);
IOCTL_SIZE_ASSERT(VHOST_SET_VRING_CALL, struct vhost_vring_file);
IOCTL_SIZE_ASSERT(VHOST_SET_VRING_ERR, struct vhost_vring_file);
IOCTL_SIZE_ASSERT(VHOST_NET_SET_BACKEND, struct vhost_vring_file);
/*
 * vDPA fixed-shape commands.  Same rules as above: only asserts on
 * commands whose _IOC_SIZE encodes a concrete struct (not a scalar,
 * not _IO, not a flex-tail).  VHOST_VDPA_GET_DEVICE_ID / GET_STATUS /
 * SET_STATUS / GET_VRING_NUM / SET_CONFIG_CALL / GET_CONFIG_SIZE /
 * GET_AS_NUM / GET_VQS_COUNT / GET_GROUP_NUM encode a bare scalar;
 * VHOST_VDPA_SUSPEND / RESUME are _IO() with no arg;
 * VHOST_VDPA_GET_CONFIG / SET_CONFIG carry struct vhost_vdpa_config
 * with a trailing flex buf[].
 */
#ifdef VHOST_VDPA_SET_VRING_ENABLE
IOCTL_SIZE_ASSERT(VHOST_VDPA_SET_VRING_ENABLE, struct vhost_vring_state);
#endif
#ifdef VHOST_VDPA_GET_IOVA_RANGE
IOCTL_SIZE_ASSERT(VHOST_VDPA_GET_IOVA_RANGE, struct vhost_vdpa_iova_range);
#endif
#ifdef VHOST_VDPA_GET_VRING_GROUP
IOCTL_SIZE_ASSERT(VHOST_VDPA_GET_VRING_GROUP, struct vhost_vring_state);
#endif
#ifdef VHOST_VDPA_SET_GROUP_ASID
IOCTL_SIZE_ASSERT(VHOST_VDPA_SET_GROUP_ASID, struct vhost_vring_state);
#endif
#ifdef VHOST_VDPA_GET_VRING_DESC_GROUP
IOCTL_SIZE_ASSERT(VHOST_VDPA_GET_VRING_DESC_GROUP, struct vhost_vring_state);
#endif
#ifdef VHOST_VDPA_GET_VRING_SIZE
IOCTL_SIZE_ASSERT(VHOST_VDPA_GET_VRING_SIZE, struct vhost_vring_state);
#endif

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
#ifdef VHOST_SET_VRING_BUSYLOOP_TIMEOUT
	IOCTL(VHOST_SET_VRING_BUSYLOOP_TIMEOUT),
#endif
#ifdef VHOST_GET_VRING_BUSYLOOP_TIMEOUT
	IOCTL(VHOST_GET_VRING_BUSYLOOP_TIMEOUT),
#endif
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
#ifdef VHOST_SET_FEATURES_ARRAY
	IOCTL(VHOST_SET_FEATURES_ARRAY),
	IOCTL(VHOST_GET_FEATURES_ARRAY),
#endif
#ifdef VHOST_VDPA_GET_DEVICE_ID
	IOCTL(VHOST_VDPA_GET_DEVICE_ID),
#endif
#ifdef VHOST_VDPA_GET_STATUS
	IOCTL(VHOST_VDPA_GET_STATUS),
#endif
#ifdef VHOST_VDPA_SET_STATUS
	IOCTL(VHOST_VDPA_SET_STATUS),
#endif
#ifdef VHOST_VDPA_GET_CONFIG
	IOCTL(VHOST_VDPA_GET_CONFIG),
#endif
#ifdef VHOST_VDPA_SET_CONFIG
	IOCTL(VHOST_VDPA_SET_CONFIG),
#endif
#ifdef VHOST_VDPA_SET_VRING_ENABLE
	IOCTL(VHOST_VDPA_SET_VRING_ENABLE),
#endif
#ifdef VHOST_VDPA_GET_VRING_NUM
	IOCTL(VHOST_VDPA_GET_VRING_NUM),
#endif
#ifdef VHOST_VDPA_SET_CONFIG_CALL
	IOCTL(VHOST_VDPA_SET_CONFIG_CALL),
#endif
#ifdef VHOST_VDPA_GET_IOVA_RANGE
	IOCTL(VHOST_VDPA_GET_IOVA_RANGE),
#endif
#ifdef VHOST_VDPA_GET_CONFIG_SIZE
	IOCTL(VHOST_VDPA_GET_CONFIG_SIZE),
#endif
#ifdef VHOST_VDPA_GET_AS_NUM
	IOCTL(VHOST_VDPA_GET_AS_NUM),
#endif
#ifdef VHOST_VDPA_GET_VRING_GROUP
	IOCTL(VHOST_VDPA_GET_VRING_GROUP),
#endif
#ifdef VHOST_VDPA_SET_GROUP_ASID
	IOCTL(VHOST_VDPA_SET_GROUP_ASID),
#endif
#ifdef VHOST_VDPA_SUSPEND
	IOCTL(VHOST_VDPA_SUSPEND),
#endif
#ifdef VHOST_VDPA_RESUME
	IOCTL(VHOST_VDPA_RESUME),
#endif
#ifdef VHOST_VDPA_GET_VRING_DESC_GROUP
	IOCTL(VHOST_VDPA_GET_VRING_DESC_GROUP),
#endif
#ifdef VHOST_VDPA_GET_VQS_COUNT
	IOCTL(VHOST_VDPA_GET_VQS_COUNT),
#endif
#ifdef VHOST_VDPA_GET_GROUP_NUM
	IOCTL(VHOST_VDPA_GET_GROUP_NUM),
#endif
#ifdef VHOST_VDPA_GET_VRING_SIZE
	IOCTL(VHOST_VDPA_GET_VRING_SIZE),
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

static void sanitise_vhost_set_mem_table(struct syscallrecord *rec)
{
	struct vhost_memory *m;
	unsigned int n, i;
	size_t sz;

	n = 1 + rnd_modulo_u32(4);
	sz = sizeof(*m) + n * sizeof(struct vhost_memory_region);
	m = (struct vhost_memory *) get_writable_struct(sz);
	if (!m)
		return;
	memset(m, 0, sz);
	m->nregions = n;
	for (i = 0; i < n; i++) {
		struct vhost_memory_region *r = &m->regions[i];

		r->guest_phys_addr = (__u64) rnd_modulo_u32(0x10000) * page_size;
		r->memory_size = (__u64) (1 + rnd_modulo_u32(16)) * page_size;
		r->userspace_addr = (__u64)(unsigned long) get_writable_struct(page_size);
	}
	rec->a3 = (unsigned long) m;
}

static void sanitise_vhost_set_log_fd(struct syscallrecord *rec)
{
	int *p;

	p = (int *) get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));
	/*
	 * fd == -1 is the documented disable sentinel for the log eventfd.
	 * Never hand in a real fd on a shared host.
	 */
	*p = -1;
	rec->a3 = (unsigned long) p;
}

static void sanitise_vhost_set_log_base(struct syscallrecord *rec)
{
	__u64 *p;

	p = (__u64 *) get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));
	*p = (__u64)(unsigned long) get_writable_struct(page_size);
	rec->a3 = (unsigned long) p;
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

/*
 * vDPA vring_state carriers.  VHOST_VDPA_SET_VRING_ENABLE uses
 * .index for the vq and .num as a 0/1 enable flag; the *_ASID and
 * *_GROUP variants overload the same struct with group/asid/vq
 * indices.  Bound .num to a small integer so the enable path stays
 * on the plausible-input side of the fence rather than being
 * indistinguishable from bulk random data.
 */
static void sanitise_vhost_vdpa_vring_state(struct syscallrecord *rec)
{
	struct vhost_vring_state *s;

	s = (struct vhost_vring_state *) get_writable_struct(sizeof(*s));
	if (!s)
		return;
	memset(s, 0, sizeof(*s));
	s->index = vhost_rand_vq_index();
	s->num = rnd_modulo_u32(4);
	rec->a3 = (unsigned long) s;
}

#if defined(VHOST_VDPA_GET_CONFIG) || defined(VHOST_VDPA_SET_CONFIG)
static void sanitise_vhost_vdpa_config(struct syscallrecord *rec)
{
	struct vhost_vdpa_config *c;
	unsigned int len;
	size_t sz;

	/*
	 * The kernel copies .off and .len from userspace, then reads or
	 * writes buf[len] against the device's config space.  Keep len
	 * bounded so we exercise a real flex-tail copy without demanding
	 * an outsized allocation, and keep an occasional len == 0 so the
	 * zero-length boundary path stays live.  .off is deliberately
	 * random 32-bit -- the overflow-vs-bounds check is one of the
	 * more interesting surfaces here.
	 */
	if (RAND_BOOL())
		len = 0;
	else
		len = 1 + rnd_modulo_u32(64);

	sz = sizeof(*c) + len;
	c = (struct vhost_vdpa_config *) get_writable_struct(sz);
	if (!c)
		return;
	memset(c, 0, sz);
	c->off = rand32();
	c->len = len;
	rec->a3 = (unsigned long) c;
}
#endif

#ifdef VHOST_VDPA_GET_IOVA_RANGE
static void sanitise_vhost_vdpa_iova_range(struct syscallrecord *rec)
{
	struct vhost_vdpa_iova_range *r;

	r = (struct vhost_vdpa_iova_range *) get_writable_struct(sizeof(*r));
	if (!r)
		return;
	memset(r, 0, sizeof(*r));
	rec->a3 = (unsigned long) r;
}
#endif

#ifdef VHOST_SET_FEATURES_ARRAY
static void sanitise_vhost_features_array(struct syscallrecord *rec)
{
	struct vhost_features_array *fa;
	unsigned int count, i;
	size_t sz;

	/*
	 * The kernel copies fa->count from userspace and then trusts it
	 * to size the trailing features[] copy (count * sizeof(__u64)).
	 * Bound count so we exercise a real flex-tail copy without
	 * asking for an unreasonable allocation; keep an occasional
	 * count == 0 so the zero-length boundary path stays live.
	 * VHOST_GET_FEATURES_ARRAY shares the same layout -- the kernel
	 * reads count in and writes the tail back, so the same buffer
	 * shape services both directions.
	 */
	if (RAND_BOOL())
		count = 0;
	else
		count = 1 + rnd_modulo_u32(32);

	sz = sizeof(*fa) + count * sizeof(__u64);
	fa = (struct vhost_features_array *) get_writable_struct(sz);
	if (!fa)
		return;
	memset(fa, 0, sz);
	fa->count = count;
	for (i = 0; i < count; i++)
		fa->features[i] = rand64();
	rec->a3 = (unsigned long) fa;
}
#endif

static void vhost_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case VHOST_SET_VRING_NUM:
		sanitise_vhost_vring_state_num(rec);
		break;
	case VHOST_SET_VRING_BASE:
	case VHOST_GET_VRING_BASE:
#ifdef VHOST_SET_VRING_BUSYLOOP_TIMEOUT
	case VHOST_SET_VRING_BUSYLOOP_TIMEOUT:
#endif
#ifdef VHOST_GET_VRING_BUSYLOOP_TIMEOUT
	case VHOST_GET_VRING_BUSYLOOP_TIMEOUT:
#endif
		sanitise_vhost_vring_state_base(rec);
		break;
	case VHOST_SET_VRING_ADDR:
		sanitise_vhost_vring_addr(rec);
		break;
	case VHOST_SET_MEM_TABLE:
		sanitise_vhost_set_mem_table(rec);
		break;
	case VHOST_SET_LOG_FD:
		sanitise_vhost_set_log_fd(rec);
		break;
	case VHOST_SET_LOG_BASE:
		sanitise_vhost_set_log_base(rec);
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
#ifdef VHOST_SET_FEATURES_ARRAY
	case VHOST_SET_FEATURES_ARRAY:
	case VHOST_GET_FEATURES_ARRAY:
		sanitise_vhost_features_array(rec);
		break;
#endif
#ifdef VHOST_VDPA_SET_VRING_ENABLE
	case VHOST_VDPA_SET_VRING_ENABLE:
#endif
#ifdef VHOST_VDPA_GET_VRING_GROUP
	case VHOST_VDPA_GET_VRING_GROUP:
#endif
#ifdef VHOST_VDPA_SET_GROUP_ASID
	case VHOST_VDPA_SET_GROUP_ASID:
#endif
#ifdef VHOST_VDPA_GET_VRING_DESC_GROUP
	case VHOST_VDPA_GET_VRING_DESC_GROUP:
#endif
#ifdef VHOST_VDPA_GET_VRING_SIZE
	case VHOST_VDPA_GET_VRING_SIZE:
#endif
#if defined(VHOST_VDPA_SET_VRING_ENABLE) || \
    defined(VHOST_VDPA_GET_VRING_GROUP) || \
    defined(VHOST_VDPA_SET_GROUP_ASID) || \
    defined(VHOST_VDPA_GET_VRING_DESC_GROUP) || \
    defined(VHOST_VDPA_GET_VRING_SIZE)
		sanitise_vhost_vdpa_vring_state(rec);
		break;
#endif
#ifdef VHOST_VDPA_GET_CONFIG
	case VHOST_VDPA_GET_CONFIG:
#endif
#ifdef VHOST_VDPA_SET_CONFIG
	case VHOST_VDPA_SET_CONFIG:
#endif
#if defined(VHOST_VDPA_GET_CONFIG) || defined(VHOST_VDPA_SET_CONFIG)
		sanitise_vhost_vdpa_config(rec);
		break;
#endif
#ifdef VHOST_VDPA_GET_IOVA_RANGE
	case VHOST_VDPA_GET_IOVA_RANGE:
		sanitise_vhost_vdpa_iova_range(rec);
		break;
#endif
	default:
		break;
	}
}

static const char *const vhost_devs[] = {
	"vhost-net",
	"vhost-vsock",
	/*
	 * vhost-vdpa registers via alloc_chrdev_region under the class
	 * name "vhost-vdpa", so /proc/devices returns that single name
	 * for every /dev/vhost-vdpaN instance -- one match string covers
	 * all vDPA parent devices present at runtime.  Absent hardware
	 * or module leaves this dark; the /dev pool provider skips what
	 * it can't open.
	 */
	"vhost-vdpa",
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
