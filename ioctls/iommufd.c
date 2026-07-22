
#ifdef USE_IOMMUFD
#include <string.h>
#include <linux/iommufd.h>

#include "fd.h"
#include "ioctls.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "syscall.h"
#include "utils.h"

static const struct ioctl iommufd_ioctls[] = {
	IOCTL(IOMMU_DESTROY),
	IOCTL(IOMMU_IOAS_ALLOC),
	IOCTL(IOMMU_IOAS_IOVA_RANGES),
	IOCTL(IOMMU_IOAS_ALLOW_IOVAS),
	IOCTL(IOMMU_IOAS_MAP),
	IOCTL(IOMMU_IOAS_COPY),
	IOCTL(IOMMU_IOAS_UNMAP),
	IOCTL(IOMMU_OPTION),
	IOCTL(IOMMU_VFIO_IOAS),
	IOCTL(IOMMU_HWPT_ALLOC),
	IOCTL(IOMMU_GET_HW_INFO),
	IOCTL(IOMMU_HWPT_SET_DIRTY_TRACKING),
	IOCTL(IOMMU_HWPT_GET_DIRTY_BITMAP),
	IOCTL(IOMMU_HWPT_INVALIDATE),
#ifdef IOMMU_FAULT_QUEUE_ALLOC
	IOCTL(IOMMU_FAULT_QUEUE_ALLOC),
#endif
#ifdef IOMMU_IOAS_MAP_FILE
	IOCTL(IOMMU_IOAS_MAP_FILE),
#endif
#ifdef IOMMU_VIOMMU_ALLOC
	IOCTL(IOMMU_VIOMMU_ALLOC),
#endif
#ifdef IOMMU_VDEVICE_ALLOC
	IOCTL(IOMMU_VDEVICE_ALLOC),
#endif
#ifdef IOMMU_IOAS_CHANGE_PROCESS
	IOCTL(IOMMU_IOAS_CHANGE_PROCESS),
#endif
#ifdef IOMMU_VEVENTQ_ALLOC
	IOCTL(IOMMU_VEVENTQ_ALLOC),
#endif
#ifdef IOMMU_HW_QUEUE_ALLOC
	IOCTL(IOMMU_HW_QUEUE_ALLOC),
#endif
};

/*
 * Per-IOMMUFD ioctl struct-arg seeding.  Mirrors the kvm_vm_sanitise() pattern:
 * delegate ioctl selection to pick_random_ioctl(), then override rec->a3 for
 * the commands whose argument is a struct.  Every IOMMUFD request is declared
 * with _IO() (size/direction are carried in-band by the struct's size field),
 * so the generic arg-shape picker in ioctls.c hands the kernel a random-shaped
 * buffer and the map/unmap/iova-ranges paths bounce on the size/reserved
 * checks before reaching the IOAS machinery.  IOMMUFD is on the efault_cache
 * opt-out list, so no probe leak is introduced here -- this sanitiser
 * replaces the random path entirely.
 */
#define IOMMUFD_FUZZ_PAGE_SIZE		0x1000UL
#define IOMMUFD_FUZZ_IOVA_LIMIT		(1UL << 40)
#define IOMMUFD_FUZZ_MAX_ORDER		6	/* 4K .. 256K */
#define IOMMUFD_FUZZ_MAX_ID		64
#define IOMMUFD_FUZZ_MAX_RANGES		16
#define IOMMUFD_FUZZ_HWPT_DATA_MAX	3	/* NONE/VTD_S1/ARM_SMMUV3 */
#define IOMMUFD_FUZZ_HWPT_DATA_ORDER	3	/* 4K .. 32K driver blob */
#define IOMMUFD_FUZZ_HW_INFO_TYPE_MAX	4	/* NONE/INTEL_VTD/ARM_SMMUV3/TEGRA241 */
#define IOMMUFD_FUZZ_HWPT_INV_TYPE_MAX	2	/* VTD_S1/ARM_SMMUV3 */
#define IOMMUFD_FUZZ_VIOMMU_TYPE_MAX	3	/* DEFAULT/ARM_SMMUV3/TEGRA241 */
#define IOMMUFD_FUZZ_VEVENTQ_TYPE_MAX	3	/* DEFAULT/ARM_SMMUV3/TEGRA241 */
#define IOMMUFD_FUZZ_HW_QUEUE_TYPE_MAX	2	/* DEFAULT/TEGRA241 */
#define IOMMUFD_FUZZ_VFIO_OP_MAX	3	/* GET/SET/CLEAR */
#define IOMMUFD_FUZZ_OPTION_ID_MAX	2	/* RLIMIT_MODE/HUGE_PAGES */
#define IOMMUFD_FUZZ_OPTION_OP_MAX	2	/* SET/GET */
#define IOMMUFD_FUZZ_MAX_ENTRIES	16
#define IOMMUFD_FUZZ_MAX_QUEUE_INDEX	8
#define IOMMUFD_FUZZ_MAX_VEVENTQ_DEPTH	256

static void sanitise_iommufd_destroy(struct syscallrecord *rec)
{
	struct iommu_destroy *d;

	d = get_writable_address(sizeof(*d));
	if (d == NULL)
		return;

	memset(d, 0, sizeof(*d));
	d->size = sizeof(*d);
	d->id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);

	rec->a3 = (unsigned long)d;
}

static void sanitise_iommufd_ioas_alloc(struct syscallrecord *rec)
{
	struct iommu_ioas_alloc *a;

	a = get_writable_address(sizeof(*a));
	if (a == NULL)
		return;

	memset(a, 0, sizeof(*a));
	a->size = sizeof(*a);

	rec->a3 = (unsigned long)a;
}

static void sanitise_iommufd_ioas_map(struct syscallrecord *rec)
{
	struct iommu_ioas_map *m;
	void *ua;
	__u64 length;

	m = get_writable_address(sizeof(*m));
	if (m == NULL)
		return;

	length = IOMMUFD_FUZZ_PAGE_SIZE
	       << rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ORDER + 1);

	ua = get_writable_address(length);
	if (ua == NULL)
		return;
	generate_rand_bytes((unsigned char *)ua, length);

	memset(m, 0, sizeof(*m));
	m->size = sizeof(*m);
	m->flags = IOMMU_IOAS_MAP_READABLE | IOMMU_IOAS_MAP_WRITEABLE;
	if (ONE_IN(4))
		m->flags |= IOMMU_IOAS_MAP_FIXED_IOVA;
	m->ioas_id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);
	m->user_va = (__u64)(unsigned long)ua;
	m->length = length;
	m->iova = rnd_modulo_u64(IOMMUFD_FUZZ_IOVA_LIMIT)
		& ~(IOMMUFD_FUZZ_PAGE_SIZE - 1);

	rec->a3 = (unsigned long)m;
}

static void sanitise_iommufd_ioas_unmap(struct syscallrecord *rec)
{
	struct iommu_ioas_unmap *u;
	__u64 length;

	u = get_writable_address(sizeof(*u));
	if (u == NULL)
		return;

	length = IOMMUFD_FUZZ_PAGE_SIZE
	       << rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ORDER + 1);

	memset(u, 0, sizeof(*u));
	u->size = sizeof(*u);
	u->ioas_id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);
	u->iova = rnd_modulo_u64(IOMMUFD_FUZZ_IOVA_LIMIT)
		& ~(IOMMUFD_FUZZ_PAGE_SIZE - 1);
	u->length = length;

	rec->a3 = (unsigned long)u;
}

static void sanitise_iommufd_ioas_iova_ranges(struct syscallrecord *rec)
{
	struct iommu_ioas_iova_ranges *r;
	void *ranges;
	__u32 num_iovas;
	unsigned long buf_sz;

	r = get_writable_address(sizeof(*r));
	if (r == NULL)
		return;

	num_iovas = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_RANGES + 1);
	buf_sz = (unsigned long)num_iovas * sizeof(struct iommu_iova_range);
	if (buf_sz == 0)
		buf_sz = sizeof(struct iommu_iova_range);

	ranges = get_writable_address(buf_sz);
	if (ranges == NULL)
		return;

	memset(r, 0, sizeof(*r));
	r->size = sizeof(*r);
	r->ioas_id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);
	r->num_iovas = num_iovas;
	r->allowed_iovas = (__u64)(unsigned long)ranges;

	rec->a3 = (unsigned long)r;
}

static void sanitise_iommufd_hwpt_alloc(struct syscallrecord *rec)
{
	struct iommu_hwpt_alloc *a;

	a = get_writable_address(sizeof(*a));
	if (a == NULL)
		return;

	memset(a, 0, sizeof(*a));
	a->size = sizeof(*a);
	a->dev_id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);
	a->pt_id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);
	if (RAND_BOOL())
		a->flags |= IOMMU_HWPT_ALLOC_NEST_PARENT;
	if (RAND_BOOL())
		a->flags |= IOMMU_HWPT_ALLOC_DIRTY_TRACKING;
	if (RAND_BOOL())
		a->flags |= IOMMU_HWPT_ALLOC_PASID;
	if (RAND_BOOL()) {
		a->flags |= IOMMU_HWPT_FAULT_ID_VALID;
		a->fault_id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);
	}
	a->data_type = rnd_modulo_u32(IOMMUFD_FUZZ_HWPT_DATA_MAX);
	if (a->data_type != IOMMU_HWPT_DATA_NONE) {
		void *data;
		__u32 data_len;

		data_len = IOMMUFD_FUZZ_PAGE_SIZE
			<< rnd_modulo_u32(IOMMUFD_FUZZ_HWPT_DATA_ORDER + 1);
		data = get_writable_address(data_len);
		if (data == NULL)
			return;
		generate_rand_bytes((unsigned char *)data, data_len);
		a->data_len = data_len;
		a->data_uptr = (__u64)(unsigned long)data;
	}

	rec->a3 = (unsigned long)a;
}

static void sanitise_iommufd_ioas_allow_iovas(struct syscallrecord *rec)
{
	struct iommu_ioas_allow_iovas *a;
	void *ranges;
	__u32 num_iovas;
	unsigned long buf_sz;

	a = get_writable_address(sizeof(*a));
	if (a == NULL)
		return;

	num_iovas = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_RANGES + 1);
	buf_sz = (unsigned long)num_iovas * sizeof(struct iommu_iova_range);
	if (buf_sz == 0)
		buf_sz = sizeof(struct iommu_iova_range);

	ranges = get_writable_address(buf_sz);
	if (ranges == NULL)
		return;

	memset(a, 0, sizeof(*a));
	a->size = sizeof(*a);
	a->ioas_id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);
	a->num_iovas = num_iovas;
	a->allowed_iovas = (__u64)(unsigned long)ranges;

	rec->a3 = (unsigned long)a;
}

static void sanitise_iommufd_ioas_copy(struct syscallrecord *rec)
{
	struct iommu_ioas_copy *c;
	__u64 length;

	c = get_writable_address(sizeof(*c));
	if (c == NULL)
		return;

	length = IOMMUFD_FUZZ_PAGE_SIZE
	       << rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ORDER + 1);

	memset(c, 0, sizeof(*c));
	c->size = sizeof(*c);
	c->flags = IOMMU_IOAS_MAP_READABLE | IOMMU_IOAS_MAP_WRITEABLE;
	if (ONE_IN(4))
		c->flags |= IOMMU_IOAS_MAP_FIXED_IOVA;
	c->dst_ioas_id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);
	c->src_ioas_id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);
	c->length = length;
	c->dst_iova = rnd_modulo_u64(IOMMUFD_FUZZ_IOVA_LIMIT)
		    & ~(IOMMUFD_FUZZ_PAGE_SIZE - 1);
	c->src_iova = rnd_modulo_u64(IOMMUFD_FUZZ_IOVA_LIMIT)
		    & ~(IOMMUFD_FUZZ_PAGE_SIZE - 1);

	rec->a3 = (unsigned long)c;
}

static void sanitise_iommufd_hwpt_set_dirty_tracking(struct syscallrecord *rec)
{
	struct iommu_hwpt_set_dirty_tracking *s;

	s = get_writable_address(sizeof(*s));
	if (s == NULL)
		return;

	memset(s, 0, sizeof(*s));
	s->size = sizeof(*s);
	s->hwpt_id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);
	if (RAND_BOOL())
		s->flags |= IOMMU_HWPT_DIRTY_TRACKING_ENABLE;

	rec->a3 = (unsigned long)s;
}

static void sanitise_iommufd_hwpt_get_dirty_bitmap(struct syscallrecord *rec)
{
	struct iommu_hwpt_get_dirty_bitmap *g;
	void *bitmap;
	__u64 length;

	g = get_writable_address(sizeof(*g));
	if (g == NULL)
		return;

	length = IOMMUFD_FUZZ_PAGE_SIZE
	       << rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ORDER + 1);

	/*
	 * bitmap holds one bit per page_size chunk of length; a single
	 * IOMMUFD_FUZZ_PAGE_SIZE buffer covers up to 32MB at 4K granularity,
	 * well past our max length draw.
	 */
	bitmap = get_writable_address(IOMMUFD_FUZZ_PAGE_SIZE);
	if (bitmap == NULL)
		return;

	memset(g, 0, sizeof(*g));
	g->size = sizeof(*g);
	g->hwpt_id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);
	if (RAND_BOOL())
		g->flags |= IOMMU_HWPT_GET_DIRTY_BITMAP_NO_CLEAR;
	g->iova = rnd_modulo_u64(IOMMUFD_FUZZ_IOVA_LIMIT)
		& ~(IOMMUFD_FUZZ_PAGE_SIZE - 1);
	g->length = length;
	g->page_size = IOMMUFD_FUZZ_PAGE_SIZE;
	g->data = (__u64)(unsigned long)bitmap;

	rec->a3 = (unsigned long)g;
}

static void sanitise_iommufd_hwpt_invalidate(struct syscallrecord *rec)
{
	struct iommu_hwpt_invalidate *i;
	void *entries;
	__u32 entry_num, entry_len;
	unsigned long buf_sz;

	i = get_writable_address(sizeof(*i));
	if (i == NULL)
		return;

	entry_num = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ENTRIES + 1);
	/* VTD_S1 wants 24B, ARM SMMUv3 wants 16B; occasionally wilder. */
	if (ONE_IN(8))
		entry_len = rnd_modulo_u32(64) + 1;
	else
		entry_len = RAND_BOOL() ? 16 : 24;

	buf_sz = (unsigned long)entry_num * entry_len;
	if (buf_sz == 0)
		buf_sz = entry_len;

	entries = get_writable_address(buf_sz);
	if (entries == NULL)
		return;

	memset(i, 0, sizeof(*i));
	i->size = sizeof(*i);
	i->hwpt_id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);
	i->data_uptr = (__u64)(unsigned long)entries;
	i->data_type = rnd_modulo_u32(IOMMUFD_FUZZ_HWPT_INV_TYPE_MAX);
	i->entry_len = entry_len;
	i->entry_num = entry_num;

	rec->a3 = (unsigned long)i;
}

static void sanitise_iommufd_get_hw_info(struct syscallrecord *rec)
{
	struct iommu_hw_info *h;
	void *data;
	__u32 data_len;

	h = get_writable_address(sizeof(*h));
	if (h == NULL)
		return;

	data_len = IOMMUFD_FUZZ_PAGE_SIZE
		 << rnd_modulo_u32(IOMMUFD_FUZZ_HWPT_DATA_ORDER + 1);
	data = get_writable_address(data_len);
	if (data == NULL)
		return;

	memset(h, 0, sizeof(*h));
	h->size = sizeof(*h);
	h->dev_id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);
	h->data_len = data_len;
	h->data_uptr = (__u64)(unsigned long)data;
	if (RAND_BOOL()) {
		h->flags |= IOMMU_HW_INFO_FLAG_INPUT_TYPE;
		h->in_data_type =
			rnd_modulo_u32(IOMMUFD_FUZZ_HW_INFO_TYPE_MAX);
	}

	rec->a3 = (unsigned long)h;
}

static void sanitise_iommufd_option(struct syscallrecord *rec)
{
	struct iommu_option *o;

	o = get_writable_address(sizeof(*o));
	if (o == NULL)
		return;

	memset(o, 0, sizeof(*o));
	o->size = sizeof(*o);
	o->option_id = rnd_modulo_u32(IOMMUFD_FUZZ_OPTION_ID_MAX);
	o->op = rnd_modulo_u32(IOMMUFD_FUZZ_OPTION_OP_MAX);
	o->object_id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);
	o->val64 = ONE_IN(8) ? rnd_u64() : rnd_modulo_u64(2);

	rec->a3 = (unsigned long)o;
}

static void sanitise_iommufd_vfio_ioas(struct syscallrecord *rec)
{
	struct iommu_vfio_ioas *v;

	v = get_writable_address(sizeof(*v));
	if (v == NULL)
		return;

	memset(v, 0, sizeof(*v));
	v->size = sizeof(*v);
	v->ioas_id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);
	v->op = rnd_modulo_u32(IOMMUFD_FUZZ_VFIO_OP_MAX);

	rec->a3 = (unsigned long)v;
}

#ifdef IOMMU_FAULT_QUEUE_ALLOC
static void sanitise_iommufd_fault_queue_alloc(struct syscallrecord *rec)
{
	struct iommu_fault_alloc *f;

	f = get_writable_address(sizeof(*f));
	if (f == NULL)
		return;

	memset(f, 0, sizeof(*f));
	f->size = sizeof(*f);
	/*
	 * flags MUST be 0 per uapi; occasionally trip the reserved-bit
	 * check to exercise the reject path.
	 */
	if (ONE_IN(8))
		f->flags = rnd_u32();

	rec->a3 = (unsigned long)f;
}
#endif

#ifdef IOMMU_IOAS_MAP_FILE
static void sanitise_iommufd_ioas_map_file(struct syscallrecord *rec)
{
	struct iommu_ioas_map_file *m;
	__u64 length;

	m = get_writable_address(sizeof(*m));
	if (m == NULL)
		return;

	length = IOMMUFD_FUZZ_PAGE_SIZE
	       << rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ORDER + 1);

	memset(m, 0, sizeof(*m));
	m->size = sizeof(*m);
	m->flags = IOMMU_IOAS_MAP_READABLE | IOMMU_IOAS_MAP_WRITEABLE;
	if (ONE_IN(4))
		m->flags |= IOMMU_IOAS_MAP_FIXED_IOVA;
	m->ioas_id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);
	m->fd = get_random_fd();
	m->start = rnd_u64() & ~(IOMMUFD_FUZZ_PAGE_SIZE - 1);
	m->length = length;
	m->iova = rnd_modulo_u64(IOMMUFD_FUZZ_IOVA_LIMIT)
		& ~(IOMMUFD_FUZZ_PAGE_SIZE - 1);

	rec->a3 = (unsigned long)m;
}
#endif

#ifdef IOMMU_IOAS_CHANGE_PROCESS
static void sanitise_iommufd_ioas_change_process(struct syscallrecord *rec)
{
	struct iommu_ioas_change_process *p;

	p = get_writable_address(sizeof(*p));
	if (p == NULL)
		return;

	memset(p, 0, sizeof(*p));
	p->size = sizeof(*p);

	rec->a3 = (unsigned long)p;
}
#endif

#ifdef IOMMU_VIOMMU_ALLOC
static void sanitise_iommufd_viommu_alloc(struct syscallrecord *rec)
{
	struct iommu_viommu_alloc *v;

	v = get_writable_address(sizeof(*v));
	if (v == NULL)
		return;

	memset(v, 0, sizeof(*v));
	v->size = sizeof(*v);
	v->type = rnd_modulo_u32(IOMMUFD_FUZZ_VIOMMU_TYPE_MAX);
	v->dev_id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);
	v->hwpt_id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);
	if (RAND_BOOL()) {
		void *data;
		__u32 data_len;

		data_len = IOMMUFD_FUZZ_PAGE_SIZE
			<< rnd_modulo_u32(IOMMUFD_FUZZ_HWPT_DATA_ORDER + 1);
		data = get_writable_address(data_len);
		if (data == NULL)
			return;
		v->data_len = data_len;
		v->data_uptr = (__u64)(unsigned long)data;
	}

	rec->a3 = (unsigned long)v;
}
#endif

#ifdef IOMMU_VDEVICE_ALLOC
static void sanitise_iommufd_vdevice_alloc(struct syscallrecord *rec)
{
	struct iommu_vdevice_alloc *v;

	v = get_writable_address(sizeof(*v));
	if (v == NULL)
		return;

	memset(v, 0, sizeof(*v));
	v->size = sizeof(*v);
	v->viommu_id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);
	v->dev_id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);
	v->virt_id = rnd_modulo_u64(IOMMUFD_FUZZ_MAX_ID);

	rec->a3 = (unsigned long)v;
}
#endif

#ifdef IOMMU_VEVENTQ_ALLOC
static void sanitise_iommufd_veventq_alloc(struct syscallrecord *rec)
{
	struct iommu_veventq_alloc *v;

	v = get_writable_address(sizeof(*v));
	if (v == NULL)
		return;

	memset(v, 0, sizeof(*v));
	v->size = sizeof(*v);
	v->viommu_id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);
	v->type = rnd_modulo_u32(IOMMUFD_FUZZ_VEVENTQ_TYPE_MAX);
	v->veventq_depth =
		rnd_modulo_u32(IOMMUFD_FUZZ_MAX_VEVENTQ_DEPTH) + 1;

	rec->a3 = (unsigned long)v;
}
#endif

#ifdef IOMMU_HW_QUEUE_ALLOC
static void sanitise_iommufd_hw_queue_alloc(struct syscallrecord *rec)
{
	struct iommu_hw_queue_alloc *q;
	__u64 length;

	q = get_writable_address(sizeof(*q));
	if (q == NULL)
		return;

	length = IOMMUFD_FUZZ_PAGE_SIZE
	       << rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ORDER + 1);

	memset(q, 0, sizeof(*q));
	q->size = sizeof(*q);
	q->viommu_id = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_ID);
	q->type = rnd_modulo_u32(IOMMUFD_FUZZ_HW_QUEUE_TYPE_MAX);
	q->index = rnd_modulo_u32(IOMMUFD_FUZZ_MAX_QUEUE_INDEX);
	q->nesting_parent_iova = rnd_modulo_u64(IOMMUFD_FUZZ_IOVA_LIMIT)
			       & ~(length - 1);
	q->length = length;

	rec->a3 = (unsigned long)q;
}
#endif

static void iommufd_sanitise(const struct ioctl_group *grp,
			     struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case IOMMU_DESTROY:
		sanitise_iommufd_destroy(rec);
		break;
	case IOMMU_IOAS_ALLOC:
		sanitise_iommufd_ioas_alloc(rec);
		break;
	case IOMMU_IOAS_MAP:
		sanitise_iommufd_ioas_map(rec);
		break;
	case IOMMU_IOAS_UNMAP:
		sanitise_iommufd_ioas_unmap(rec);
		break;
	case IOMMU_IOAS_IOVA_RANGES:
		sanitise_iommufd_ioas_iova_ranges(rec);
		break;
	case IOMMU_HWPT_ALLOC:
		sanitise_iommufd_hwpt_alloc(rec);
		break;
	case IOMMU_IOAS_ALLOW_IOVAS:
		sanitise_iommufd_ioas_allow_iovas(rec);
		break;
	case IOMMU_IOAS_COPY:
		sanitise_iommufd_ioas_copy(rec);
		break;
	case IOMMU_HWPT_SET_DIRTY_TRACKING:
		sanitise_iommufd_hwpt_set_dirty_tracking(rec);
		break;
	case IOMMU_HWPT_GET_DIRTY_BITMAP:
		sanitise_iommufd_hwpt_get_dirty_bitmap(rec);
		break;
	case IOMMU_HWPT_INVALIDATE:
		sanitise_iommufd_hwpt_invalidate(rec);
		break;
	case IOMMU_GET_HW_INFO:
		sanitise_iommufd_get_hw_info(rec);
		break;
	case IOMMU_OPTION:
		sanitise_iommufd_option(rec);
		break;
	case IOMMU_VFIO_IOAS:
		sanitise_iommufd_vfio_ioas(rec);
		break;
#ifdef IOMMU_FAULT_QUEUE_ALLOC
	case IOMMU_FAULT_QUEUE_ALLOC:
		sanitise_iommufd_fault_queue_alloc(rec);
		break;
#endif
#ifdef IOMMU_IOAS_MAP_FILE
	case IOMMU_IOAS_MAP_FILE:
		sanitise_iommufd_ioas_map_file(rec);
		break;
#endif
#ifdef IOMMU_IOAS_CHANGE_PROCESS
	case IOMMU_IOAS_CHANGE_PROCESS:
		sanitise_iommufd_ioas_change_process(rec);
		break;
#endif
#ifdef IOMMU_VIOMMU_ALLOC
	case IOMMU_VIOMMU_ALLOC:
		sanitise_iommufd_viommu_alloc(rec);
		break;
#endif
#ifdef IOMMU_VDEVICE_ALLOC
	case IOMMU_VDEVICE_ALLOC:
		sanitise_iommufd_vdevice_alloc(rec);
		break;
#endif
#ifdef IOMMU_VEVENTQ_ALLOC
	case IOMMU_VEVENTQ_ALLOC:
		sanitise_iommufd_veventq_alloc(rec);
		break;
#endif
#ifdef IOMMU_HW_QUEUE_ALLOC
	case IOMMU_HW_QUEUE_ALLOC:
		sanitise_iommufd_hw_queue_alloc(rec);
		break;
#endif
	default:
		break;
	}
}

static const char *const iommufd_devs[] = {
	"iommu",
};

static const struct ioctl_group iommufd_grp = {
	.devtype = DEV_MISC,
	.devs = iommufd_devs,
	.devs_cnt = ARRAY_SIZE(iommufd_devs),
	.sanitise = iommufd_sanitise,
	.ioctls = iommufd_ioctls,
	.ioctls_cnt = ARRAY_SIZE(iommufd_ioctls),
};

REG_IOCTL_GROUP(iommufd_grp)
#endif
