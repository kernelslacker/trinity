#include <linux/firewire-cdev.h>
#include <linux/firewire-constants.h>

#include "ioctls.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

/*
 * Compile-time: every fixed-shape FW_CDEV_IOC_* command the
 * sanitisers below fill must have sizeof(struct) matching the
 * _IOC_SIZE encoded in its request bits.  A mismatch means the
 * kernel firewire-cdev.h moved under us and the sanitiser is
 * memset()ing / stamping into a buffer the kernel copies less of
 * than we prepared (under-encoded) or reads past (over-encoded).
 * FW_CDEV_IOC_GET_SPEED is _IO() with no struct arg and is
 * intentionally absent -- its _IOC_SIZE is 0 by construction.
 */
IOCTL_SIZE_ASSERT(FW_CDEV_IOC_GET_INFO, struct fw_cdev_get_info);
IOCTL_SIZE_ASSERT(FW_CDEV_IOC_SEND_REQUEST, struct fw_cdev_send_request);
IOCTL_SIZE_ASSERT(FW_CDEV_IOC_SEND_BROADCAST_REQUEST, struct fw_cdev_send_request);
IOCTL_SIZE_ASSERT(FW_CDEV_IOC_ALLOCATE, struct fw_cdev_allocate);
IOCTL_SIZE_ASSERT(FW_CDEV_IOC_DEALLOCATE, struct fw_cdev_deallocate);
IOCTL_SIZE_ASSERT(FW_CDEV_IOC_DEALLOCATE_ISO_RESOURCE, struct fw_cdev_deallocate);
IOCTL_SIZE_ASSERT(FW_CDEV_IOC_SEND_RESPONSE, struct fw_cdev_send_response);
IOCTL_SIZE_ASSERT(FW_CDEV_IOC_INITIATE_BUS_RESET, struct fw_cdev_initiate_bus_reset);
IOCTL_SIZE_ASSERT(FW_CDEV_IOC_ADD_DESCRIPTOR, struct fw_cdev_add_descriptor);
IOCTL_SIZE_ASSERT(FW_CDEV_IOC_REMOVE_DESCRIPTOR, struct fw_cdev_remove_descriptor);
IOCTL_SIZE_ASSERT(FW_CDEV_IOC_CREATE_ISO_CONTEXT, struct fw_cdev_create_iso_context);
IOCTL_SIZE_ASSERT(FW_CDEV_IOC_QUEUE_ISO, struct fw_cdev_queue_iso);
IOCTL_SIZE_ASSERT(FW_CDEV_IOC_START_ISO, struct fw_cdev_start_iso);
IOCTL_SIZE_ASSERT(FW_CDEV_IOC_STOP_ISO, struct fw_cdev_stop_iso);
IOCTL_SIZE_ASSERT(FW_CDEV_IOC_GET_CYCLE_TIMER, struct fw_cdev_get_cycle_timer);
IOCTL_SIZE_ASSERT(FW_CDEV_IOC_ALLOCATE_ISO_RESOURCE, struct fw_cdev_allocate_iso_resource);
IOCTL_SIZE_ASSERT(FW_CDEV_IOC_ALLOCATE_ISO_RESOURCE_ONCE, struct fw_cdev_allocate_iso_resource);
IOCTL_SIZE_ASSERT(FW_CDEV_IOC_DEALLOCATE_ISO_RESOURCE_ONCE, struct fw_cdev_allocate_iso_resource);
IOCTL_SIZE_ASSERT(FW_CDEV_IOC_SEND_STREAM_PACKET, struct fw_cdev_send_stream_packet);
#ifdef FW_CDEV_IOC_GET_CYCLE_TIMER2
IOCTL_SIZE_ASSERT(FW_CDEV_IOC_GET_CYCLE_TIMER2, struct fw_cdev_get_cycle_timer2);
#endif
#ifdef FW_CDEV_IOC_SEND_PHY_PACKET
IOCTL_SIZE_ASSERT(FW_CDEV_IOC_SEND_PHY_PACKET, struct fw_cdev_send_phy_packet);
#endif
#ifdef FW_CDEV_IOC_RECEIVE_PHY_PACKETS
IOCTL_SIZE_ASSERT(FW_CDEV_IOC_RECEIVE_PHY_PACKETS, struct fw_cdev_receive_phy_packets);
#endif
#ifdef FW_CDEV_IOC_SET_ISO_CHANNELS
IOCTL_SIZE_ASSERT(FW_CDEV_IOC_SET_ISO_CHANNELS, struct fw_cdev_set_iso_channels);
#endif
#ifdef FW_CDEV_IOC_FLUSH_ISO
IOCTL_SIZE_ASSERT(FW_CDEV_IOC_FLUSH_ISO, struct fw_cdev_flush_iso);
#endif

/*
 * The kernel's ioctl_send_request() rejects anything outside this set with
 * -EINVAL, so drawing over the full 4-bit space wastes 12/16 attempts and
 * never reaches the lock tcodes (>= 0x10) at all.
 */
static const __u32 fw_request_tcodes[] = {
	TCODE_WRITE_QUADLET_REQUEST,
	TCODE_WRITE_BLOCK_REQUEST,
	TCODE_READ_QUADLET_REQUEST,
	TCODE_READ_BLOCK_REQUEST,
	TCODE_LOCK_MASK_SWAP,
	TCODE_LOCK_COMPARE_SWAP,
	TCODE_LOCK_FETCH_ADD,
	TCODE_LOCK_LITTLE_ADD,
	TCODE_LOCK_BOUNDED_ADD,
	TCODE_LOCK_WRAP_ADD,
	TCODE_LOCK_VENDOR_DEPENDENT,
};

static void sanitise_fw_send_request(struct syscallrecord *rec)
{
	struct fw_cdev_send_request *req;
	void *data;
	__u32 payload_len;

	req = (struct fw_cdev_send_request *) get_writable_struct(sizeof(*req));
	if (!req)
		return;
	memset(req, 0, sizeof(*req));
	payload_len = rnd_modulo_u32(512);
	data = get_writable_struct(payload_len + 4);
	if (!data)
		return;
	req->tcode = RAND_ARRAY(fw_request_tcodes);
	req->length = payload_len;
	req->offset = rand64() & 0xFFFFFFFFFFFFULL;	/* 48-bit address space */
	req->closure = rand64();
	req->data = (unsigned long) data;
	req->generation = rand32();
	rec->a3 = (unsigned long) req;
}

static void sanitise_fw_allocate(struct syscallrecord *rec)
{
	struct fw_cdev_allocate *a;

	a = (struct fw_cdev_allocate *) get_writable_struct(sizeof(*a));
	if (!a)
		return;
	memset(a, 0, sizeof(*a));
	a->offset = rand64() & 0xFFFFFFFFFFFFULL;
	a->closure = rand64();
	a->length = rnd_modulo_u32(4096) + 4;
	a->region_end = a->offset + a->length;
	rec->a3 = (unsigned long) a;
}

static void sanitise_fw_deallocate(struct syscallrecord *rec)
{
	struct fw_cdev_deallocate *d;

	d = (struct fw_cdev_deallocate *) get_writable_struct(sizeof(*d));
	if (!d)
		return;
	memset(d, 0, sizeof(*d));
	d->handle = rand32();
	rec->a3 = (unsigned long) d;
}

static void sanitise_fw_send_response(struct syscallrecord *rec)
{
	struct fw_cdev_send_response *resp;
	void *data;
	__u32 payload_len;

	resp = (struct fw_cdev_send_response *) get_writable_struct(sizeof(*resp));
	if (!resp)
		return;
	memset(resp, 0, sizeof(*resp));
	payload_len = rnd_modulo_u32(512);
	data = get_writable_struct(payload_len + 4);
	if (!data)
		return;
	resp->rcode = rnd_modulo_u32(8);
	resp->length = payload_len;
	resp->data = (unsigned long) data;
	resp->handle = rand32();
	rec->a3 = (unsigned long) resp;
}

static void sanitise_fw_add_descriptor(struct syscallrecord *rec)
{
	struct fw_cdev_add_descriptor *desc;
	void *data;
	__u32 len;

	desc = (struct fw_cdev_add_descriptor *) get_writable_struct(sizeof(*desc));
	if (!desc)
		return;
	memset(desc, 0, sizeof(*desc));
	len = rnd_modulo_u32(16) + 1;
	data = get_writable_struct(len * 4);
	if (!data)
		return;
	desc->immediate = RAND_BOOL() ? rand32() : 0;
	desc->key = 0x81000000;	/* leaf entry type */
	desc->length = len;
	desc->data = (unsigned long) data;
	rec->a3 = (unsigned long) desc;
}

static void sanitise_fw_create_iso_context(struct syscallrecord *rec)
{
	struct fw_cdev_create_iso_context *ctx;

	ctx = (struct fw_cdev_create_iso_context *) get_writable_struct(sizeof(*ctx));
	if (!ctx)
		return;
	memset(ctx, 0, sizeof(*ctx));
	ctx->type = rnd_modulo_u32(3);
	ctx->header_size = (rnd_modulo_u32(8)) * 4;	/* must be multiple of 4 */
	ctx->channel = rnd_modulo_u32(64);
	ctx->speed = rnd_modulo_u32(6);
	ctx->closure = rand64();
	rec->a3 = (unsigned long) ctx;
}

static void sanitise_fw_queue_iso(struct syscallrecord *rec)
{
	struct fw_cdev_queue_iso *q;
	struct fw_cdev_iso_packet *pkt;
	void *data;

	q = (struct fw_cdev_queue_iso *) get_writable_struct(sizeof(*q));
	if (!q)
		return;
	memset(q, 0, sizeof(*q));
	pkt = (struct fw_cdev_iso_packet *) get_writable_struct(sizeof(*pkt));
	if (pkt) {
		memset(pkt, 0, sizeof(*pkt));
		pkt->control = rand32();
	}
	data = get_writable_struct(4096);
	if (!data)
		return;
	q->packets = (unsigned long) pkt;
	q->data = (unsigned long) data;
	q->size = sizeof(*pkt);
	q->handle = rand32();
	rec->a3 = (unsigned long) q;
}

static void sanitise_fw_start_iso(struct syscallrecord *rec)
{
	struct fw_cdev_start_iso *s;

	s = (struct fw_cdev_start_iso *) get_writable_struct(sizeof(*s));
	if (!s)
		return;
	memset(s, 0, sizeof(*s));
	s->cycle = RAND_BOOL() ? -1 : (int) rnd_modulo_u32(8000);
	s->sync = rnd_modulo_u32(16);
	s->tags = rnd_modulo_u32(16);
	s->handle = rand32();
	rec->a3 = (unsigned long) s;
}

static void sanitise_fw_alloc_iso_resource(struct syscallrecord *rec)
{
	struct fw_cdev_allocate_iso_resource *r;

	r = (struct fw_cdev_allocate_iso_resource *) get_writable_struct(sizeof(*r));
	if (!r)
		return;
	memset(r, 0, sizeof(*r));
	r->closure = rand64();
	r->channels = 1ULL << (rnd_modulo_u32(64));
	r->bandwidth = rnd_modulo_u32(4096);
	rec->a3 = (unsigned long) r;
}

static void sanitise_fw_send_stream_packet(struct syscallrecord *rec)
{
	struct fw_cdev_send_stream_packet *pkt;
	void *data;
	__u32 payload_len;

	pkt = (struct fw_cdev_send_stream_packet *) get_writable_struct(sizeof(*pkt));
	if (!pkt)
		return;
	memset(pkt, 0, sizeof(*pkt));
	payload_len = rnd_modulo_u32(512);
	data = get_writable_struct(payload_len + 4);
	if (!data)
		return;
	pkt->length = payload_len;
	pkt->tag = rnd_modulo_u32(4);
	pkt->channel = rnd_modulo_u32(64);
	pkt->sy = rnd_modulo_u32(16);
	pkt->closure = rand64();
	pkt->data = (unsigned long) data;
	pkt->generation = rand32();
	pkt->speed = rnd_modulo_u32(6);
	rec->a3 = (unsigned long) pkt;
}

static void sanitise_fw_get_info(struct syscallrecord *rec)
{
	struct fw_cdev_get_info *info;

	/* mostly output; just allocate and let kernel fill it */
	info = (struct fw_cdev_get_info *) get_writable_struct(sizeof(*info));
	if (!info)
		return;
	/* rom and bus_reset are __user pointers consumed by the
	 * kernel's copy_to_user; zero the struct so we don't
	 * hand it uninitialised garbage. */
	memset(info, 0, sizeof(*info));
	info->version = rnd_modulo_u32(6) + 1;
	info->bus_reset_closure = rand64();
	rec->a3 = (unsigned long) info;
}

static void sanitise_fw_initiate_bus_reset(struct syscallrecord *rec)
{
	struct fw_cdev_initiate_bus_reset *r;

	r = (struct fw_cdev_initiate_bus_reset *) get_writable_struct(sizeof(*r));
	if (!r)
		return;
	memset(r, 0, sizeof(*r));
	r->type = rnd_modulo_u32(2);	/* FW_CDEV_LONG_RESET or FW_CDEV_SHORT_RESET */
	rec->a3 = (unsigned long) r;
}

static void sanitise_fw_remove_descriptor(struct syscallrecord *rec)
{
	struct fw_cdev_remove_descriptor *d;

	d = (struct fw_cdev_remove_descriptor *) get_writable_struct(sizeof(*d));
	if (!d)
		return;
	memset(d, 0, sizeof(*d));
	d->handle = rand32();
	rec->a3 = (unsigned long) d;
}

static void sanitise_fw_stop_iso(struct syscallrecord *rec)
{
	struct fw_cdev_stop_iso *s;

	s = (struct fw_cdev_stop_iso *) get_writable_struct(sizeof(*s));
	if (!s)
		return;
	memset(s, 0, sizeof(*s));
	s->handle = rand32();
	rec->a3 = (unsigned long) s;
}

static void sanitise_fw_get_cycle_timer(struct syscallrecord *rec)
{
	struct fw_cdev_get_cycle_timer *ct;

	/* output only */
	ct = (struct fw_cdev_get_cycle_timer *) get_writable_struct(sizeof(*ct));
	if (!ct)
		return;
	memset(ct, 0, sizeof(*ct));
	rec->a3 = (unsigned long) ct;
}

#ifdef FW_CDEV_IOC_GET_CYCLE_TIMER2
static void sanitise_fw_get_cycle_timer2(struct syscallrecord *rec)
{
	struct fw_cdev_get_cycle_timer2 *ct2;

	ct2 = (struct fw_cdev_get_cycle_timer2 *) get_writable_struct(sizeof(*ct2));
	if (!ct2)
		return;
	memset(ct2, 0, sizeof(*ct2));
	/* clk_id is an input field; 0=REALTIME 1=MONOTONIC */
	ct2->clk_id = rnd_modulo_u32(2);
	rec->a3 = (unsigned long) ct2;
}
#endif

#ifdef FW_CDEV_IOC_SEND_PHY_PACKET
static void sanitise_fw_send_phy_packet(struct syscallrecord *rec)
{
	struct fw_cdev_send_phy_packet *p;

	p = (struct fw_cdev_send_phy_packet *) get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));
	p->closure = rand64();
	p->data[0] = rand32();
	p->data[1] = ~p->data[0];	/* standard PHY packet encoding */
	p->generation = rand32();
	rec->a3 = (unsigned long) p;
}
#endif

#ifdef FW_CDEV_IOC_RECEIVE_PHY_PACKETS
static void sanitise_fw_receive_phy_packets(struct syscallrecord *rec)
{
	struct fw_cdev_receive_phy_packets *p;

	p = (struct fw_cdev_receive_phy_packets *) get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));
	p->closure = rand64();
	rec->a3 = (unsigned long) p;
}
#endif

#ifdef FW_CDEV_IOC_SET_ISO_CHANNELS
static void sanitise_fw_set_iso_channels(struct syscallrecord *rec)
{
	struct fw_cdev_set_iso_channels *sc;

	sc = (struct fw_cdev_set_iso_channels *) get_writable_struct(sizeof(*sc));
	if (!sc)
		return;
	memset(sc, 0, sizeof(*sc));
	sc->channels = 1ULL << (rnd_modulo_u32(64));
	sc->handle = rand32();
	rec->a3 = (unsigned long) sc;
}
#endif

#ifdef FW_CDEV_IOC_FLUSH_ISO
static void sanitise_fw_flush_iso(struct syscallrecord *rec)
{
	struct fw_cdev_flush_iso *f;

	f = (struct fw_cdev_flush_iso *) get_writable_struct(sizeof(*f));
	if (!f)
		return;
	memset(f, 0, sizeof(*f));
	f->handle = rand32();
	rec->a3 = (unsigned long) f;
}
#endif

static void firewire_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case FW_CDEV_IOC_GET_INFO:
		sanitise_fw_get_info(rec);
		break;

	case FW_CDEV_IOC_SEND_REQUEST:
	case FW_CDEV_IOC_SEND_BROADCAST_REQUEST:
		sanitise_fw_send_request(rec);
		break;

	case FW_CDEV_IOC_ALLOCATE:
		sanitise_fw_allocate(rec);
		break;

	case FW_CDEV_IOC_DEALLOCATE:
	case FW_CDEV_IOC_DEALLOCATE_ISO_RESOURCE:
		sanitise_fw_deallocate(rec);
		break;

	case FW_CDEV_IOC_SEND_RESPONSE:
		sanitise_fw_send_response(rec);
		break;

	case FW_CDEV_IOC_INITIATE_BUS_RESET:
		sanitise_fw_initiate_bus_reset(rec);
		break;

	case FW_CDEV_IOC_ADD_DESCRIPTOR:
		sanitise_fw_add_descriptor(rec);
		break;

	case FW_CDEV_IOC_REMOVE_DESCRIPTOR:
		sanitise_fw_remove_descriptor(rec);
		break;

	case FW_CDEV_IOC_CREATE_ISO_CONTEXT:
		sanitise_fw_create_iso_context(rec);
		break;

	case FW_CDEV_IOC_QUEUE_ISO:
		sanitise_fw_queue_iso(rec);
		break;

	case FW_CDEV_IOC_START_ISO:
		sanitise_fw_start_iso(rec);
		break;

	case FW_CDEV_IOC_STOP_ISO:
		sanitise_fw_stop_iso(rec);
		break;

	case FW_CDEV_IOC_GET_CYCLE_TIMER:
		sanitise_fw_get_cycle_timer(rec);
		break;

	case FW_CDEV_IOC_ALLOCATE_ISO_RESOURCE:
	case FW_CDEV_IOC_ALLOCATE_ISO_RESOURCE_ONCE:
	case FW_CDEV_IOC_DEALLOCATE_ISO_RESOURCE_ONCE:
		sanitise_fw_alloc_iso_resource(rec);
		break;

	case FW_CDEV_IOC_GET_SPEED:
		/* _IO: no pointer argument */
		break;

	case FW_CDEV_IOC_SEND_STREAM_PACKET:
		sanitise_fw_send_stream_packet(rec);
		break;

#ifdef FW_CDEV_IOC_GET_CYCLE_TIMER2
	case FW_CDEV_IOC_GET_CYCLE_TIMER2:
		sanitise_fw_get_cycle_timer2(rec);
		break;
#endif

#ifdef FW_CDEV_IOC_SEND_PHY_PACKET
	case FW_CDEV_IOC_SEND_PHY_PACKET:
		sanitise_fw_send_phy_packet(rec);
		break;
#endif

#ifdef FW_CDEV_IOC_RECEIVE_PHY_PACKETS
	case FW_CDEV_IOC_RECEIVE_PHY_PACKETS:
		sanitise_fw_receive_phy_packets(rec);
		break;
#endif

#ifdef FW_CDEV_IOC_SET_ISO_CHANNELS
	case FW_CDEV_IOC_SET_ISO_CHANNELS:
		sanitise_fw_set_iso_channels(rec);
		break;
#endif

#ifdef FW_CDEV_IOC_FLUSH_ISO
	case FW_CDEV_IOC_FLUSH_ISO:
		sanitise_fw_flush_iso(rec);
		break;
#endif

	default:
		break;
	}
}

static const struct ioctl firewire_ioctls[] = {
	IOCTL(FW_CDEV_IOC_GET_INFO),
	IOCTL(FW_CDEV_IOC_SEND_REQUEST),
	IOCTL(FW_CDEV_IOC_ALLOCATE),
	IOCTL(FW_CDEV_IOC_DEALLOCATE),
	IOCTL(FW_CDEV_IOC_SEND_RESPONSE),
	IOCTL(FW_CDEV_IOC_INITIATE_BUS_RESET),
	IOCTL(FW_CDEV_IOC_ADD_DESCRIPTOR),
	IOCTL(FW_CDEV_IOC_REMOVE_DESCRIPTOR),
	IOCTL(FW_CDEV_IOC_CREATE_ISO_CONTEXT),
	IOCTL(FW_CDEV_IOC_QUEUE_ISO),
	IOCTL(FW_CDEV_IOC_START_ISO),
	IOCTL(FW_CDEV_IOC_STOP_ISO),
	IOCTL(FW_CDEV_IOC_GET_CYCLE_TIMER),
	IOCTL(FW_CDEV_IOC_ALLOCATE_ISO_RESOURCE),
	IOCTL(FW_CDEV_IOC_DEALLOCATE_ISO_RESOURCE),
	IOCTL(FW_CDEV_IOC_ALLOCATE_ISO_RESOURCE_ONCE),
	IOCTL(FW_CDEV_IOC_DEALLOCATE_ISO_RESOURCE_ONCE),
	IOCTL(FW_CDEV_IOC_GET_SPEED),
	IOCTL(FW_CDEV_IOC_SEND_BROADCAST_REQUEST),
	IOCTL(FW_CDEV_IOC_SEND_STREAM_PACKET),
#ifdef FW_CDEV_IOC_GET_CYCLE_TIMER2
	IOCTL(FW_CDEV_IOC_GET_CYCLE_TIMER2),
#endif
#ifdef FW_CDEV_IOC_SEND_PHY_PACKET
	IOCTL(FW_CDEV_IOC_SEND_PHY_PACKET),
#endif
#ifdef FW_CDEV_IOC_RECEIVE_PHY_PACKETS
	IOCTL(FW_CDEV_IOC_RECEIVE_PHY_PACKETS),
#endif
#ifdef FW_CDEV_IOC_SET_ISO_CHANNELS
	IOCTL(FW_CDEV_IOC_SET_ISO_CHANNELS),
#endif
#ifdef FW_CDEV_IOC_FLUSH_ISO
	IOCTL(FW_CDEV_IOC_FLUSH_ISO),
#endif
};

static const char *const firewire_devs[] = {
	"firewire",
};

static const struct ioctl_group firewire_grp = {
	.devtype = DEV_MISC,
	.devs = firewire_devs,
	.devs_cnt = ARRAY_SIZE(firewire_devs),
	.sanitise = firewire_sanitise,
	.ioctls = firewire_ioctls,
	.ioctls_cnt = ARRAY_SIZE(firewire_ioctls),
};

REG_IOCTL_GROUP(firewire_grp)
