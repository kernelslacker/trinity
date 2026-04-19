#include <linux/firewire-cdev.h>

#include "ioctls.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

static void sanitise_fw_send_request(struct syscallrecord *rec)
{
	struct fw_cdev_send_request *req;
	__u32 payload_len;

	req = (struct fw_cdev_send_request *) get_writable_struct(sizeof(*req));
	if (!req)
		return;
	req->tcode = rand() % 16;
	payload_len = rand() % 512;
	req->length = payload_len;
	req->offset = rand64() & 0xFFFFFFFFFFFFULL;	/* 48-bit address space */
	req->closure = rand64();
	req->data = (unsigned long) get_writable_struct(payload_len + 4);
	req->generation = rand32();
	rec->a3 = (unsigned long) req;
}

static void sanitise_fw_allocate(struct syscallrecord *rec)
{
	struct fw_cdev_allocate *a;

	a = (struct fw_cdev_allocate *) get_writable_struct(sizeof(*a));
	if (!a)
		return;
	a->offset = rand64() & 0xFFFFFFFFFFFFULL;
	a->closure = rand64();
	a->length = rand() % 4096 + 4;
	a->region_end = a->offset + a->length;
	rec->a3 = (unsigned long) a;
}

static void sanitise_fw_deallocate(struct syscallrecord *rec)
{
	struct fw_cdev_deallocate *d;

	d = (struct fw_cdev_deallocate *) get_writable_struct(sizeof(*d));
	if (!d)
		return;
	d->handle = rand32();
	rec->a3 = (unsigned long) d;
}

static void sanitise_fw_send_response(struct syscallrecord *rec)
{
	struct fw_cdev_send_response *resp;
	__u32 payload_len;

	resp = (struct fw_cdev_send_response *) get_writable_struct(sizeof(*resp));
	if (!resp)
		return;
	resp->rcode = rand() % 8;
	payload_len = rand() % 512;
	resp->length = payload_len;
	resp->data = (unsigned long) get_writable_struct(payload_len + 4);
	resp->handle = rand32();
	rec->a3 = (unsigned long) resp;
}

static void sanitise_fw_add_descriptor(struct syscallrecord *rec)
{
	struct fw_cdev_add_descriptor *desc;
	__u32 len;

	desc = (struct fw_cdev_add_descriptor *) get_writable_struct(sizeof(*desc));
	if (!desc)
		return;
	desc->immediate = RAND_BOOL() ? rand32() : 0;
	desc->key = 0x81000000;	/* leaf entry type */
	len = rand() % 16 + 1;
	desc->length = len;
	desc->data = (unsigned long) get_writable_struct(len * 4);
	rec->a3 = (unsigned long) desc;
}

static void sanitise_fw_create_iso_context(struct syscallrecord *rec)
{
	struct fw_cdev_create_iso_context *ctx;

	ctx = (struct fw_cdev_create_iso_context *) get_writable_struct(sizeof(*ctx));
	if (!ctx)
		return;
	ctx->type = rand() % 3;
	ctx->header_size = (rand() % 8) * 4;	/* must be multiple of 4 */
	ctx->channel = rand() % 64;
	ctx->speed = rand() % 6;
	ctx->closure = rand64();
	rec->a3 = (unsigned long) ctx;
}

static void sanitise_fw_queue_iso(struct syscallrecord *rec)
{
	struct fw_cdev_queue_iso *q;
	struct fw_cdev_iso_packet *pkt;

	q = (struct fw_cdev_queue_iso *) get_writable_struct(sizeof(*q));
	if (!q)
		return;
	pkt = (struct fw_cdev_iso_packet *) get_writable_struct(sizeof(*pkt));
	if (pkt)
		pkt->control = rand32();
	q->packets = (unsigned long) pkt;
	q->data = (unsigned long) get_writable_struct(4096);
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
	s->cycle = RAND_BOOL() ? -1 : (rand() % 8000);
	s->sync = rand() % 16;
	s->tags = rand() % 16;
	s->handle = rand32();
	rec->a3 = (unsigned long) s;
}

static void sanitise_fw_alloc_iso_resource(struct syscallrecord *rec)
{
	struct fw_cdev_allocate_iso_resource *r;

	r = (struct fw_cdev_allocate_iso_resource *) get_writable_struct(sizeof(*r));
	if (!r)
		return;
	r->closure = rand64();
	r->channels = 1ULL << (rand() % 64);
	r->bandwidth = rand() % 4096;
	rec->a3 = (unsigned long) r;
}

static void sanitise_fw_send_stream_packet(struct syscallrecord *rec)
{
	struct fw_cdev_send_stream_packet *pkt;
	__u32 payload_len;

	pkt = (struct fw_cdev_send_stream_packet *) get_writable_struct(sizeof(*pkt));
	if (!pkt)
		return;
	payload_len = rand() % 512;
	pkt->length = payload_len;
	pkt->tag = rand() % 4;
	pkt->channel = rand() % 64;
	pkt->sy = rand() % 16;
	pkt->closure = rand64();
	pkt->data = (unsigned long) get_writable_struct(payload_len + 4);
	pkt->generation = rand32();
	pkt->speed = rand() % 6;
	rec->a3 = (unsigned long) pkt;
}

static void firewire_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case FW_CDEV_IOC_GET_INFO: {
		/* mostly output; just allocate and let kernel fill it */
		struct fw_cdev_get_info *info = get_writable_struct(sizeof(*info));
		if (info) {
			info->version = rand() % 6 + 1;
			info->bus_reset_closure = rand64();
			rec->a3 = (unsigned long) info;
		}
		break;
	}

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

	case FW_CDEV_IOC_INITIATE_BUS_RESET: {
		struct fw_cdev_initiate_bus_reset *r = get_writable_struct(sizeof(*r));
		if (r) {
			r->type = rand() % 2;	/* FW_CDEV_LONG_RESET or FW_CDEV_SHORT_RESET */
			rec->a3 = (unsigned long) r;
		}
		break;
	}

	case FW_CDEV_IOC_ADD_DESCRIPTOR:
		sanitise_fw_add_descriptor(rec);
		break;

	case FW_CDEV_IOC_REMOVE_DESCRIPTOR: {
		struct fw_cdev_remove_descriptor *d = get_writable_struct(sizeof(*d));
		if (d) {
			d->handle = rand32();
			rec->a3 = (unsigned long) d;
		}
		break;
	}

	case FW_CDEV_IOC_CREATE_ISO_CONTEXT:
		sanitise_fw_create_iso_context(rec);
		break;

	case FW_CDEV_IOC_QUEUE_ISO:
		sanitise_fw_queue_iso(rec);
		break;

	case FW_CDEV_IOC_START_ISO:
		sanitise_fw_start_iso(rec);
		break;

	case FW_CDEV_IOC_STOP_ISO: {
		struct fw_cdev_stop_iso *s = get_writable_struct(sizeof(*s));
		if (s) {
			s->handle = rand32();
			rec->a3 = (unsigned long) s;
		}
		break;
	}

	case FW_CDEV_IOC_GET_CYCLE_TIMER: {
		/* output only */
		struct fw_cdev_get_cycle_timer *ct = get_writable_struct(sizeof(*ct));
		if (ct)
			rec->a3 = (unsigned long) ct;
		break;
	}

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
	case FW_CDEV_IOC_GET_CYCLE_TIMER2: {
		struct fw_cdev_get_cycle_timer2 *ct2 = get_writable_struct(sizeof(*ct2));
		if (ct2) {
			/* clk_id is an input field; 0=REALTIME 1=MONOTONIC */
			ct2->clk_id = rand() % 2;
			rec->a3 = (unsigned long) ct2;
		}
		break;
	}
#endif

#ifdef FW_CDEV_IOC_SEND_PHY_PACKET
	case FW_CDEV_IOC_SEND_PHY_PACKET: {
		struct fw_cdev_send_phy_packet *p = get_writable_struct(sizeof(*p));
		if (p) {
			p->closure = rand64();
			p->data[0] = rand32();
			p->data[1] = ~p->data[0];	/* standard PHY packet encoding */
			p->generation = rand32();
			rec->a3 = (unsigned long) p;
		}
		break;
	}
#endif

#ifdef FW_CDEV_IOC_RECEIVE_PHY_PACKETS
	case FW_CDEV_IOC_RECEIVE_PHY_PACKETS: {
		struct fw_cdev_receive_phy_packets *p = get_writable_struct(sizeof(*p));
		if (p) {
			p->closure = rand64();
			rec->a3 = (unsigned long) p;
		}
		break;
	}
#endif

#ifdef FW_CDEV_IOC_SET_ISO_CHANNELS
	case FW_CDEV_IOC_SET_ISO_CHANNELS: {
		struct fw_cdev_set_iso_channels *sc = get_writable_struct(sizeof(*sc));
		if (sc) {
			sc->channels = 1ULL << (rand() % 64);
			sc->handle = rand32();
			rec->a3 = (unsigned long) sc;
		}
		break;
	}
#endif

#ifdef FW_CDEV_IOC_FLUSH_ISO
	case FW_CDEV_IOC_FLUSH_ISO: {
		struct fw_cdev_flush_iso *f = get_writable_struct(sizeof(*f));
		if (f) {
			f->handle = rand32();
			rec->a3 = (unsigned long) f;
		}
		break;
	}
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
