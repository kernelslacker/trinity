
#include <linux/types.h>
#include <sound/asound.h>
#include <sound/asequencer.h>

#include "ioctls.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "snd-internal.h"
#include "utils.h"

/* seq */
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_SYSTEM_INFO, struct snd_seq_system_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_RUNNING_MODE, struct snd_seq_running_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_GET_CLIENT_INFO, struct snd_seq_client_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_SET_CLIENT_INFO, struct snd_seq_client_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_QUERY_NEXT_CLIENT, struct snd_seq_client_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_CREATE_PORT, struct snd_seq_port_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_DELETE_PORT, struct snd_seq_port_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_GET_PORT_INFO, struct snd_seq_port_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_SET_PORT_INFO, struct snd_seq_port_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_QUERY_NEXT_PORT, struct snd_seq_port_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_SUBSCRIBE_PORT, struct snd_seq_port_subscribe);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_UNSUBSCRIBE_PORT, struct snd_seq_port_subscribe);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_GET_SUBSCRIPTION, struct snd_seq_port_subscribe);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_CREATE_QUEUE, struct snd_seq_queue_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_DELETE_QUEUE, struct snd_seq_queue_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_GET_QUEUE_INFO, struct snd_seq_queue_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_SET_QUEUE_INFO, struct snd_seq_queue_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_GET_NAMED_QUEUE, struct snd_seq_queue_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_GET_QUEUE_STATUS, struct snd_seq_queue_status);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_GET_QUEUE_TEMPO, struct snd_seq_queue_tempo);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_SET_QUEUE_TEMPO, struct snd_seq_queue_tempo);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_GET_QUEUE_TIMER, struct snd_seq_queue_timer);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_SET_QUEUE_TIMER, struct snd_seq_queue_timer);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_GET_QUEUE_CLIENT, struct snd_seq_queue_client);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_SET_QUEUE_CLIENT, struct snd_seq_queue_client);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_GET_CLIENT_POOL, struct snd_seq_client_pool);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_SET_CLIENT_POOL, struct snd_seq_client_pool);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_REMOVE_EVENTS, struct snd_seq_remove_events);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_QUERY_SUBS, struct snd_seq_query_subs);
#ifdef SNDRV_SEQ_IOCTL_GET_CLIENT_UMP_INFO
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_GET_CLIENT_UMP_INFO, struct snd_seq_client_ump_info);
IOCTL_SIZE_ASSERT(SNDRV_SEQ_IOCTL_SET_CLIENT_UMP_INFO, struct snd_seq_client_ump_info);
#endif

static void fill_snd_seq_addr(struct snd_seq_addr *addr)
{
	addr->client = rnd_modulo_u32(128);
	addr->port = rnd_modulo_u32(256);
}

static void sanitise_snd_seq_system_info(struct syscallrecord *rec)
{
	struct snd_seq_system_info *info = get_writable_struct(sizeof(*info));
	if (info) {
		memset(info, 0, sizeof(*info));
		rec->a3 = (unsigned long) info;
	}
}

static void sanitise_snd_seq_running_mode(struct syscallrecord *rec)
{
	struct snd_seq_running_info *info = get_writable_struct(sizeof(*info));
	if (info) {
		memset(info, 0, sizeof(*info));
		info->client = rnd_modulo_u32(128);
		rec->a3 = (unsigned long) info;
	}
}

static void sanitise_snd_seq_client_info(struct syscallrecord *rec)
{
	struct snd_seq_client_info *ci = get_writable_struct(sizeof(*ci));
	if (ci) {
		memset(ci, 0, sizeof(*ci));
		ci->client = RAND_BOOL() ? -1 : (int)(rnd_modulo_u32(128));
		rec->a3 = (unsigned long) ci;
	}
}

static void sanitise_snd_seq_port_info(struct syscallrecord *rec)
{
	struct snd_seq_port_info *pi = get_writable_struct(sizeof(*pi));
	if (pi) {
		memset(pi, 0, sizeof(*pi));
		fill_snd_seq_addr(&pi->addr);
		if (rec->a2 == SNDRV_SEQ_IOCTL_QUERY_NEXT_PORT)
			pi->addr.port = (unsigned char)(rnd_modulo_u32(256) - 1);
		pi->capability = rnd_u32();
		pi->type = rnd_u32();
		pi->midi_channels = rnd_modulo_u32(16) + 1;
		rec->a3 = (unsigned long) pi;
	}
}

static void sanitise_snd_seq_port_subscribe(struct syscallrecord *rec)
{
	struct snd_seq_port_subscribe *sub = get_writable_struct(sizeof(*sub));
	if (sub) {
		memset(sub, 0, sizeof(*sub));
		fill_snd_seq_addr(&sub->sender);
		fill_snd_seq_addr(&sub->dest);
		rec->a3 = (unsigned long) sub;
	}
}

static void sanitise_snd_seq_queue_info(struct syscallrecord *rec)
{
	struct snd_seq_queue_info *qi = get_writable_struct(sizeof(*qi));
	if (qi) {
		memset(qi, 0, sizeof(*qi));
		qi->queue = rnd_modulo_u32(8);
		qi->owner = rnd_modulo_u32(128);
		rec->a3 = (unsigned long) qi;
	}
}

static void sanitise_snd_seq_queue_status(struct syscallrecord *rec)
{
	struct snd_seq_queue_status *qs = get_writable_struct(sizeof(*qs));
	if (qs) {
		memset(qs, 0, sizeof(*qs));
		qs->queue = rnd_modulo_u32(8);
		rec->a3 = (unsigned long) qs;
	}
}

static void sanitise_snd_seq_queue_tempo(struct syscallrecord *rec)
{
	struct snd_seq_queue_tempo *qt = get_writable_struct(sizeof(*qt));
	if (qt) {
		memset(qt, 0, sizeof(*qt));
		qt->queue = rnd_modulo_u32(8);
		qt->tempo = rnd_modulo_u32(2000000) + 60000;	/* 60ms-2s per beat */
		qt->ppq = rnd_modulo_u32(480) + 24;
		rec->a3 = (unsigned long) qt;
	}
}

static void sanitise_snd_seq_queue_timer(struct syscallrecord *rec)
{
	struct snd_seq_queue_timer *timer = get_writable_struct(sizeof(*timer));
	if (timer) {
		memset(timer, 0, sizeof(*timer));
		timer->queue = rnd_modulo_u32(8);
		timer->type = rnd_modulo_u32(3);
		fill_snd_timer_id(&timer->u.alsa.id);
		timer->u.alsa.resolution = rnd_modulo_u32(480) + 24;
		rec->a3 = (unsigned long) timer;
	}
}

static void sanitise_snd_seq_queue_client(struct syscallrecord *rec)
{
	struct snd_seq_queue_client *qc = get_writable_struct(sizeof(*qc));
	if (qc) {
		memset(qc, 0, sizeof(*qc));
		qc->queue = rnd_modulo_u32(8);
		qc->client = rnd_modulo_u32(128);
		qc->used = RAND_BOOL();
		rec->a3 = (unsigned long) qc;
	}
}

static void sanitise_snd_seq_client_pool(struct syscallrecord *rec)
{
	struct snd_seq_client_pool *cp = get_writable_struct(sizeof(*cp));
	if (cp) {
		memset(cp, 0, sizeof(*cp));
		cp->client = rnd_modulo_u32(128);
		cp->output_pool = rnd_modulo_u32(1024) + 64;
		cp->input_pool = rnd_modulo_u32(512) + 32;
		cp->output_room = rnd_modulo_u32(64) + 1;
		rec->a3 = (unsigned long) cp;
	}
}

static void sanitise_snd_seq_remove_events(struct syscallrecord *rec)
{
	struct snd_seq_remove_events *re = get_writable_struct(sizeof(*re));
	if (re) {
		memset(re, 0, sizeof(*re));
		re->remove_mode = rnd_u32() & 0x3ff;
		rec->a3 = (unsigned long) re;
	}
}

static void sanitise_snd_seq_query_subs(struct syscallrecord *rec)
{
	struct snd_seq_query_subs *qs = get_writable_struct(sizeof(*qs));
	if (qs) {
		memset(qs, 0, sizeof(*qs));
		fill_snd_seq_addr(&qs->root);
		qs->type = rnd_u32() & 1;
		qs->index = rnd_modulo_u32(64);
		rec->a3 = (unsigned long) qs;
	}
}

#ifdef SNDRV_SEQ_IOCTL_GET_CLIENT_UMP_INFO
static void sanitise_snd_seq_client_ump_info(struct syscallrecord *rec)
{
	struct snd_seq_client_ump_info *ui = get_writable_struct(sizeof(*ui));
	if (ui) {
		memset(ui, 0, sizeof(*ui));
		ui->client = RAND_BOOL() ? -1 : (int)(rnd_modulo_u32(128));
		ui->type = rnd_u32() & 1;	/* ENDPOINT or BLOCK */
		rec->a3 = (unsigned long) ui;
	}
}
#endif

void sanitise_snd_seq(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDRV_SEQ_IOCTL_SYSTEM_INFO:
		sanitise_snd_seq_system_info(rec);
		break;
	case SNDRV_SEQ_IOCTL_RUNNING_MODE:
		sanitise_snd_seq_running_mode(rec);
		break;
	case SNDRV_SEQ_IOCTL_GET_CLIENT_INFO:
	case SNDRV_SEQ_IOCTL_SET_CLIENT_INFO:
	case SNDRV_SEQ_IOCTL_QUERY_NEXT_CLIENT:
		sanitise_snd_seq_client_info(rec);
		break;
	case SNDRV_SEQ_IOCTL_CREATE_PORT:
	case SNDRV_SEQ_IOCTL_DELETE_PORT:
	case SNDRV_SEQ_IOCTL_GET_PORT_INFO:
	case SNDRV_SEQ_IOCTL_SET_PORT_INFO:
	case SNDRV_SEQ_IOCTL_QUERY_NEXT_PORT:
		sanitise_snd_seq_port_info(rec);
		break;
	case SNDRV_SEQ_IOCTL_SUBSCRIBE_PORT:
	case SNDRV_SEQ_IOCTL_UNSUBSCRIBE_PORT:
	case SNDRV_SEQ_IOCTL_GET_SUBSCRIPTION:
		sanitise_snd_seq_port_subscribe(rec);
		break;
	case SNDRV_SEQ_IOCTL_CREATE_QUEUE:
	case SNDRV_SEQ_IOCTL_DELETE_QUEUE:
	case SNDRV_SEQ_IOCTL_GET_QUEUE_INFO:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_INFO:
	case SNDRV_SEQ_IOCTL_GET_NAMED_QUEUE:
		sanitise_snd_seq_queue_info(rec);
		break;
	case SNDRV_SEQ_IOCTL_GET_QUEUE_STATUS:
		sanitise_snd_seq_queue_status(rec);
		break;
	case SNDRV_SEQ_IOCTL_GET_QUEUE_TEMPO:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_TEMPO:
		sanitise_snd_seq_queue_tempo(rec);
		break;
	case SNDRV_SEQ_IOCTL_GET_QUEUE_TIMER:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_TIMER:
		sanitise_snd_seq_queue_timer(rec);
		break;
	case SNDRV_SEQ_IOCTL_GET_QUEUE_CLIENT:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_CLIENT:
		sanitise_snd_seq_queue_client(rec);
		break;
	case SNDRV_SEQ_IOCTL_GET_CLIENT_POOL:
	case SNDRV_SEQ_IOCTL_SET_CLIENT_POOL:
		sanitise_snd_seq_client_pool(rec);
		break;
	case SNDRV_SEQ_IOCTL_REMOVE_EVENTS:
		sanitise_snd_seq_remove_events(rec);
		break;
	case SNDRV_SEQ_IOCTL_QUERY_SUBS:
		sanitise_snd_seq_query_subs(rec);
		break;
#ifdef SNDRV_SEQ_IOCTL_GET_CLIENT_UMP_INFO
	case SNDRV_SEQ_IOCTL_GET_CLIENT_UMP_INFO:
	case SNDRV_SEQ_IOCTL_SET_CLIENT_UMP_INFO:
		sanitise_snd_seq_client_ump_info(rec);
		break;
#endif
	default:
		break;
	}
}

/* snd-seq */
int dispatch_snd_seq(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case SNDRV_SEQ_IOCTL_SYSTEM_INFO:
	case SNDRV_SEQ_IOCTL_RUNNING_MODE:
	case SNDRV_SEQ_IOCTL_GET_CLIENT_INFO:
	case SNDRV_SEQ_IOCTL_SET_CLIENT_INFO:
	case SNDRV_SEQ_IOCTL_CREATE_PORT:
	case SNDRV_SEQ_IOCTL_DELETE_PORT:
	case SNDRV_SEQ_IOCTL_GET_PORT_INFO:
	case SNDRV_SEQ_IOCTL_SET_PORT_INFO:
	case SNDRV_SEQ_IOCTL_SUBSCRIBE_PORT:
	case SNDRV_SEQ_IOCTL_UNSUBSCRIBE_PORT:
	case SNDRV_SEQ_IOCTL_CREATE_QUEUE:
	case SNDRV_SEQ_IOCTL_DELETE_QUEUE:
	case SNDRV_SEQ_IOCTL_GET_QUEUE_INFO:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_INFO:
	case SNDRV_SEQ_IOCTL_GET_NAMED_QUEUE:
	case SNDRV_SEQ_IOCTL_GET_QUEUE_STATUS:
	case SNDRV_SEQ_IOCTL_GET_QUEUE_TEMPO:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_TEMPO:
	case SNDRV_SEQ_IOCTL_GET_QUEUE_TIMER:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_TIMER:
	case SNDRV_SEQ_IOCTL_GET_QUEUE_CLIENT:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_CLIENT:
	case SNDRV_SEQ_IOCTL_GET_CLIENT_POOL:
	case SNDRV_SEQ_IOCTL_SET_CLIENT_POOL:
	case SNDRV_SEQ_IOCTL_REMOVE_EVENTS:
	case SNDRV_SEQ_IOCTL_QUERY_SUBS:
	case SNDRV_SEQ_IOCTL_GET_SUBSCRIPTION:
	case SNDRV_SEQ_IOCTL_QUERY_NEXT_CLIENT:
	case SNDRV_SEQ_IOCTL_QUERY_NEXT_PORT:
#ifdef SNDRV_SEQ_IOCTL_GET_CLIENT_UMP_INFO
	case SNDRV_SEQ_IOCTL_GET_CLIENT_UMP_INFO:
	case SNDRV_SEQ_IOCTL_SET_CLIENT_UMP_INFO:
#endif
		sanitise_snd_seq(rec);
		return 1;
	}
	return 0;
}
