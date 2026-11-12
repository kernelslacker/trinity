/*
 * Struct catalog: a static catalog of known struct types (with per-field
 * offset and size) and the by-name lookup over it.  The (syscall, arg)
 * mapping and the nr-indexed lookup live in struct_catalog/registry.c.
 */

#include <stddef.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <utime.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <linux/if_packet.h>
#include <linux/netfilter.h>
#include <linux/sched.h>
#include <linux/sched/types.h>
#include <linux/mount.h>
#include <fcntl.h>
#include <string.h>

#include "config.h"
#ifdef USE_BPF
#include <linux/bpf.h>
#endif
#ifdef USE_SCTP
#include <linux/sctp.h>
#endif
#ifdef USE_TCP_REPAIR_OPT
#include <linux/tcp.h>
#endif

#include "argtype-ops.h"
#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"
#include "debug.h"
#include "perf.h"
#include "perf_event.h"
#include "random.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

/* FIELD / FIELDX initialiser macros live in struct_catalog-internal.h
 * so the per-family leaf TUs under struct_catalog/ can reuse them. */

/* ------------------------------------------------------------------ */
/* The catalog itself                                                   */
/* ------------------------------------------------------------------ */

const struct struct_desc struct_catalog[] = {
	/* Slot order is immaterial -- refs use SC_X. */
	[SC_SCHED_ATTR] = {
		.name		= "sched_attr",
		.struct_size	= sizeof(struct sched_attr),
		.fields		= sched_attr_fields,
		.num_fields	= ARRAY_SIZE(sched_attr_fields),
	},
	[SC_CLONE_ARGS] = {
		.name		= "clone_args",
		.struct_size	= sizeof(struct clone_args),
		.fields		= clone_args_fields,
		.num_fields	= ARRAY_SIZE(clone_args_fields),
	},
	[SC_RLIMIT] = {
		.name		= "rlimit",
		.struct_size	= sizeof(struct rlimit),
		.fields		= rlimit_fields,
		.num_fields	= ARRAY_SIZE(rlimit_fields),
	},
	[SC_EPOLL_EVENT] = {
		.name		= "epoll_event",
		.struct_size	= sizeof(struct epoll_event),
		.fields		= epoll_event_fields,
		.num_fields	= ARRAY_SIZE(epoll_event_fields),
	},
	[SC_PERF_EVENT_ATTR] = {
		.name			= "perf_event_attr",
		.struct_size		= sizeof(struct perf_event_attr),
		.fields			= perf_event_attr_fields,
		.num_fields		= ARRAY_SIZE(perf_event_attr_fields),
		.variants		= perf_event_attr_variants,
		.num_variants		= ARRAY_SIZE(perf_event_attr_variants),
		.buffer_discrim_offset	= offsetof(struct perf_event_attr, type),
		.buffer_discrim_size	= sizeof(((struct perf_event_attr *) 0)->
						 type),
	},
#include "catalog-bpf.inc"
	[SC_MOUNT_ATTR] = {
		.name		= "mount_attr",
		.struct_size	= sizeof(struct mount_attr),
		.fields		= mount_attr_fields,
		.num_fields	= ARRAY_SIZE(mount_attr_fields),
	},
	[SC_UTIMBUF] = {
		.name		= "utimbuf",
		.struct_size	= sizeof(struct utimbuf),
		.fields		= utimbuf_fields,
		.num_fields	= ARRAY_SIZE(utimbuf_fields),
	},
	[SC_FLOCK] = {
		.name		= "flock",
		.struct_size	= sizeof(struct flock),
		.fields		= flock_fields,
		.num_fields	= ARRAY_SIZE(flock_fields),
	},
	[SC_TIMEVAL] = {
		.name		= "timeval",
		.struct_size	= sizeof(struct timeval),
		.fields		= timeval_fields,
		.num_fields	= ARRAY_SIZE(timeval_fields),
	},
	[SC_F_OWNER_EX] = {
		.name		= "f_owner_ex",
		.struct_size	= sizeof(struct f_owner_ex),
		.fields		= f_owner_ex_fields,
		.num_fields	= ARRAY_SIZE(f_owner_ex_fields),
	},
#include "catalog-setsockopt.inc"
#ifdef USE_TCP_REPAIR_OPT
	[SC_TCP_REPAIR_OPT] = {
		.name		= "tcp_repair_opt",
		.struct_size	= sizeof(struct tcp_repair_opt),
		.fields		= tcp_repair_opt_fields,
		.num_fields	= ARRAY_SIZE(tcp_repair_opt_fields),
	},
#endif
#include "catalog-sctp.inc"
	[SC_FILE_HANDLE] = {
		.name		= "file_handle",
		.struct_size	= sizeof(struct file_handle),
		.fields		= file_handle_fields,
		.num_fields	= ARRAY_SIZE(file_handle_fields),
	},
};

/*
 * Lock the enum and the array in lockstep at compile time.  A missing
 * [SC_X] = {...} slot would let ARRAY_SIZE diverge from SC_NR_ENTRIES;
 * catching it here is sharper than the runtime hole-check below.
 */
_Static_assert(ARRAY_SIZE(struct_catalog) == SC_NR_ENTRIES,
	       "struct_catalog[] and enum struct_catalog_idx must stay in lockstep");

/* ------------------------------------------------------------------ */
/* API                                                                  */
/* ------------------------------------------------------------------ */

const struct struct_desc *struct_catalog_lookup(const char *name)
{
	unsigned int i;

	if (name == NULL)
		return NULL;

	for (i = 0; i < SC_NR_ENTRIES; i++) {
		if (strcmp(struct_catalog[i].name, name) == 0)
			return &struct_catalog[i];
	}
	return NULL;
}


