/*
 * Struct catalog and offset mapping for CMP-guided struct filling.
 *
 * Provides a static catalog of known struct types (with per-field offset
 * and size), a table mapping syscall args to those struct types, and a
 * fast nr-indexed lookup built at init time.
 *
 * The field-for-CMP heuristic uses value magnitude to narrow which field
 * a kernel CMP constant was most likely comparing against.
 */

#include <stddef.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <utime.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <linux/netlink.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/tipc.h>
#include <linux/netfilter.h>
#include <linux/sched.h>
#include <linux/sched/types.h>
#include <linux/mount.h>
#include <linux/userfaultfd.h>
#include <fcntl.h>
#include <string.h>

#include "config.h"
/*
 * linux/if_pppox.h pulls in linux/l2tp.h, whose enum declares
 * L2TP_ATTR_IP6_SADDR / RX_COOKIE_DISCARDS / ... as identifiers.
 * include/kernel headers define those same names as fallback numeric macros for
 * older kernel-headers packages, so the include must precede the kernel fallback header;
 * otherwise the macro expansion turns the enum members into integer
 * literals and -Werror trips.
 */
#ifdef USE_PPPOX
#include <linux/if_pppox.h>
#endif
#ifdef USE_BPF
#include <linux/bpf.h>
#endif
#ifdef USE_VSOCK
#include <linux/vm_sockets.h>
#endif
#ifdef USE_CAN
#include <linux/can.h>
#endif
#ifdef USE_RXRPC
#include <linux/rxrpc.h>
#endif
#ifdef USE_X25
#include <linux/x25.h>
#endif
#ifdef USE_PHONET
#include <linux/phonet.h>
#endif
#ifdef USE_ATALK
#include <linux/atalk.h>
#endif
#ifdef USE_ATM
#include <linux/atm.h>
#endif
#ifdef USE_LLC
#include <linux/llc.h>
#endif
#ifdef USE_MCTP
#include <linux/mctp.h>
#endif
#ifdef USE_XDP
#include <linux/if_xdp.h>
/*
 * XDP_USE_NEED_WAKEUP landed in 5.4 (commit 77cd0d7b3f25); older
 * toolchain headers won't carry it even when the rest of the
 * sockaddr_xdp definitions are present.  Fall back to the upstream
 * bit value so the FT_FLAGS mask stays the same on either side.
 */
#ifndef XDP_USE_NEED_WAKEUP
#define XDP_USE_NEED_WAKEUP	(1 << 3)
#endif
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
#if defined(__x86_64__) || defined(__aarch64__)
/*
 * struct pt_regs (x86_64) / struct user_pt_regs (aarch64) live in
 * <asm/ptrace.h>; struct user_regs_struct lives in <sys/user.h> on
 * both arches.  The spine needs the types visible for sizeof() on
 * its catalog entries; the leaf TU under struct_catalog/ptrace_regs.c
 * pulls the same headers for FIELD() offsetof / sizeof initialisers.
 */
#include <asm/ptrace.h>
#include <sys/user.h>
#endif
#include "debug.h"
#include "perf.h"		/* random_tracepoint_config -- FT_PICKER for TRACEPOINT.config */
#include "perf_event.h"
#include "random.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/l2tp.h"
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
	[SC_SOCKADDR_STORAGE] = {
		.name			= "sockaddr_storage",
		.struct_size		= sizeof(struct sockaddr_storage),
		.fields			= sockaddr_storage_fields,
		.num_fields		= ARRAY_SIZE(sockaddr_storage_fields),
		.variants		= sockaddr_storage_variants,
		.num_variants		= ARRAY_SIZE(sockaddr_storage_variants),
		.buffer_discrim_offset	= offsetof(struct sockaddr_storage,
						   ss_family),
		.buffer_discrim_size	= sizeof(((struct sockaddr_storage *) 0)->
						 ss_family),
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
#include "catalog-ptrace_regs.inc"
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
#include "catalog-uffdio.inc"
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


