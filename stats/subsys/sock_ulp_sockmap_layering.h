#ifndef _TRINITY_STATS_SUBSYS_SOCK_ULP_SOCKMAP_LAYERING_H
#define _TRINITY_STATS_SUBSYS_SOCK_ULP_SOCKMAP_LAYERING_H

struct sock_ulp_sockmap_layering_stats {
	/* sock_ulp_sockmap_layering childop counters */
	unsigned long runs;		/* total invocations */
	unsigned long setup_failed;	/* loopback TCP pair setup failed */
	unsigned long map_failed;	/* BPF_MAP_CREATE(SOCKMAP) failed (no CONFIG_BPF_SYSCALL etc) */
	unsigned long prog_failed;	/* BPF_PROG_LOAD(SK_SKB) failed (no CONFIG_BPF_STREAM_PARSER etc) */
	unsigned long attach_failed;	/* BPF_PROG_ATTACH(STREAM_VERDICT) failed */
	unsigned long layered_ok;	/* at least one fd ended up with both ULP+sockmap layered */
};

#endif /* _TRINITY_STATS_SUBSYS_SOCK_ULP_SOCKMAP_LAYERING_H */
