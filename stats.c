#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "arch.h"
#include "arg-len-semantics.h"
#include "breadcrumb_ring.h"
#include "child.h"
#include "cmp_hints.h"
#include "cred_throttle.h"
#include "fd.h"
#include "kcov.h"
#include "minicorpus.h"
#include "params.h"
#include "pc_format.h"
#include "pids.h"
#include "reach-band.h"
#include "sequence.h"
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "stats_ring.h"
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "utils.h"
#include "version.h"

/*
 * Linker-provided bounds of the running binary's executable text.  Used
 * to filter PC samples whose storage was itself stomped by the wild
 * writes we are trying to attribute -- an entry whose pc lands outside
 * [__executable_start, _etext) cannot be a real call site and would
 * otherwise dump as garbage.
 */
extern char __executable_start[];
extern char _etext[];

bool pc_in_text(void *pc)
{
	return pc >= (void *)__executable_start && pc < (void *)_etext;
}

const char * const op_names[MUT_NUM_OPS] = {
	"bit-flip", "add", "sub", "boundary", "byte-shuf", "keep",
	"bswap-add", "bswap-sub", "fd-swap"
};

/*
 * Aggregate-stats table column widths. Header + every row uses the same
 * format string so output is greppable (grep '^fd_lifecycle ') and
 * human-scannable (columns line up).
 */
static void stats_emit_header(void)
{
	output(0, "\n");
	output(0, STATS_HDR_FMT, "CATEGORY", "METRIC", "VALUE");
	output(0, STATS_HDR_FMT,
	       "----------------------",
	       "--------------------------------",
	       "-----");
}

void stat_row(const char *category, const char *metric, unsigned long value)
{
	output(0, STATS_ROW_FMT, category, metric, value);
}

/*
 * Mechanical name-prefix → category lookup.  The table is ordered so that
 * longer prefixes shadow shorter ones for the same head ("readlink" before
 * "read", "sendfile" before "send"); first match wins.  Operator-grade
 * categorisation, not a taxonomy — anything not listed lands in OTHER.
 */
unsigned int stats_syscall_category(const char *name)
{
	static const struct { const char *p; unsigned char cat; } tab[] = {
		{ "readlink", SYSCAT_FILE },   { "preadv",   SYSCAT_READ },
		{ "pread",    SYSCAT_READ },   { "read",     SYSCAT_READ },
		{ "pwritev",  SYSCAT_WRITE },  { "pwrite",   SYSCAT_WRITE },
		{ "writev",   SYSCAT_WRITE },  { "write",    SYSCAT_WRITE },
		{ "open",     SYSCAT_OPEN },   { "creat",    SYSCAT_OPEN },
		{ "mmap",     SYSCAT_MMAP },   { "munmap",   SYSCAT_MMAP },
		{ "mremap",   SYSCAT_MMAP },   { "mprotect", SYSCAT_MMAP },
		{ "madvise",  SYSCAT_MMAP },   { "msync",    SYSCAT_MMAP },
		{ "mbind",    SYSCAT_MMAP },   { "mlock",    SYSCAT_MMAP },
		{ "munlock",  SYSCAT_MMAP },   { "mincore",  SYSCAT_MMAP },
		{ "brk",      SYSCAT_MMAP },
		{ "sendfile", SYSCAT_FILE },
		{ "socket",   SYSCAT_SOCKET }, { "bind",     SYSCAT_SOCKET },
		{ "listen",   SYSCAT_SOCKET }, { "accept",   SYSCAT_SOCKET },
		{ "connect",  SYSCAT_SOCKET }, { "send",     SYSCAT_SOCKET },
		{ "recv",     SYSCAT_SOCKET }, { "shutdown", SYSCAT_SOCKET },
		{ "getsock",  SYSCAT_SOCKET }, { "setsock",  SYSCAT_SOCKET },
		{ "getpeer",  SYSCAT_SOCKET },
		{ "fork",     SYSCAT_PROCESS },{ "vfork",    SYSCAT_PROCESS },
		{ "clone",    SYSCAT_PROCESS },{ "exec",     SYSCAT_PROCESS },
		{ "exit",     SYSCAT_PROCESS },{ "wait",     SYSCAT_PROCESS },
		{ "kill",     SYSCAT_PROCESS },{ "tkill",    SYSCAT_PROCESS },
		{ "tgkill",   SYSCAT_PROCESS },{ "pidfd",    SYSCAT_PROCESS },
		{ "futex",    SYSCAT_IPC },    { "mq_",      SYSCAT_IPC },
		{ "msg",      SYSCAT_IPC },    { "sem",      SYSCAT_IPC },
		{ "shm",      SYSCAT_IPC },    { "pipe",     SYSCAT_IPC },
		{ "eventfd",  SYSCAT_IPC },    { "signalfd", SYSCAT_IPC },
		{ "rt_sig",   SYSCAT_IPC },    { "sigaction",SYSCAT_IPC },
		{ "stat",     SYSCAT_FILE },   { "fstat",    SYSCAT_FILE },
		{ "lstat",    SYSCAT_FILE },   { "access",   SYSCAT_FILE },
		{ "chmod",    SYSCAT_FILE },   { "chown",    SYSCAT_FILE },
		{ "fchmod",   SYSCAT_FILE },   { "fchown",   SYSCAT_FILE },
		{ "lchown",   SYSCAT_FILE },   { "link",     SYSCAT_FILE },
		{ "unlink",   SYSCAT_FILE },   { "symlink",  SYSCAT_FILE },
		{ "rename",   SYSCAT_FILE },   { "mkdir",    SYSCAT_FILE },
		{ "rmdir",    SYSCAT_FILE },   { "close",    SYSCAT_FILE },
		{ "dup",      SYSCAT_FILE },   { "fcntl",    SYSCAT_FILE },
		{ "ioctl",    SYSCAT_FILE },   { "lseek",    SYSCAT_FILE },
		{ "truncate", SYSCAT_FILE },   { "ftruncate",SYSCAT_FILE },
		{ "fsync",    SYSCAT_FILE },   { "fdatasync",SYSCAT_FILE },
		{ "sync",     SYSCAT_FILE },
	};
	unsigned int i;

	if (name == NULL)
		return SYSCAT_OTHER;
	for (i = 0; i < ARRAY_SIZE(tab); i++)
		if (strncmp(name, tab[i].p, strlen(tab[i].p)) == 0)
			return tab[i].cat;
	return SYSCAT_OTHER;
}

static void dump_syscall_category_histogram(void)
{
	static const char * const cat_names[NR_SYSCAT] = {
		"read", "write", "open", "mmap", "socket",
		"process", "file", "ipc", "other",
	};
	unsigned long total = 0;
	unsigned int i;

	for (i = 0; i < NR_SYSCAT; i++)
		total += parent_stats.syscall_category_count[i];
	if (total == 0)
		return;

	output(0, "Syscall category histogram (total: %lu):\n", total);
	for (i = 0; i < NR_SYSCAT; i++) {
		unsigned long c = parent_stats.syscall_category_count[i];
		unsigned long pct10 = total ? (c * 1000UL / total) : 0UL;

		output(0, "  %-8s %10lu  (%lu.%lu%%)\n",
		       cat_names[i], c, pct10 / 10, pct10 % 10);
	}
}

static void dump_entry(const struct syscalltable *table, unsigned int i)
{
	struct syscallentry *entry;
	unsigned int j;

	entry = table[i].entry;
	if (entry == NULL)
		return;

	if (entry->attempted == 0)
		return;

	output(0, "%s: (attempted:%u. success:%u. failures:%u.\n", entry->name, entry->attempted, entry->successes, entry->failures);

	for (j = 0; j <= NR_ERRNOS; j++) {
		if (entry->errnos[j] != 0) {
			output(0, "    %s: %d\n", strerror(j), entry->errnos[j]);
		}
	}
}

/* Insertion-sort push for a top-N table held as parallel arrays
 * (vals[], nrs[], descending by value, capped at cap).  Shared by the
 * kcov dump paths that track leading edge-producing, recent-growth, and
 * CMP-insert syscalls. */
void topn_push(unsigned long *vals, unsigned int *nrs,
		      unsigned int *count, unsigned int cap,
		      unsigned long value, unsigned int nr)
{
	unsigned int j;

	for (j = *count; j > 0 && value > vals[j - 1]; j--) {
		if (j < cap) {
			vals[j] = vals[j - 1];
			nrs[j] = nrs[j - 1];
		}
	}
	if (j < cap) {
		vals[j] = value;
		nrs[j] = nr;
		if (*count < cap)
			(*count)++;
	}
}


/*
 * Descriptor-table form for stat categories whose JSON / text emit shape
 * is "object name + N (field, value) scalar pairs".  Each category lists
 * its fields once; the JSON walker and the text walker iterate the same
 * descriptor so a new counter is added by declaring the struct member and
 * appending one STAT_FIELD() row -- the JSON key is derived from the
 * field-name suffix so the schema cannot drift from the struct.
 *
 * Generalises the in-tree pattern already used by defense_counters[] for
 * the periodic-window dump; here it replaces correlated edits in
 * struct stats_s + dump_stats_json() + dump_stats() with a single edit
 * site per counter.
 */
unsigned long stat_field_load(const struct stat_field *f)
{
	unsigned long *p = (unsigned long *)((char *)&shm->stats + f->offset);
	return __atomic_load_n(p, __ATOMIC_RELAXED);
}

unsigned long stat_gate_load(const struct stat_category *cat)
{
	unsigned long *p = (unsigned long *)((char *)&shm->stats + cat->gate_offset);
	return __atomic_load_n(p, __ATOMIC_RELAXED);
}


/*
 * Emit one category as text rows.  Mirrors the existing
 * "if (shm->stats.<gate>) { stat_row(...); ... }" idiom: when the gate
 * counter is zero the whole block is suppressed so quiet runs stay terse.
 */
void stat_category_emit_text(const struct stat_category *cat)
{
	size_t i;

	if (stat_gate_load(cat) == 0)
		return;
	for (i = 0; i < cat->n_fields; i++)
		stat_row(cat->name, cat->fields[i].name,
		         stat_field_load(&cat->fields[i]));
}

/* --blob-mutator (default off): A/B observability for the ARG_BUF_SIZED
 * content-authoring lane.  fills is the gate (total invocations that
 * authored content), havoc_ops is the count of bounded byte-mutation
 * ops applied on top of the FILL floor, dict_inserts is the count of
 * committed cmp-pool splats the CMPDICT rung applied from the learned
 * per-nr cmp_hints pool (one bump per successful cmp_hints_try_get
 * pull + splat; pool misses are silent), static_magic_inserts is the
 * count of committed splats the CMPDICT rung applied from the built-
 * in well-known-magic table (ext4 / XFS / BTRFS / squashfs / ELF /
 * gzip) -- the ratio to dict_inserts is the observable static-vs-
 * learned A/B split.  dict_transform_inserts is the count of
 * committed splats (across both sources) that applied a non-plain
 * splat form -- big-endian byte-swap or value ± 1 at width -- for
 * endian and off-by-one boundary coverage; the ratio to
 * (dict_inserts + static_magic_inserts) is the transform-vs-plain
 * split.  All five are bumped only by CMPDICT, so the per-rung
 * contribution is isolated across an off / fill / havoc / cmpdict
 * A/B.  When the mode is OFF the gate counter stays at zero so
 * stat_category_emit_text suppresses the whole block (render-gap-
 * aware). */
static const struct stat_field blob_mutator_fields[] = {
	STAT_FIELD(blob, fills),
	STAT_FIELD(blob, havoc_ops),
	STAT_FIELD(blob, dict_inserts),
	STAT_FIELD(blob, static_magic_inserts),
	STAT_FIELD(blob, dict_transform_inserts),
};

const struct stat_category blob_mutator_category =
	STAT_CATEGORY("blob_mutator",
	              blob_fills,
	              blob_mutator_fields);

static const struct stat_field msg_zerocopy_churn_fields[] = {
	STAT_FIELD(msg_zerocopy_churn, runs),
	STAT_FIELD(msg_zerocopy_churn, setup_failed),
	STAT_FIELD(msg_zerocopy_churn, sends_ok),
	STAT_FIELD(msg_zerocopy_churn, sends_efault),
	STAT_FIELD(msg_zerocopy_churn, sends_eagain),
	STAT_FIELD(msg_zerocopy_churn, errqueue_drained),
	STAT_FIELD(msg_zerocopy_churn, errqueue_empty),
	STAT_FIELD(msg_zerocopy_churn, munmap_ok),
	STAT_FIELD(msg_zerocopy_churn, send_after_munmap_caught),
	STAT_FIELD(msg_zerocopy_churn, sndzc_disable_ok),
};

const struct stat_category msg_zerocopy_churn_category =
	STAT_CATEGORY("msg_zerocopy_churn",
	              msg_zerocopy_churn_runs,
	              msg_zerocopy_churn_fields);

static const struct stat_field tcp_ulp_swap_churn_fields[] = {
	STAT_FIELD(tcp_ulp_swap_churn, runs),
	STAT_FIELD(tcp_ulp_swap_churn, setup_failed),
	STAT_FIELD(tcp_ulp_swap_churn, install_tls_ok),
	STAT_FIELD(tcp_ulp_swap_churn, tx_install_ok),
	STAT_FIELD(tcp_ulp_swap_churn, send_ok),
	STAT_FIELD(tcp_ulp_swap_churn, swap_rejected_ok),
	STAT_FIELD(tcp_ulp_swap_churn, ifname_probe_ok),
	STAT_FIELD(tcp_ulp_swap_churn, uninstall_ok),
	STAT_FIELD(tcp_ulp_swap_churn, reinstall_ok),
	STAT_FIELD(tcp_ulp_swap_churn, install_failed),
};

const struct stat_category tcp_ulp_swap_churn_category =
	STAT_CATEGORY("tcp_ulp_swap_churn",
	              tcp_ulp_swap_churn_runs,
	              tcp_ulp_swap_churn_fields);

static const struct stat_field tls_rotate_fields[] = {
	STAT_FIELD(tls_rotate, runs),
	STAT_FIELD(tls_rotate, setup_failed),
	STAT_FIELD(tls_rotate, ulp_failed),
	STAT_FIELD(tls_rotate, ulp_asymmetric),
	STAT_FIELD(tls_rotate, installs),
	STAT_FIELD(tls_rotate, rekeys_ok),
	STAT_FIELD(tls_rotate, rekeys_rejected),
};

const struct stat_category tls_rotate_category =
	STAT_CATEGORY("tls_rotate",
	              tls_rotate_runs,
	              tls_rotate_fields);

static const struct stat_field netns_teardown_fields[] = {
	STAT_FIELD(netns_teardown, runs),
	STAT_FIELD(netns_teardown, setup_failed),
	STAT_FIELD(netns_teardown, unshare_ok),
	STAT_FIELD(netns_teardown, socket_pair_ok),
	STAT_FIELD(netns_teardown, fork_ok),
	STAT_FIELD(netns_teardown, setns_ok),
	STAT_FIELD(netns_teardown, kill_ok),
	STAT_FIELD(netns_teardown, completed_ok),
};

const struct stat_category netns_teardown_category =
	STAT_CATEGORY("netns_teardown",
	              netns_teardown_runs,
	              netns_teardown_fields);

static const struct stat_field setsockopt_pairing_fields[] = {
	STAT_FIELD(setsockopt_pairing, paired_emitted),
};

const struct stat_category setsockopt_pairing_category =
	STAT_CATEGORY("setsockopt_pairing",
	              setsockopt_pairing_paired_emitted,
	              setsockopt_pairing_fields);

static const struct stat_field sched_cycler_fields[] = {
	STAT_FIELD(sched_cycler, runs),
	STAT_FIELD(sched_cycler, eperm),
};

const struct stat_category sched_cycler_category =
	STAT_CATEGORY("sched_cycler",
	              sched_cycler_runs,
	              sched_cycler_fields);

static const struct stat_field userns_fuzzer_fields[] = {
	STAT_FIELD(userns, runs),
	STAT_FIELD(userns, inner_crashed),
	STAT_FIELD(userns, unsupported),
};

const struct stat_category userns_fuzzer_category =
	STAT_CATEGORY("userns_fuzzer",
	              userns_runs,
	              userns_fuzzer_fields);

static const struct stat_field userns_bootstrap_fields[] = {
	STAT_FIELD(userns_bootstrap, runs),
	STAT_FIELD(userns_bootstrap, ran),
	STAT_FIELD(userns_bootstrap, eperm),
	STAT_FIELD(userns_bootstrap, userns_other),
	STAT_FIELD(userns_bootstrap, map_write_fail),
	STAT_FIELD(userns_bootstrap, map_write_fail_eperm),
	STAT_FIELD(userns_bootstrap, map_write_fail_einval),
	STAT_FIELD(userns_bootstrap, map_write_fail_other),
	STAT_FIELD(userns_bootstrap, target_unshare),
	STAT_FIELD(userns_bootstrap, fork_fail),
	STAT_FIELD(userns_bootstrap, signalled),
};

const struct stat_category userns_bootstrap_category =
	STAT_CATEGORY("userns_bootstrap",
	              userns_bootstrap_runs,
	              userns_bootstrap_fields);

static const struct stat_field barrier_racer_fields[] = {
	STAT_FIELD(barrier_racer, runs),
	STAT_FIELD(barrier_racer, inner_crashed),
};

const struct stat_category barrier_racer_category =
	STAT_CATEGORY("barrier_racer",
	              barrier_racer_runs,
	              barrier_racer_fields);

static const struct stat_field perf_event_chains_fields[] = {
	STAT_FIELD(perf_chains, runs),
	STAT_FIELD(perf_chains, groups_created),
	STAT_FIELD(perf_chains, ioctl_ops),
};

const struct stat_category perf_event_chains_category =
	STAT_CATEGORY("perf_event_chains",
	              perf_chains_runs,
	              perf_event_chains_fields);

static const struct stat_field bpf_lifecycle_fields[] = {
	STAT_FIELD(bpf_lifecycle, runs),
	STAT_FIELD(bpf_lifecycle, progs_loaded),
	STAT_FIELD(bpf_lifecycle, attached),
	STAT_FIELD(bpf_lifecycle, triggered),
	STAT_FIELD(bpf_lifecycle, verifier_rejects),
	STAT_FIELD(bpf_lifecycle, attach_failed),
	STAT_FIELD(bpf_lifecycle, eperm),
};

const struct stat_category bpf_lifecycle_category =
	STAT_CATEGORY("bpf_lifecycle",
	              bpf_lifecycle_runs,
	              bpf_lifecycle_fields);

static const struct stat_field signal_storm_fields[] = {
	STAT_FIELD(signal_storm, runs),
	STAT_FIELD(signal_storm, kill),
	STAT_FIELD(signal_storm, probe),
	STAT_FIELD(signal_storm, sigqueue),
	STAT_FIELD(signal_storm, no_targets),
};

const struct stat_category signal_storm_category =
	STAT_CATEGORY("signal_storm",
	              signal_storm_runs,
	              signal_storm_fields);

static const struct stat_field socket_family_chain_fields[] = {
	STAT_FIELD(socket_family_chain, runs),
	STAT_FIELD(socket_family_chain, completed),
	STAT_FIELD(socket_family_chain, failed),
	STAT_FIELD(socket_family_chain, authencesn_attempts),
	STAT_FIELD(socket_family_chain, splice_attempts),
};

const struct stat_category socket_family_chain_category =
	STAT_CATEGORY("socket_family_chain",
	              socket_family_chain_runs,
	              socket_family_chain_fields);

static const struct stat_field socket_family_grammar_fields[] = {
	STAT_FIELD(socket_family_grammar, runs),
	STAT_FIELD(socket_family_grammar, completed),
};

const struct stat_category socket_family_grammar_category =
	STAT_CATEGORY("socket_family_grammar",
	              socket_family_grammar_runs,
	              socket_family_grammar_fields);

static const struct stat_field tcp_ao_rotate_fields[] = {
	STAT_FIELD(tcp_ao_rotate, runs),
	STAT_FIELD(tcp_ao_rotate, setup_failed),
	STAT_FIELD(tcp_ao_rotate, addkey_rejected),
	STAT_FIELD(tcp_ao_rotate, keys_added),
	STAT_FIELD(tcp_ao_rotate, connect_failed),
	STAT_FIELD(tcp_ao_rotate, connected),
	STAT_FIELD(tcp_ao_rotate, packets_sent),
	STAT_FIELD(tcp_ao_rotate, key_rotations),
	STAT_FIELD(tcp_ao_rotate, info_rejected),
	STAT_FIELD(tcp_ao_rotate, key_dels),
	STAT_FIELD(tcp_ao_rotate, delkey_rejected),
	STAT_FIELD(tcp_ao_rotate, cycles),
};

const struct stat_category tcp_ao_rotate_category =
	STAT_CATEGORY("tcp_ao_rotate",
	              tcp_ao_rotate_runs,
	              tcp_ao_rotate_fields);

static const struct stat_field tcp_md5_listener_race_fields[] = {
	STAT_FIELD(tcp_md5_listener_race, runs),
	STAT_FIELD(tcp_md5_listener_race, setup_failed),
	STAT_FIELD(tcp_md5_listener_race, md5_set_ok),
	STAT_FIELD(tcp_md5_listener_race, md5_set_failed),
	STAT_FIELD(tcp_md5_listener_race, connect_ok),
	STAT_FIELD(tcp_md5_listener_race, rst_sent_ok),
	STAT_FIELD(tcp_md5_listener_race, completed_ok),
};

const struct stat_category tcp_md5_listener_race_category =
	STAT_CATEGORY("tcp_md5_listener_race",
	              tcp_md5_listener_race_runs,
	              tcp_md5_listener_race_fields);

static const struct stat_field ipv6_pmtu_race_fields[] = {
	STAT_FIELD(ipv6_pmtu_race, runs),
	STAT_FIELD(ipv6_pmtu_race, setup_failed),
	STAT_FIELD(ipv6_pmtu_race, ptb_sent_ok),
	STAT_FIELD(ipv6_pmtu_race, dellink_ok),
	STAT_FIELD(ipv6_pmtu_race, completed_ok),
};

const struct stat_category ipv6_pmtu_race_category =
	STAT_CATEGORY("ipv6_pmtu_race",
	              ipv6_pmtu_race_runs,
	              ipv6_pmtu_race_fields);

static const struct stat_field vrf_fib_churn_fields[] = {
	STAT_FIELD(vrf_fib_churn, runs),
	STAT_FIELD(vrf_fib_churn, setup_failed),
	STAT_FIELD(vrf_fib_churn, link_ok),
	STAT_FIELD(vrf_fib_churn, addr_ok),
	STAT_FIELD(vrf_fib_churn, up_ok),
	STAT_FIELD(vrf_fib_churn, rule_added),
	STAT_FIELD(vrf_fib_churn, bound),
	STAT_FIELD(vrf_fib_churn, sendto_ok),
	STAT_FIELD(vrf_fib_churn, rule2_added),
	STAT_FIELD(vrf_fib_churn, rule_removed),
	STAT_FIELD(vrf_fib_churn, link_removed),
};

const struct stat_category vrf_fib_churn_category =
	STAT_CATEGORY("vrf_fib_churn",
	              vrf_fib_churn_runs,
	              vrf_fib_churn_fields);

static const struct stat_field mpls_route_churn_fields[] = {
	STAT_FIELD(mpls_route_churn, runs),
	STAT_FIELD(mpls_route_churn, label_install_ok),
	STAT_FIELD(mpls_route_churn, iptunnel_install_ok),
	STAT_FIELD(mpls_route_churn, delete_ok),
	STAT_FIELD(mpls_route_churn, ns_unsupported),
};

const struct stat_category mpls_route_churn_category =
	STAT_CATEGORY("mpls_route_churn",
	              mpls_route_churn_runs,
	              mpls_route_churn_fields);

static const struct stat_field tls_ulp_churn_fields[] = {
	STAT_FIELD(tls_ulp_churn, runs),
	STAT_FIELD(tls_ulp_churn, setup_failed),
	STAT_FIELD(tls_ulp_churn, ulp_install_ok),
	STAT_FIELD(tls_ulp_churn, tx_install_ok),
	STAT_FIELD(tls_ulp_churn, send_ok),
	STAT_FIELD(tls_ulp_churn, splice_ok),
	STAT_FIELD(tls_ulp_churn, rekey_ok),
	STAT_FIELD(tls_ulp_churn, recv_ok),
};

const struct stat_category tls_ulp_churn_category =
	STAT_CATEGORY("tls_ulp_churn",
	              tls_ulp_churn_runs,
	              tls_ulp_churn_fields);

static const struct stat_field ip6gre_bond_lapb_stack_fields[] = {
	STAT_FIELD(ip6gre_lapb, runs),
	STAT_FIELD(ip6gre_lapb, setup_failed),
	STAT_FIELD(ip6gre_lapb, flag_toggles),
};

const struct stat_category ip6gre_bond_lapb_stack_category =
	STAT_CATEGORY("ip6gre_bond_lapb_stack",
	              ip6gre_lapb_runs,
	              ip6gre_bond_lapb_stack_fields);

static const struct stat_field vxlan_encap_churn_fields[] = {
	STAT_FIELD(vxlan_encap_churn, runs),
	STAT_FIELD(vxlan_encap_churn, setup_failed),
	STAT_FIELD(vxlan_encap_churn, link_create_ok),
	STAT_FIELD(vxlan_encap_churn, fdb_add_ok),
	STAT_FIELD(vxlan_encap_churn, link_up_ok),
	STAT_FIELD(vxlan_encap_churn, packet_sent_ok),
	STAT_FIELD(vxlan_encap_churn, link_del_ok),
};

const struct stat_category vxlan_encap_churn_category =
	STAT_CATEGORY("vxlan_encap_churn",
	              vxlan_encap_churn_runs,
	              vxlan_encap_churn_fields);

static const struct stat_field ovs_tunnel_vport_churn_fields[] = {
	STAT_FIELD(ovs_tunnel_vport_churn, runs),
	STAT_FIELD(ovs_tunnel_vport_churn, setup_failed),
	STAT_FIELD(ovs_tunnel_vport_churn, create_ok),
	STAT_FIELD(ovs_tunnel_vport_churn, delete_ok),
	STAT_FIELD(ovs_tunnel_vport_churn, race_dellink_attempted),
};

const struct stat_category ovs_tunnel_vport_churn_category =
	STAT_CATEGORY("ovs_tunnel_vport_churn",
	              ovs_tunnel_vport_churn_runs,
	              ovs_tunnel_vport_churn_fields);

static const struct stat_field netlink_monitor_race_fields[] = {
	STAT_FIELD(netlink_monitor_race, runs),
	STAT_FIELD(netlink_monitor_race, setup_failed),
	STAT_FIELD(netlink_monitor_race, mon_open),
	STAT_FIELD(netlink_monitor_race, mut_open),
	STAT_FIELD(netlink_monitor_race, mut_op_ok),
	STAT_FIELD(netlink_monitor_race, recv_drained),
	STAT_FIELD(netlink_monitor_race, group_drop),
	STAT_FIELD(netlink_monitor_race, group_add),
};

const struct stat_category netlink_monitor_race_category =
	STAT_CATEGORY("netlink_monitor_race",
	              netlink_monitor_race_runs,
	              netlink_monitor_race_fields);

static const struct stat_field tipc_link_churn_fields[] = {
	STAT_FIELD(tipc_link_churn, runs),
	STAT_FIELD(tipc_link_churn, setup_failed),
	STAT_FIELD(tipc_link_churn, bearer_enable_ok),
	STAT_FIELD(tipc_link_churn, sock_rdm_ok),
	STAT_FIELD(tipc_link_churn, topsrv_connect_ok),
	STAT_FIELD(tipc_link_churn, sub_ports_sent),
	STAT_FIELD(tipc_link_churn, publish_ok),
	STAT_FIELD(tipc_link_churn, bearer_disable_ok),
};

const struct stat_category tipc_link_churn_category =
	STAT_CATEGORY("tipc_link_churn",
	              tipc_link_churn_runs,
	              tipc_link_churn_fields);

static const struct stat_field igmp_mld_source_churn_fields[] = {
	STAT_FIELD(igmp_mld_source_churn, runs),
	STAT_FIELD(igmp_mld_source_churn, setup_failed),
	STAT_FIELD(igmp_mld_source_churn, join_ok),
	STAT_FIELD(igmp_mld_source_churn, leave_ok),
	STAT_FIELD(igmp_mld_source_churn, block_ok),
	STAT_FIELD(igmp_mld_source_churn, msfilter_ok),
	STAT_FIELD(igmp_mld_source_churn, drop_ok),
	STAT_FIELD(igmp_mld_source_churn, send_ok),
};

const struct stat_category igmp_mld_source_churn_category =
	STAT_CATEGORY("igmp_mld_source_churn",
	              igmp_mld_source_churn_runs,
	              igmp_mld_source_churn_fields);

static const struct stat_field bridge_vlan_churn_fields[] = {
	STAT_FIELD(bridge_vlan_churn, runs),
	STAT_FIELD(bridge_vlan_churn, setup_failed),
	STAT_FIELD(bridge_vlan_churn, bridge_create_ok),
	STAT_FIELD(bridge_vlan_churn, veth_create_ok),
	STAT_FIELD(bridge_vlan_churn, vlan_add_ok),
	STAT_FIELD(bridge_vlan_churn, vlan_del_ok),
	STAT_FIELD(bridge_vlan_churn, tunnel_add_ok),
	STAT_FIELD(bridge_vlan_churn, mst_set_ok),
	STAT_FIELD(bridge_vlan_churn, raw_send_ok),
};

const struct stat_category bridge_vlan_churn_category =
	STAT_CATEGORY("bridge_vlan_churn",
	              bridge_vlan_churn_runs,
	              bridge_vlan_churn_fields);

static const struct stat_field iscsi_target_probe_fields[] = {
	STAT_FIELD(iscsi_target_probe, runs),
	STAT_FIELD(iscsi_target_probe, setup_failed),
	STAT_FIELD(iscsi_target_probe, no_target),
	STAT_FIELD(iscsi_target_probe, connected),
	STAT_FIELD(iscsi_target_probe, login_sent),
	STAT_FIELD(iscsi_target_probe, login_replies),
	STAT_FIELD(iscsi_target_probe, scsi_cmd_sent),
	STAT_FIELD(iscsi_target_probe, bytes_out),
	STAT_FIELD(iscsi_target_probe, bytes_in),
	STAT_FIELD(iscsi_target_probe, length_decoupled),
};

const struct stat_category iscsi_target_probe_category =
	STAT_CATEGORY("iscsi_target_probe",
	              iscsi_target_probe_runs,
	              iscsi_target_probe_fields);

static const struct stat_field iscsi_login_walker_fields[] = {
	STAT_FIELD(iscsi_walker, runs),
	STAT_FIELD(iscsi_walker, setup_failed),
	STAT_FIELD(iscsi_walker, no_target),
	STAT_FIELD(iscsi_walker, connected),
	STAT_FIELD(iscsi_walker, state_init_sent),
	STAT_FIELD(iscsi_walker, state_security_sent),
	STAT_FIELD(iscsi_walker, state_op_neg_sent),
	STAT_FIELD(iscsi_walker, ffp_iters),
	STAT_FIELD(iscsi_walker, ffp_pdus),
	STAT_FIELD(iscsi_walker, chaos_runs),
	STAT_FIELD(iscsi_walker, chaos_pdus),
	STAT_FIELD(iscsi_walker, bytes_out),
	STAT_FIELD(iscsi_walker, bytes_in),
};

const struct stat_category iscsi_login_walker_category =
	STAT_CATEGORY("iscsi_login_walker",
	              iscsi_walker_runs,
	              iscsi_login_walker_fields);

static const struct stat_field ipv6_ndisc_proxy_fields[] = {
	STAT_FIELD(ipv6_ndisc_proxy, runs),
	STAT_FIELD(ipv6_ndisc_proxy, ns_sent_ok),
	STAT_FIELD(ipv6_ndisc_proxy, setup_failed),
	STAT_FIELD(ipv6_ndisc_proxy, proxy_enable_ok),
};

const struct stat_category ipv6_ndisc_proxy_category =
	STAT_CATEGORY("ipv6_ndisc_proxy",
	              ipv6_ndisc_proxy_runs,
	              ipv6_ndisc_proxy_fields);

static const struct stat_field rxrpc_key_install_fields[] = {
	STAT_FIELD(rxrpc_key_install, runs),
	STAT_FIELD(rxrpc_key_install, calls),
	STAT_FIELD(rxrpc_key_install, revokes),
	STAT_FIELD(rxrpc_key_install, quota_hits),
	STAT_FIELD(rxrpc_key_install, unsupported),
	STAT_FIELD(rxrpc_key_install, xrxgk_accepted),
};

const struct stat_category rxrpc_key_install_category =
	STAT_CATEGORY("rxrpc_key_install",
	              rxrpc_key_install_runs,
	              rxrpc_key_install_fields);

static const struct stat_field af_alg_weak_cipher_probe_fields[] = {
	STAT_FIELD(af_alg_weak_cipher_probe, runs),
	STAT_FIELD(af_alg_weak_cipher_probe, socket_failed),
	STAT_FIELD(af_alg_weak_cipher_probe, total_bind_attempts),
	STAT_FIELD(af_alg_weak_cipher_probe, total_bind_accepted),
	STAT_FIELD(af_alg_weak_cipher_probe, weak_accepted_total),
	STAT_FIELD(af_alg_weak_cipher_probe, setkey_accepted_total),
	STAT_FIELD(af_alg_weak_cipher_probe, skcipher_weak_accepted),
	STAT_FIELD(af_alg_weak_cipher_probe, aead_weak_accepted),
	STAT_FIELD(af_alg_weak_cipher_probe, hash_weak_accepted),
	STAT_FIELD(af_alg_weak_cipher_probe, strong_rejected),
};

const struct stat_category af_alg_weak_cipher_probe_category =
	STAT_CATEGORY("af_alg_weak_cipher_probe",
	              af_alg_weak_cipher_probe_runs,
	              af_alg_weak_cipher_probe_fields);

static const struct stat_field bridge_conntrack_churn_fields[] = {
	STAT_FIELD(bridge_ct, runs),
	STAT_FIELD(bridge_ct, flushes),
	STAT_FIELD(bridge_ct, pkts_sent),
};

const struct stat_category bridge_conntrack_churn_category =
	STAT_CATEGORY("bridge_conntrack_churn",
	              bridge_ct_runs,
	              bridge_conntrack_churn_fields);

static const struct stat_field blkdev_lifecycle_race_fields[] = {
	STAT_FIELD(blkdev_lifecycle, runs),
	STAT_FIELD(blkdev_lifecycle, setup_failed),
	STAT_FIELD(blkdev_lifecycle, set_fd_ok),
	STAT_FIELD(blkdev_lifecycle, clr_fd),
	STAT_FIELD(blkdev_lifecycle, ebusy),
	STAT_FIELD(blkdev_lifecycle, rescans),
};

const struct stat_category blkdev_lifecycle_race_category =
	STAT_CATEGORY("blkdev_lifecycle_race",
	              blkdev_lifecycle_runs,
	              blkdev_lifecycle_race_fields);

static const struct stat_field veth_asymmetric_xdp_fields[] = {
	STAT_FIELD(veth_asym, iters),
	STAT_FIELD(veth_asym, eperm),
	STAT_FIELD(veth_asym, unsupported),
	STAT_FIELD(veth_asym, pair_ok),
	STAT_FIELD(veth_asym, xdp_attach_ok),
	STAT_FIELD(veth_asym, send_ok),
};

const struct stat_category veth_asymmetric_xdp_category =
	STAT_CATEGORY("veth_asymmetric_xdp",
	              veth_asym_iters,
	              veth_asymmetric_xdp_fields);

static const struct stat_field ip6erspan_netns_migrate_fields[] = {
	STAT_FIELD(inm, iters),
	STAT_FIELD(inm, eperm),
	STAT_FIELD(inm, unsupported),
	STAT_FIELD(inm, link_create_ok),
	STAT_FIELD(inm, netns_migrate_ok),
	STAT_FIELD(inm, changelink_ok),
};

const struct stat_category ip6erspan_netns_migrate_category =
	STAT_CATEGORY("ip6erspan_netns_migrate",
	              inm_iters,
	              ip6erspan_netns_migrate_fields);

static const struct stat_field flowtable_encap_vlan_fields[] = {
	STAT_FIELD(flowtable_vlan, runs),
	STAT_FIELD(flowtable_vlan, setup_ok),
	STAT_FIELD(flowtable_vlan, setup_failed),
	STAT_FIELD(flowtable_vlan, offloaded_pkts),
	STAT_FIELD(flowtable_vlan, gso_sends),
	STAT_FIELD(flowtable_vlan, vlan_teardown_races),
	STAT_FIELD(flowtable_vlan, unsupported_latched),
};

const struct stat_category flowtable_encap_vlan_category =
	STAT_CATEGORY("flowtable_encap_vlan",
	              flowtable_vlan_runs,
	              flowtable_encap_vlan_fields);

static const struct stat_field splice_protocols_fields[] = {
	STAT_FIELD(splice_protocols, runs),
	STAT_FIELD(splice_protocols, setup_failed),
	STAT_FIELD(splice_protocols, chain_ok),
	STAT_FIELD(splice_protocols, in_bytes),
	STAT_FIELD(splice_protocols, out_bytes),
	STAT_FIELD(splice_protocols, udp_encap_attempted),
	STAT_FIELD(splice_protocols, tcp_repair_attempted),
	STAT_FIELD(splice_protocols, packet_ring_attempted),
	STAT_FIELD(splice_protocols, alg_attempted),
	STAT_FIELD(splice_protocols, rxrpc_attempted),
	STAT_FIELD(splice_protocols, msg_splice_pages_attempted),
	STAT_FIELD(splice_protocols, msg_splice_pages_path_taken_inferred),
};

const struct stat_category splice_protocols_category =
	STAT_CATEGORY("splice_protocols",
	              splice_protocols_runs,
	              splice_protocols_fields);

static const struct stat_field wireguard_decrypt_flood_fields[] = {
	STAT_FIELD(wgdf, runs),
	STAT_FIELD(wgdf, setup_failed),
	STAT_FIELD(wgdf, packets_sent),
	STAT_FIELD(wgdf, unsupported_latched),
};

const struct stat_category wireguard_decrypt_flood_category =
	STAT_CATEGORY("wireguard_decrypt_flood",
	              wgdf_runs,
	              wireguard_decrypt_flood_fields);

static const struct stat_field rtnl_vf_broadcast_getlink_fields[] = {
	STAT_FIELD(rtnl_vf_broadcast, runs),
	STAT_FIELD(rtnl_vf_broadcast, setup_ok),
	STAT_FIELD(rtnl_vf_broadcast, setup_failed),
	STAT_FIELD(rtnl_vf_broadcast, getlink_ok),
};

const struct stat_category rtnl_vf_broadcast_getlink_category =
	STAT_CATEGORY("rtnl_vf_broadcast_getlink",
	              rtnl_vf_broadcast_runs,
	              rtnl_vf_broadcast_getlink_fields);

static const struct stat_field pci_bind_fields[] = {
	STAT_FIELD(pci_bind, runs),
	STAT_FIELD(pci_bind, drivers_available),
	STAT_FIELD(pci_bind, no_devices),
	STAT_FIELD(pci_bind, unbind_ok),
	STAT_FIELD(pci_bind, unbind_enodev),
	STAT_FIELD(pci_bind, unbind_failed),
	STAT_FIELD(pci_bind, bind_ok),
	STAT_FIELD(pci_bind, bind_enodev),
	STAT_FIELD(pci_bind, bind_failed),
};

const struct stat_category pci_bind_category =
	STAT_CATEGORY("pci_bind",
	              pci_bind_runs,
	              pci_bind_fields);

static const struct stat_field ublk_lifecycle_fields[] = {
	STAT_FIELD(ublk_lifecycle, iters),
	STAT_FIELD(ublk_lifecycle, eperm),
	STAT_FIELD(ublk_lifecycle, add_ok),
	STAT_FIELD(ublk_lifecycle, fetch_ok),
	STAT_FIELD(ublk_lifecycle, del_ok),
	STAT_FIELD(ublk_lifecycle, race_observed),
};

const struct stat_category ublk_lifecycle_category =
	STAT_CATEGORY("ublk_lifecycle",
	              ublk_lifecycle_iters,
	              ublk_lifecycle_fields);

static const struct stat_field handshake_req_abort_fields[] = {
	STAT_FIELD(handshake_req_abort, runs),
	STAT_FIELD(handshake_req_abort, setup_failed),
	STAT_FIELD(handshake_req_abort, accept_ok),
	STAT_FIELD(handshake_req_abort, done_ok),
	STAT_FIELD(handshake_req_abort, abort_ok),
	STAT_FIELD(handshake_req_abort, orphan_close),
};

const struct stat_category handshake_req_abort_category =
	STAT_CATEGORY("handshake_req_abort",
	              handshake_req_abort_runs,
	              handshake_req_abort_fields);

static const struct stat_field nf_conntrack_helper_churn_fields[] = {
	STAT_FIELD(nf_conntrack_helper_churn, runs),
	STAT_FIELD(nf_conntrack_helper_churn, setup_failed),
	STAT_FIELD(nf_conntrack_helper_churn, no_helper),
	STAT_FIELD(nf_conntrack_helper_churn, attach_ok),
	STAT_FIELD(nf_conntrack_helper_churn, attach_fail),
	STAT_FIELD(nf_conntrack_helper_churn, exp_ok),
	STAT_FIELD(nf_conntrack_helper_churn, packet_sent),
	STAT_FIELD(nf_conntrack_helper_churn, delete_ok),
	STAT_FIELD(nf_conntrack_helper_churn, zone_swap),
	STAT_FIELD(nf_conntrack_helper_churn, detach_ok),
};

const struct stat_category nf_conntrack_helper_churn_category =
	STAT_CATEGORY("nf_conntrack_helper_churn",
	              nf_conntrack_helper_churn_runs,
	              nf_conntrack_helper_churn_fields);

static const struct stat_field af_unix_scm_rights_gc_fields[] = {
	STAT_FIELD(af_unix_scm_rights_gc, runs),
	STAT_FIELD(af_unix_scm_rights_gc, setup_failed),
	STAT_FIELD(af_unix_scm_rights_gc, cycle_built_ok),
	STAT_FIELD(af_unix_scm_rights_gc, close_ok),
	STAT_FIELD(af_unix_scm_rights_gc, trigger_ok),
	STAT_FIELD(af_unix_scm_rights_gc, recv_ok),
	STAT_FIELD(af_unix_scm_rights_gc, peek_ok),
	STAT_FIELD(af_unix_scm_rights_gc, iouring_variant_ok),
	STAT_FIELD(af_unix_scm_rights_gc, sibling_spawn_ok),
	STAT_FIELD(af_unix_scm_rights_gc, sibling_spawn_failed),
	STAT_FIELD(af_unix_scm_rights_gc, sibling_reaped_ok),
	STAT_FIELD(af_unix_scm_rights_gc, sibling_crashed),
};

const struct stat_category af_unix_scm_rights_gc_category =
	STAT_CATEGORY("af_unix_scm_rights_gc",
	              af_unix_scm_rights_gc_runs,
	              af_unix_scm_rights_gc_fields);

static const struct stat_field af_unix_peek_race_fields[] = {
	STAT_FIELD(af_unix_peek_race, runs),
	STAT_FIELD(af_unix_peek_race, setup_failed),
	STAT_FIELD(af_unix_peek_race, pair_open_ok),
	STAT_FIELD(af_unix_peek_race, peek_off_armed),
	STAT_FIELD(af_unix_peek_race, peek_off_rejected),
	STAT_FIELD(af_unix_peek_race, send_ok),
	STAT_FIELD(af_unix_peek_race, shutdown_ok),
	STAT_FIELD(af_unix_peek_race, pair_rebuilds),
	STAT_FIELD(af_unix_peek_race, sibling_spawn_ok),
	STAT_FIELD(af_unix_peek_race, sibling_spawn_failed),
	STAT_FIELD(af_unix_peek_race, sibling_reaped_ok),
	STAT_FIELD(af_unix_peek_race, sibling_crashed),
};

const struct stat_category af_unix_peek_race_category =
	STAT_CATEGORY("af_unix_peek_race",
		af_unix_peek_race_runs,
		af_unix_peek_race_fields);

static const struct stat_field sysv_shm_orphan_race_fields[] = {
	STAT_FIELD(sysv_shm_orphan_race, runs),
	STAT_FIELD(sysv_shm_orphan_race, setup_failed),
	STAT_FIELD(sysv_shm_orphan_race, shmget_ok),
	STAT_FIELD(sysv_shm_orphan_race, shmget_failed),
	STAT_FIELD(sysv_shm_orphan_race, attach_ok),
	STAT_FIELD(sysv_shm_orphan_race, attach_failed),
	STAT_FIELD(sysv_shm_orphan_race, rmid_ok),
	STAT_FIELD(sysv_shm_orphan_race, rmid_failed),
	STAT_FIELD(sysv_shm_orphan_race, sibling_spawn_ok),
	STAT_FIELD(sysv_shm_orphan_race, sibling_spawn_failed),
	STAT_FIELD(sysv_shm_orphan_race, sibling_reaped_ok),
	STAT_FIELD(sysv_shm_orphan_race, sibling_crashed),
};

const struct stat_category sysv_shm_orphan_race_category =
	STAT_CATEGORY("sysv_shm_orphan_race",
		sysv_shm_orphan_race_runs,
		sysv_shm_orphan_race_fields);

static const struct stat_field qrtr_bind_race_fields[] = {
	STAT_FIELD(qrtr_bind_race, runs),
	STAT_FIELD(qrtr_bind_race, setup_failed),
	STAT_FIELD(qrtr_bind_race, iter),
	STAT_FIELD(qrtr_bind_race, fork_failed),
	STAT_FIELD(qrtr_bind_race, spawn_pair_ok),
	STAT_FIELD(qrtr_bind_race, sibling_reaped_ok),
	STAT_FIELD(qrtr_bind_race, sibling_crashed),
	STAT_FIELD(qrtr_bind, setup_fail),
};

const struct stat_category qrtr_bind_race_category =
	STAT_CATEGORY("qrtr_bind_race",
		qrtr_bind_race_runs,
		qrtr_bind_race_fields);

static const struct stat_field pfkey_spd_walk_fields[] = {
	STAT_FIELD(pfkey_spd_walk, runs),
	STAT_FIELD(pfkey_spd_walk, setup_failed),
	STAT_FIELD(pfkey_spd_walk, iter),
	STAT_FIELD(pfkey_spd_walk, fork_failed),
	STAT_FIELD(pfkey_spd_walk, spawn_pair_ok),
	STAT_FIELD(pfkey_spd_walk, sibling_reaped_ok),
	STAT_FIELD(pfkey_spd_walk, sibling_crashed),
	STAT_FIELD(pfkey, spdget_resolved),
	STAT_FIELD(pfkey, spdget_missed),
};

const struct stat_category pfkey_spd_walk_category =
	STAT_CATEGORY("pfkey_spd_walk",
		pfkey_spd_walk_runs,
		pfkey_spd_walk_fields);

static const struct stat_field l2tp_ifname_race_fields[] = {
	STAT_FIELD(l2tp_ifname_race, runs),
	STAT_FIELD(l2tp_ifname_race, setup_failed),
	STAT_FIELD(l2tp_ifname_race, iter),
	STAT_FIELD(l2tp_ifname_race, tunnel_ok),
	STAT_FIELD(l2tp_ifname_race, tunnel_fail),
	STAT_FIELD(l2tp_ifname_race, fork_failed),
	STAT_FIELD(l2tp_ifname_race, spawn_pair_ok),
	STAT_FIELD(l2tp_ifname_race, sibling_reaped_ok),
	STAT_FIELD(l2tp_ifname_race, sibling_crashed),
};

const struct stat_category l2tp_ifname_race_category =
	STAT_CATEGORY("l2tp_ifname_race",
		l2tp_ifname_race_runs,
		l2tp_ifname_race_fields);

static const struct stat_field bpf_cgroup_attach_fields[] = {
	STAT_FIELD(bpf_cgroup_attach, runs),
	STAT_FIELD(bpf_cgroup_attach, setup_failed),
	STAT_FIELD(bpf_cgroup_attach, prog_loaded),
	STAT_FIELD(bpf_cgroup_attach, attached),
	STAT_FIELD(bpf_cgroup_attach, attach_rejected),
	STAT_FIELD(bpf_cgroup_attach, packets_sent),
	STAT_FIELD(bpf_cgroup_attach, detached),
	STAT_FIELD(bpf_cgroup_attach, post_detach_sent),
};

const struct stat_category bpf_cgroup_attach_category =
	STAT_CATEGORY("bpf_cgroup_attach",
	              bpf_cgroup_attach_runs,
	              bpf_cgroup_attach_fields);

static const struct stat_field pipe_thrash_fields[] = {
	STAT_FIELD(pipe_thrash, runs),
	STAT_FIELD(pipe_thrash, pipes),
	STAT_FIELD(pipe_thrash, socketpairs),
	STAT_FIELD(pipe_thrash, alloc_failed),
};

const struct stat_category pipe_thrash_category =
	STAT_CATEGORY("pipe_thrash",
	              pipe_thrash_runs,
	              pipe_thrash_fields);

static const struct stat_field fork_storm_fields[] = {
	STAT_FIELD(fork_storm, runs),
	STAT_FIELD(fork_storm, forks),
	STAT_FIELD(fork_storm, failed),
	STAT_FIELD(fork_storm, nested),
	STAT_FIELD(fork_storm, reaped_signal),
};

const struct stat_category fork_storm_category =
	STAT_CATEGORY("fork_storm",
	              fork_storm_runs,
	              fork_storm_fields);

static const struct stat_field cpu_hotplug_rider_fields[] = {
	STAT_FIELD(cpu_hotplug, runs),
	STAT_FIELD(cpu_hotplug, affinity_calls),
	STAT_FIELD(cpu_hotplug, sysfs_writes),
	STAT_FIELD(cpu_hotplug, open_eperm),
	STAT_FIELD(cpu_hotplug, write_eperm),
	STAT_FIELD(cpu_hotplug, write_ok),
	STAT_FIELD(cpu_hotplug, actual_offlines),
};

const struct stat_category cpu_hotplug_rider_category =
	STAT_CATEGORY("cpu_hotplug_rider",
	              cpu_hotplug_runs,
	              cpu_hotplug_rider_fields);

static const struct stat_field pidfd_storm_fields[] = {
	STAT_FIELD(pidfd_storm, runs),
	STAT_FIELD(pidfd_storm, signals),
	STAT_FIELD(pidfd_storm, getfds),
	STAT_FIELD(pidfd_storm, failed),
};

const struct stat_category pidfd_storm_category =
	STAT_CATEGORY("pidfd_storm",
	              pidfd_storm_runs,
	              pidfd_storm_fields);

static const struct stat_field madvise_cycler_fields[] = {
	STAT_FIELD(madvise_cycler, runs),
	STAT_FIELD(madvise_cycler, calls),
	STAT_FIELD(madvise_cycler, failed),
};

const struct stat_category madvise_cycler_category =
	STAT_CATEGORY("madvise_cycler",
	              madvise_cycler_runs,
	              madvise_cycler_fields);

static const struct stat_field keyring_spam_fields[] = {
	STAT_FIELD(keyring_spam, runs),
	STAT_FIELD(keyring_spam, calls),
	STAT_FIELD(keyring_spam, failed),
};

const struct stat_category keyring_spam_category =
	STAT_CATEGORY("keyring_spam",
	              keyring_spam_runs,
	              keyring_spam_fields);

static const struct stat_field vdso_mremap_race_fields[] = {
	STAT_FIELD(vdso_race, runs),
	STAT_FIELD(vdso_race, mutations),
	STAT_FIELD(vdso_race, helper_segvs),
};

const struct stat_category vdso_mremap_race_category =
	STAT_CATEGORY("vdso_mremap_race",
	              vdso_race_runs,
	              vdso_mremap_race_fields);

static const struct stat_field flock_thrash_fields[] = {
	STAT_FIELD(flock_thrash, runs),
	STAT_FIELD(flock_thrash, locks),
	STAT_FIELD(flock_thrash, failed),
};

const struct stat_category flock_thrash_category =
	STAT_CATEGORY("flock_thrash",
	              flock_thrash_runs,
	              flock_thrash_fields);

static const struct stat_field xattr_thrash_fields[] = {
	STAT_FIELD(xattr_thrash, runs),
	STAT_FIELD(xattr_thrash, set),
	STAT_FIELD(xattr_thrash, get),
	STAT_FIELD(xattr_thrash, remove),
	STAT_FIELD(xattr_thrash, list),
	STAT_FIELD(xattr_thrash, failed),
};

const struct stat_category xattr_thrash_category =
	STAT_CATEGORY("xattr_thrash",
	              xattr_thrash_runs,
	              xattr_thrash_fields);

static const struct stat_field epoll_volatility_fields[] = {
	STAT_FIELD(epoll_volatility, runs),
	STAT_FIELD(epoll_volatility, ctl_calls),
	STAT_FIELD(epoll_volatility, failed),
};

const struct stat_category epoll_volatility_category =
	STAT_CATEGORY("epoll_volatility",
	              epoll_volatility_runs,
	              epoll_volatility_fields);

static const struct stat_field cgroup_churn_fields[] = {
	STAT_FIELD(cgroup_churn, runs),
	STAT_FIELD(cgroup, mkdirs),
	STAT_FIELD(cgroup, rmdirs),
	STAT_FIELD(cgroup, failed),
	STAT_FIELD(cgroup, psi_race_runs),
	STAT_FIELD(cgroup, psi_race_writes),
	STAT_FIELD(cgroup, psi_race_failed),
};

const struct stat_category cgroup_churn_category =
	STAT_CATEGORY("cgroup_churn",
	              cgroup_churn_runs,
	              cgroup_churn_fields);

static const struct stat_field mount_churn_fields[] = {
	STAT_FIELD(mount_churn, runs),
	STAT_FIELD(mount_churn, mounts),
	STAT_FIELD(mount_churn, umounts),
	STAT_FIELD(mount_churn, failed),
};

const struct stat_category mount_churn_category =
	STAT_CATEGORY("mount_churn",
	              mount_churn_runs,
	              mount_churn_fields);

static const struct stat_field umount_race_fields[] = {
	STAT_FIELD(umount_race, runs),
	STAT_FIELD(umount_race, picks),
	STAT_FIELD(umount_race, forks),
	STAT_FIELD(umount_race, umounts),
	STAT_FIELD(umount_race, umount_failed),
	STAT_FIELD(umount_race, setup_failed),
};

const struct stat_category umount_race_category =
	STAT_CATEGORY("umount_race",
	              umount_race_runs,
	              umount_race_fields);

static const struct stat_field statmount_idmap_fields[] = {
	STAT_FIELD(statmount_idmap, runs),
	STAT_FIELD(statmount_idmap, setup_failed),
	STAT_FIELD(statmount_idmap, iter),
	STAT_FIELD(statmount_idmap, fork_failed),
	STAT_FIELD(statmount_idmap, carrier_ok),
	STAT_FIELD(statmount_idmap, carrier_fail),
	STAT_FIELD(statmount_idmap, setattr_ok),
	STAT_FIELD(statmount_idmap, setattr_fail),
	STAT_FIELD(statmount_idmap, statmount_call),
	STAT_FIELD(statmount_idmap, statmount_ok),
	STAT_FIELD(statmount_idmap, statmount_overflow),
};

const struct stat_category statmount_idmap_category =
	STAT_CATEGORY("statmount_idmap",
	              statmount_idmap_runs,
	              statmount_idmap_fields);

static const struct stat_field uffd_churn_fields[] = {
	STAT_FIELD(uffd, runs),
	STAT_FIELD(uffd, registers),
	STAT_FIELD(uffd, unregisters),
	STAT_FIELD(uffd, failed),
};

const struct stat_category uffd_churn_category =
	STAT_CATEGORY("uffd_churn",
	              uffd_runs,
	              uffd_churn_fields);

static const struct stat_field iouring_flood_fields[] = {
	STAT_FIELD(iouring, runs),
	STAT_FIELD(iouring, submits),
	STAT_FIELD(iouring, reaped),
	STAT_FIELD(iouring, failed),
};

const struct stat_category iouring_flood_category =
	STAT_CATEGORY("iouring_flood",
	              iouring_runs,
	              iouring_flood_fields);

static const struct stat_field iouring_send_zc_churn_fields[] = {
	STAT_FIELD(iouring_send_zc_churn, runs),
	STAT_FIELD(iouring_send_zc_churn, setup_failed),
	STAT_FIELD(iouring_send_zc_churn, register_bufs_ok),
	STAT_FIELD(iouring_send_zc_churn, send_zc_ok),
	STAT_FIELD(iouring_send_zc_churn, sendmsg_zc_ok),
	STAT_FIELD(iouring_send_zc_churn, unregister_race_ok),
	STAT_FIELD(iouring_send_zc_churn, update_race_ok),
	STAT_FIELD(iouring_send_zc_churn, cqe_drained),
};

const struct stat_category iouring_send_zc_churn_category =
	STAT_CATEGORY("iouring_send_zc_churn",
	              iouring_send_zc_churn_runs,
	              iouring_send_zc_churn_fields);

static const struct stat_field close_racer_fields[] = {
	STAT_FIELD(close_racer, runs),
	STAT_FIELD(close_racer, pairs),
	STAT_FIELD(close_racer, failed),
	STAT_FIELD(close_racer, thread_spawn_fail),
};

const struct stat_category close_racer_category =
	STAT_CATEGORY("close_racer",
	              close_racer_runs,
	              close_racer_fields);

static const struct stat_field refcount_audit_fields[] = {
	STAT_FIELD(refcount_audit, runs),
	STAT_FIELD(refcount_audit, fd_anomalies),
	STAT_FIELD(refcount_audit, mmap_anomalies),
	STAT_FIELD(refcount_audit, sock_anomalies),
};

const struct stat_category refcount_audit_category =
	STAT_CATEGORY("refcount_audit",
	              refcount_audit_runs,
	              refcount_audit_fields);

/*
 * Descriptors for dump_stats_json_lifecycle_and_storms().  The JSON walker
 * ignores gate_offset (it emits every category unconditionally) so the gate
 * field here only matters if a future change wires stat_category_emit_text()
 * onto these tables; the current text dump for these two categories stays
 * hand-coded in dump_stats_childop_runs_local().
 */
static const struct stat_field fs_lifecycle_fields[] = {
	STAT_FIELD(fs_lifecycle, tmpfs),
	STAT_FIELD(fs_lifecycle, ramfs),
	STAT_FIELD(fs_lifecycle, rdonly),
	STAT_FIELD(fs_lifecycle, overlay),
	STAT_FIELD(fs_lifecycle, quota),
	STAT_FIELD(fs_lifecycle, bind),
	STAT_FIELD(fs_lifecycle, unsupported),
};

const struct stat_category fs_lifecycle_category =
	STAT_CATEGORY("fs_lifecycle",
	              fs_lifecycle_tmpfs,
	              fs_lifecycle_fields);

static const struct stat_field futex_storm_fields[] = {
	STAT_FIELD(futex_storm, runs),
	STAT_FIELD(futex_storm, inner_crashed),
	STAT_FIELD(futex_storm, iters),
};

const struct stat_category futex_storm_category =
	STAT_CATEGORY("futex_storm",
	              futex_storm_runs,
	              futex_storm_fields);

/*
 * Descriptors for dump_stats_json_oracle().  Every member is named
 * <syscall>_oracle_anomalies in struct stats_s but the JSON schema emits it
 * as "<syscall>_anomalies" (the "oracle_" infix is implicit in the enclosing
 * category key), so each row uses STAT_FIELD_JSON to pin the cross-prefix
 * JSON key.  The JSON walker ignores stat_category.gate_offset (it emits
 * every category unconditionally) and the text dump for oracle stays
 * hand-coded in dump_stats_oracle_anomalies() where each row has its own
 * per-field gate, so fd_oracle_anomalies here is a placeholder gate that
 * matters only if a future change wires stat_category_emit_text() onto this
 * table.
 */
static const struct stat_field oracle_fields[] = {
	STAT_FIELD_JSON(fd_oracle, anomalies, "fd_anomalies"),
	STAT_FIELD_JSON(mmap_oracle, anomalies, "mmap_anomalies"),
	STAT_FIELD_JSON(cred_oracle, anomalies, "cred_anomalies"),
	STAT_FIELD_JSON(sched_oracle, anomalies, "sched_anomalies"),
	STAT_FIELD_JSON(uid_oracle, anomalies, "uid_anomalies"),
	STAT_FIELD_JSON(gid_oracle, anomalies, "gid_anomalies"),
	STAT_FIELD_JSON(setgroups_oracle, anomalies, "setgroups_anomalies"),
	STAT_FIELD_JSON(getegid_oracle, anomalies, "getegid_anomalies"),
	STAT_FIELD_JSON(getuid_oracle, anomalies, "getuid_anomalies"),
	STAT_FIELD_JSON(getgid_oracle, anomalies, "getgid_anomalies"),
	STAT_FIELD_JSON(getppid_oracle, anomalies, "getppid_anomalies"),
	STAT_FIELD_JSON(getcwd_oracle, anomalies, "getcwd_anomalies"),
	STAT_FIELD_JSON(getpid_oracle, anomalies, "getpid_anomalies"),
	STAT_FIELD_JSON(getpgid_oracle, anomalies, "getpgid_anomalies"),
	STAT_FIELD_JSON(getpgrp_oracle, anomalies, "getpgrp_anomalies"),
	STAT_FIELD_JSON(geteuid_oracle, anomalies, "geteuid_anomalies"),
	STAT_FIELD_JSON(getsid_oracle, anomalies, "getsid_anomalies"),
	STAT_FIELD_JSON(gettid_oracle, anomalies, "gettid_anomalies"),
	STAT_FIELD_JSON(setsid_oracle, anomalies, "setsid_anomalies"),
	STAT_FIELD_JSON(setpgid_oracle, anomalies, "setpgid_anomalies"),
	STAT_FIELD_JSON(sched_getscheduler_oracle, anomalies, "sched_getscheduler_anomalies"),
	STAT_FIELD_JSON(getgroups_oracle, anomalies, "getgroups_anomalies"),
	STAT_FIELD_JSON(getresuid_oracle, anomalies, "getresuid_anomalies"),
	STAT_FIELD_JSON(getresgid_oracle, anomalies, "getresgid_anomalies"),
	STAT_FIELD_JSON(umask_oracle, anomalies, "umask_anomalies"),
	STAT_FIELD_JSON(sched_get_priority_max_oracle, anomalies, "sched_get_priority_max_anomalies"),
	STAT_FIELD_JSON(sched_get_priority_min_oracle, anomalies, "sched_get_priority_min_anomalies"),
	STAT_FIELD_JSON(sched_yield_oracle, anomalies, "sched_yield_anomalies"),
	STAT_FIELD_JSON(getpagesize_oracle, anomalies, "getpagesize_anomalies"),
	STAT_FIELD_JSON(time_oracle, anomalies, "time_anomalies"),
	STAT_FIELD_JSON(gettimeofday_oracle, anomalies, "gettimeofday_anomalies"),
	STAT_FIELD_JSON(newuname_oracle, anomalies, "newuname_anomalies"),
	STAT_FIELD_JSON(rt_sigpending_oracle, anomalies, "rt_sigpending_anomalies"),
	STAT_FIELD_JSON(sched_getaffinity_oracle, anomalies, "sched_getaffinity_anomalies"),
	STAT_FIELD_JSON(rt_sigprocmask_oracle, anomalies, "rt_sigprocmask_anomalies"),
	STAT_FIELD_JSON(sched_getparam_oracle, anomalies, "sched_getparam_anomalies"),
	STAT_FIELD_JSON(sched_rr_get_interval_oracle, anomalies, "sched_rr_get_interval_anomalies"),
	STAT_FIELD_JSON(get_robust_list_oracle, anomalies, "get_robust_list_anomalies"),
	STAT_FIELD_JSON(getrlimit_oracle, anomalies, "getrlimit_anomalies"),
	STAT_FIELD_JSON(sysinfo_oracle, anomalies, "sysinfo_anomalies"),
	STAT_FIELD_JSON(times_oracle, anomalies, "times_anomalies"),
	STAT_FIELD_JSON(clock_getres_oracle, anomalies, "clock_getres_anomalies"),
	STAT_FIELD_JSON(capget_oracle, anomalies, "capget_anomalies"),
	STAT_FIELD_JSON(capdrop_oracle, anomalies, "capdrop_anomalies"),
	STAT_FIELD_JSON(newlstat_oracle, anomalies, "newlstat_anomalies"),
	STAT_FIELD_JSON(newstat_oracle, anomalies, "newstat_anomalies"),
	STAT_FIELD_JSON(newfstat_oracle, anomalies, "newfstat_anomalies"),
	STAT_FIELD_JSON(newfstatat_oracle, anomalies, "newfstatat_anomalies"),
	STAT_FIELD_JSON(statx_oracle, anomalies, "statx_anomalies"),
	STAT_FIELD_JSON(fstatfs_oracle, anomalies, "fstatfs_anomalies"),
	STAT_FIELD_JSON(fstatfs64_oracle, anomalies, "fstatfs64_anomalies"),
	STAT_FIELD_JSON(statfs_oracle, anomalies, "statfs_anomalies"),
	STAT_FIELD_JSON(statfs64_oracle, anomalies, "statfs64_anomalies"),
	STAT_FIELD_JSON(uname_oracle, anomalies, "uname_anomalies"),
	STAT_FIELD_JSON(lsm_list_modules_oracle, anomalies, "lsm_list_modules_anomalies"),
	STAT_FIELD_JSON(listmount_oracle, anomalies, "listmount_anomalies"),
	STAT_FIELD_JSON(statmount_oracle, anomalies, "statmount_anomalies"),
	STAT_FIELD_JSON(getsockname_oracle, anomalies, "getsockname_anomalies"),
	STAT_FIELD_JSON(getpeername_oracle, anomalies, "getpeername_anomalies"),
	STAT_FIELD_JSON(file_getattr_oracle, anomalies, "file_getattr_anomalies"),
	STAT_FIELD_JSON(sched_getattr_oracle, anomalies, "sched_getattr_anomalies"),
	STAT_FIELD_JSON(getrusage_oracle, anomalies, "getrusage_anomalies"),
	STAT_FIELD_JSON(sigpending_oracle, anomalies, "sigpending_anomalies"),
	STAT_FIELD_JSON(getcpu_oracle, anomalies, "getcpu_anomalies"),
	STAT_FIELD_JSON(clock_gettime_oracle, anomalies, "clock_gettime_anomalies"),
	STAT_FIELD_JSON(get_mempolicy_oracle, anomalies, "get_mempolicy_anomalies"),
	STAT_FIELD_JSON(lsm_get_self_attr_oracle, anomalies, "lsm_get_self_attr_anomalies"),
	STAT_FIELD_JSON(prlimit64_oracle, anomalies, "prlimit64_anomalies"),
	STAT_FIELD_JSON(sigaltstack_oracle, anomalies, "sigaltstack_anomalies"),
	STAT_FIELD_JSON(olduname_oracle, anomalies, "olduname_anomalies"),
	STAT_FIELD_JSON(lookup_dcookie_oracle, anomalies, "lookup_dcookie_anomalies"),
	STAT_FIELD_JSON(getxattr_oracle, anomalies, "getxattr_anomalies"),
	STAT_FIELD_JSON(lgetxattr_oracle, anomalies, "lgetxattr_anomalies"),
	STAT_FIELD_JSON(fgetxattr_oracle, anomalies, "fgetxattr_anomalies"),
	STAT_FIELD_JSON(listxattrat_oracle, anomalies, "listxattrat_anomalies"),
	STAT_FIELD_JSON(flistxattr_oracle, anomalies, "flistxattr_anomalies"),
	STAT_FIELD_JSON(listxattr_oracle, anomalies, "listxattr_anomalies"),
	STAT_FIELD_JSON(llistxattr_oracle, anomalies, "llistxattr_anomalies"),
	STAT_FIELD_JSON(readlink_oracle, anomalies, "readlink_anomalies"),
	STAT_FIELD_JSON(readlinkat_oracle, anomalies, "readlinkat_anomalies"),
	STAT_FIELD_JSON(sysfs_oracle, anomalies, "sysfs_anomalies"),
};

const struct stat_category oracle_category =
	STAT_CATEGORY("oracle",
	              fd_oracle_anomalies,
	              oracle_fields);

/*
 * Descriptor tables staged for the follow-up JSON fan-out (per-fn conversions
 * of dump_stats_json_iouring_and_zombies / _socket_family_and_tls /
 * _iouring_zc_and_kvm / _netfilter_and_xfrm / _fault_and_fd_lifecycle).
 *
 * The category JSON key in each case doesn't match the struct member's
 * single prefix, so STAT_FIELD() rows pick whichever prefix matches the
 * actual struct member (packet_fanout_*, recipe_*, nat_t_churn_/nat_t_,
 * kvm_run_/kvm_, fd_/local_fd_/epoll_); .name doubles as the text-side
 * key.  For fd_lifecycle's three cross-prefix members (local_fd_* and
 * epoll_*) the suffix alone wouldn't yield the schema's JSON key, so
 * STAT_FIELD_JSON() pins the JSON key explicitly.
 *
 * As with the fs_lifecycle/futex_storm pair above, the JSON walker
 * ignores stat_category.gate_offset; the gate field is set to the same
 * counter the existing text emitter uses (or a placeholder for
 * fd_lifecycle, which has no single gate) so a future text-side wiring
 * has a sensible default.  These tables have no live caller yet -- they
 * land here so the per-fn JSON conversions can be reviewed in isolation.
 */
static const struct stat_field packet_fanout_thrash_fields[] = {
	STAT_FIELD(packet_fanout, runs),
	STAT_FIELD(packet_fanout, setup_failed),
	STAT_FIELD(packet_fanout, ring_failed),
	STAT_FIELD(packet_fanout, rings_installed),
	STAT_FIELD(packet_fanout, mmap_failed),
	STAT_FIELD(packet_fanout, joins),
	STAT_FIELD(packet_fanout, rejoins_ok),
	STAT_FIELD(packet_fanout, rejoins_rejected),
};

static const struct stat_category packet_fanout_thrash_category
	__attribute__((unused)) =
	STAT_CATEGORY("packet_fanout_thrash",
	              packet_fanout_runs,
	              packet_fanout_thrash_fields);

static const struct stat_field recipe_runner_fields[] = {
	STAT_FIELD(recipe, runs),
	STAT_FIELD(recipe, completed),
	STAT_FIELD(recipe, partial),
	STAT_FIELD(recipe, unsupported),
};

const struct stat_category recipe_runner_category =
	STAT_CATEGORY("recipe_runner",
	              recipe_runs,
	              recipe_runner_fields);

/*
 * Descriptors for the remaining categories in
 * dump_stats_json_iouring_and_zombies().  The text-side dump for these stays
 * hand-coded for now, and the JSON walker ignores gate_offset, so the gate
 * field choices below only matter if a future change wires
 * stat_category_emit_text() onto these tables.
 */
static const struct stat_field iouring_recipes_fields[] = {
	STAT_FIELD(iouring_recipes, runs),
	STAT_FIELD(iouring_recipes, completed),
	STAT_FIELD(iouring_recipes, partial),
	STAT_FIELD(iouring_recipes, enosys),
};

const struct stat_category iouring_recipes_category =
	STAT_CATEGORY("iouring_recipes",
	              iouring_recipes_runs,
	              iouring_recipes_fields);

static const struct stat_field iouring_eventfd_fields[] = {
	STAT_FIELD(iouring_eventfd, register_ok),
	STAT_FIELD(iouring_eventfd, register_fail),
	STAT_FIELD(iouring_eventfd, recursive_runs),
	STAT_FIELD(iouring_eventfd, recursive_cqes),
};

const struct stat_category iouring_eventfd_category =
	STAT_CATEGORY("iouring_eventfd",
	              iouring_eventfd_register_ok,
	              iouring_eventfd_fields);

/* aio_submitted: iocbs the kernel accepted on io_submit's success branch
 * (retval > 0 and within [0, nr]).  A single-field category sits next to
 * its iouring siblings so a quiet success window is distinguishable from
 * a quiet rejection window in both JSON and text dumps. */
static const struct stat_field aio_fields[] = {
	STAT_FIELD(aio, submitted),
};

const struct stat_category aio_category =
	STAT_CATEGORY("aio",
	              aio_submitted,
	              aio_fields);

/* errno_gradient: SHADOW measurement of upward errno-class crossings (no
 * fuzzer-behaviour change -- see the errno_gradient_* block in
 * include/stats.h for the class axis and the SHADOW contract).  Aggregate
 * scalars only; the per-syscall last-class array is deliberately
 * unrendered (internal to the predicate, matching the other per-syscall
 * shadow arrays).  Text render gates on errno_gradient_crossings so a
 * run that never observed an upward transition emits nothing in the
 * text dump; JSON renders unconditionally for schema stability,
 * matching the aio sibling above. */
static const struct stat_field errno_gradient_fields[] = {
	STAT_FIELD(errno_gradient, crossings),
	STAT_FIELD(errno_gradient, to_permstate),
	STAT_FIELD(errno_gradient, to_success),
};

const struct stat_category errno_gradient_category =
	STAT_CATEGORY("errno_gradient",
	              errno_gradient_crossings,
	              errno_gradient_fields);

/* cold_overflow: SHADOW measurement of would-save events that fall on the
 * cold-or-corpus-absent tail under a CMP_RISING_PC_FLAT plateau (no
 * fuzzer-behaviour change -- see the cold_overflow_would_save_* block
 * in include/stats.h for the predicate and the SHADOW contract).
 * Aggregate scalars only.  Text render gates on cold_overflow_would_
 * save so a run that never observed a qualifying event emits nothing
 * in the text dump; JSON renders unconditionally for schema stability,
 * matching the errno_gradient sibling above. */
static const struct stat_field cold_overflow_fields[] = {
	STAT_FIELD(cold_overflow, would_save),
	STAT_FIELD(cold_overflow, would_save_cold),
	STAT_FIELD(cold_overflow, would_save_absent),
};

const struct stat_category cold_overflow_category =
	STAT_CATEGORY("cold_overflow",
	              cold_overflow_would_save,
	              cold_overflow_fields);

/* inplace_crypto_mutated: the inplace-crypto oracle childop overwrites a
 * plaintext slot mid-flight to catch handlers that read after the kernel
 * has copied; the per-mutation bump is the only positive signal that the
 * oracle ran productively in a window.  A single-field category renders
 * it in both JSON and text so a quiet "no mutations" window is
 * distinguishable from a window where the childop never fired. */
static const struct stat_field inplace_crypto_fields[] = {
	STAT_FIELD(inplace_crypto, mutated),
};

const struct stat_category inplace_crypto_category =
	STAT_CATEGORY("inplace_crypto",
	              inplace_crypto_mutated,
	              inplace_crypto_fields);

/* fd_runtime_skipped: handle_retval_obj_fd's post-success classify of an
 * fd retval against the per-child local-object table.  The two paths are
 * mutually exclusive per call and both increment from the same site, so a
 * run where neither bumped means no syscall ever produced a registerable
 * fd; gating on _stdio (the dominant arm — retvals 0/1/2 from any
 * fd-returning syscall) keeps a quiet window terse in the text dump.
 * JSON renders unconditionally alongside aio for schema stability. */
static const struct stat_field fd_runtime_skipped_fields[] = {
	STAT_FIELD(fd_runtime_skipped, stdio),
	STAT_FIELD(fd_runtime_skipped, already_registered),
};

const struct stat_category fd_runtime_skipped_category =
	STAT_CATEGORY("fd_runtime_skipped",
	              fd_runtime_skipped_stdio,
	              fd_runtime_skipped_fields);

/* zombie_slots mixes two struct prefixes (zombie_slots_ for the gauge,
 * zombies_ for the counters); each STAT_FIELD picks its own prefix so the
 * JSON keys stay flat ("pending", "reaped", "timed_out"). */
static const struct stat_field zombie_slots_fields[] = {
	STAT_FIELD(zombie_slots, pending),
	STAT_FIELD(zombies, reaped),
	STAT_FIELD(zombies, timed_out),
};

const struct stat_category zombie_slots_category =
	STAT_CATEGORY("zombie_slots",
	              zombies_reaped,
	              zombie_slots_fields);

static const struct stat_field nat_t_churn_fields[] = {
	STAT_FIELD(nat_t_churn, runs),
	STAT_FIELD(nat_t_churn, setup_failed),
	STAT_FIELD(nat_t_churn, sa_added),
	STAT_FIELD(nat_t_churn, sa_deleted),
	STAT_FIELD(nat_t_churn, frames_sent),
	STAT_FIELD(nat_t, xfrm6_setup_ok),
	STAT_FIELD(nat_t, xfrm6_setup_fail),
	STAT_FIELD(nat_t, xfrm6_sendto_runs),
	STAT_FIELD(nat_t, xfrm6_delsa_races),
};

static const struct stat_category nat_t_churn_category
	__attribute__((unused)) =
	STAT_CATEGORY("nat_t_churn",
	              nat_t_churn_runs,
	              nat_t_churn_fields);

static const struct stat_field kvm_run_churn_fields[] = {
	STAT_FIELD(kvm_run, invocations),
	STAT_FIELD(kvm_run, exit_io),
	STAT_FIELD(kvm_run, exit_mmio),
	STAT_FIELD(kvm_run, exit_hlt),
	STAT_FIELD(kvm_run, exit_shutdown),
	STAT_FIELD(kvm_run, exit_fail_entry),
	STAT_FIELD(kvm_run, exit_internal_error),
	STAT_FIELD(kvm_run, exit_intr),
	STAT_FIELD(kvm_run, exit_other),
	STAT_FIELD(kvm_run, errors),
	STAT_FIELD(kvm, gpc_memslot_race_runs),
	STAT_FIELD(kvm, gpc_memslot_race_deletes),
	STAT_FIELD(kvm, gpc_memslot_race_unsupported),
};

static const struct stat_category kvm_run_churn_category
	__attribute__((unused)) =
	STAT_CATEGORY("kvm_run_churn",
	              kvm_run_invocations,
	              kvm_run_churn_fields);

static const struct stat_field fd_lifecycle_fields[] = {
	STAT_FIELD(fd, stale_detected),
	STAT_FIELD(fd, stale_by_generation),
	STAT_FIELD(fd, closed_tracked),
	STAT_FIELD(fd, duped),
	STAT_FIELD(fd, events_processed),
	STAT_FIELD(fd, events_dropped),
	STAT_FIELD(fd, event_close_count),
	STAT_FIELD(fd, event_evict_count),
	STAT_FIELD(fd, hash_reinsert_dropped),
	STAT_FIELD_JSON(local_fd, hash_insert_dropped,
	                "local_hash_insert_dropped"),
	STAT_FIELD(fd, runtime_registered),
	STAT_FIELD_JSON(epoll, lazy_armed, "epoll_lazy_armed"),
	STAT_FIELD_JSON(epoll, blocking_poll_skipped,
	                "epoll_blocking_poll_skipped"),
	STAT_FIELD(fd, random_exhausted),
	STAT_FIELD(fd, provider_invalid),
};

/* fd_lifecycle has no single gate counter -- the text emitter ORs many
 * fields.  Use fd_stale_detected as a placeholder for the JSON walker
 * (which ignores gate_offset); any text-side wiring will need to revisit. */
static const struct stat_category fd_lifecycle_category
	__attribute__((unused)) =
	STAT_CATEGORY("fd_lifecycle",
	              fd_stale_detected,
	              fd_lifecycle_fields);




/*
 * observability table: top syscalls by per-window
 * cmp-insert delta, with the matching injected / hint_pc_wins / edge
 * deltas in adjacent columns so the operator can read the conversion
 * funnel without grepping a flat key/value dump.  The "CMP-rich but
 * unconverted" diagnostic signature is high cmp+ and injected+ with low
 * pc-wins+ and edge+ -- the row format puts those four numbers
 * side-by-side so the visual scan is single-line per syscall.
 *
 * Window snapshots live in function-static arrays (MAX_NR_SYSCALL of
 * unsigned long apiece, ~32 KiB total BSS in this TU) rather than in
 * kcov_shm: the dump consumer is single-owner (the parent's periodic
 * tick), so a per-tick window state in shm would just duplicate state
 * without adding any cross-process value, and the BSS cost is paid
 * once per process, not per child.  The existing per_syscall_*_previous
 * arrays in kcov_shm are consumed by dump_stats() at run shutdown and
 * by the JSON dump, with no defined update cadence; reusing them here
 * would silently desync the window deltas.
 */
static void kcov_cmp_observability_block_render(long elapsed __unused__)
{
	static unsigned long prev_cmp_inserts[MAX_NR_SYSCALL];
	static unsigned long prev_cmp_injected[MAX_NR_SYSCALL];
	static unsigned long prev_pc_wins[MAX_NR_SYSCALL];
	static unsigned long prev_edges[MAX_NR_SYSCALL];
	static bool armed;
	unsigned int top_nr[10];
	unsigned long top_cmp[10];
	unsigned long top_injected[10];
	unsigned long top_pc_wins[10];
	unsigned long top_edges[10];
	unsigned int top_count = 0;
	unsigned int nr_syscalls_to_scan;
	const struct syscalltable *table;
	unsigned int i;
	unsigned int j;

	if (kcov_shm == NULL)
		return;

	nr_syscalls_to_scan = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
	if (nr_syscalls_to_scan > MAX_NR_SYSCALL)
		nr_syscalls_to_scan = MAX_NR_SYSCALL;
	table = biarch ? syscalls_64bit : syscalls;

	memset(top_cmp, 0, sizeof(top_cmp));
	memset(top_injected, 0, sizeof(top_injected));
	memset(top_pc_wins, 0, sizeof(top_pc_wins));
	memset(top_edges, 0, sizeof(top_edges));

	for (i = 0; i < nr_syscalls_to_scan; i++) {
		unsigned long cur_inserts = __atomic_load_n(
			&kcov_shm->per_syscall_cmp_inserts[i], __ATOMIC_RELAXED);
		unsigned long cur_injected = __atomic_load_n(
			&kcov_shm->per_syscall_cmp_injected[i], __ATOMIC_RELAXED);
		unsigned long cur_pc_wins = __atomic_load_n(
			&kcov_shm->per_syscall_cmp_hint_pc_wins[i], __ATOMIC_RELAXED);
		unsigned long cur_edges = __atomic_load_n(
			&kcov_shm->per_syscall_edges[i], __ATOMIC_RELAXED);
		unsigned long delta_inserts;
		unsigned long delta_injected;
		unsigned long delta_pc_wins;
		unsigned long delta_edges;
		unsigned int k;

		/* First window: arm the snapshot and skip emit so any
		 * pre-existing cumulative counts (warm-start / prior epoch)
		 * are not mis-attributed to the first dump window. */
		if (!armed) {
			prev_cmp_inserts[i] = cur_inserts;
			prev_cmp_injected[i] = cur_injected;
			prev_pc_wins[i] = cur_pc_wins;
			prev_edges[i] = cur_edges;
			continue;
		}

		/* Guarded unsigned subtraction.  Counters are monotonic in
		 * the steady-state case but a cmp-hints warm-start that
		 * lands between two dumps can publish a lower value; clamp
		 * to zero so a one-shot warm-start doesn't underflow into a
		 * ~ULONG_MAX delta the topn picker would pin to slot 0. */
		delta_inserts  = (cur_inserts  > prev_cmp_inserts[i])  ? cur_inserts  - prev_cmp_inserts[i]  : 0;
		delta_injected = (cur_injected > prev_cmp_injected[i]) ? cur_injected - prev_cmp_injected[i] : 0;
		delta_pc_wins  = (cur_pc_wins  > prev_pc_wins[i])      ? cur_pc_wins  - prev_pc_wins[i]      : 0;
		delta_edges    = (cur_edges    > prev_edges[i])        ? cur_edges    - prev_edges[i]        : 0;

		prev_cmp_inserts[i] = cur_inserts;
		prev_cmp_injected[i] = cur_injected;
		prev_pc_wins[i] = cur_pc_wins;
		prev_edges[i] = cur_edges;

		if (delta_inserts == 0)
			continue;

		/* Rank by cmp_inserts delta: that's the producer-side
		 * "kernel emitted distinct CMP signal for this syscall"
		 * column, which is the one the PHASE-0 hold cares about.
		 * Insertion sort on the four arrays in lock-step so the
		 * top-N rows stay aligned across columns. */
		for (j = top_count; j > 0 && delta_inserts > top_cmp[j - 1]; j--) {
			if (j < 10) {
				top_cmp[j]      = top_cmp[j - 1];
				top_injected[j] = top_injected[j - 1];
				top_pc_wins[j]  = top_pc_wins[j - 1];
				top_edges[j]    = top_edges[j - 1];
				top_nr[j]       = top_nr[j - 1];
			}
		}
		k = j;
		if (k < 10) {
			top_cmp[k]      = delta_inserts;
			top_injected[k] = delta_injected;
			top_pc_wins[k]  = delta_pc_wins;
			top_edges[k]    = delta_edges;
			top_nr[k]       = i;
			if (top_count < 10)
				top_count++;
		}
	}

	if (!armed) {
		armed = true;
		return;
	}

	if (top_count == 0)
		return;

	stats_log_write("KCOV CMP-rich syscalls (top by per-window cmp_inserts delta):\n");
	stats_log_write("  %-24s %10s %10s %10s %10s\n",
			"syscall", "cmp+", "injected+", "pc-wins+", "edge+");
	for (j = 0; j < top_count; j++) {
		struct syscallentry *entry = table[top_nr[j]].entry;
		const char *name = entry ? entry->name : "???";

		stats_log_write("  %-24s %10lu %10lu %10lu %10lu\n",
				name, top_cmp[j], top_injected[j],
				top_pc_wins[j], top_edges[j]);
	}
}

/*
 * RedQueen observability: top-N syscalls by re-exec
 * attempt delta + flat aggregates for the per-slot histograms.  The
 * per-slot histograms stay flat (6 entries each) rather than per-nr to
 * keep the block readable -- the "which arg slot won attribution" and
 * "which arg slot produced novelty" questions are aggregate-shaped, not
 * per-syscall, so the answer is two short rows of counts.  The per-nr
 * partition for attempts and ambiguity is the syscall-shaped half: that
 * goes through the top-N table.
 */
static void kcov_redqueen_observability_block_render(long elapsed __unused__)
{
	static unsigned long prev_attempts[MAX_NR_SYSCALL];
	static unsigned long prev_ambiguous[MAX_NR_SYSCALL];
	static bool armed;
	unsigned int top_nr[10];
	unsigned long top_attempts[10];
	unsigned long top_ambiguous[10];
	unsigned int top_count = 0;
	unsigned long slot_hist[CMP_REDQUEEN_SLOT_HIST_NR];
	unsigned long slot_success[CMP_REDQUEEN_SLOT_HIST_NR];
	bool any_slot = false;
	unsigned long pick_success[REEXEC_PENDING_PICK_HIST_NR];
	bool any_pick_success = false;
	unsigned int nr_syscalls_to_scan;
	const struct syscalltable *table;
	unsigned int i;
	unsigned int j;

	if (kcov_shm == NULL)
		return;

	nr_syscalls_to_scan = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
	if (nr_syscalls_to_scan > MAX_NR_SYSCALL)
		nr_syscalls_to_scan = MAX_NR_SYSCALL;
	table = biarch ? syscalls_64bit : syscalls;

	memset(top_attempts, 0, sizeof(top_attempts));
	memset(top_ambiguous, 0, sizeof(top_ambiguous));

	for (i = 0; i < nr_syscalls_to_scan; i++) {
		unsigned long cur_attempts = __atomic_load_n(
			&kcov_shm->reexec_attempts_by_syscall[i], __ATOMIC_RELAXED);
		unsigned long cur_ambig = __atomic_load_n(
			&kcov_shm->reexec_ambiguous_by_syscall[i], __ATOMIC_RELAXED);
		unsigned long delta_attempts;
		unsigned long delta_ambig;
		unsigned int k;

		if (!armed) {
			prev_attempts[i] = cur_attempts;
			prev_ambiguous[i] = cur_ambig;
			continue;
		}

		delta_attempts = (cur_attempts > prev_attempts[i])  ? cur_attempts - prev_attempts[i]  : 0;
		delta_ambig    = (cur_ambig    > prev_ambiguous[i]) ? cur_ambig    - prev_ambiguous[i] : 0;

		prev_attempts[i] = cur_attempts;
		prev_ambiguous[i] = cur_ambig;

		if (delta_attempts == 0)
			continue;

		for (j = top_count; j > 0 && delta_attempts > top_attempts[j - 1]; j--) {
			if (j < 10) {
				top_attempts[j]  = top_attempts[j - 1];
				top_ambiguous[j] = top_ambiguous[j - 1];
				top_nr[j]        = top_nr[j - 1];
			}
		}
		k = j;
		if (k < 10) {
			top_attempts[k]  = delta_attempts;
			top_ambiguous[k] = delta_ambig;
			top_nr[k]        = i;
			if (top_count < 10)
				top_count++;
		}
	}

	for (i = 0; i < CMP_REDQUEEN_SLOT_HIST_NR; i++) {
		slot_hist[i] = __atomic_load_n(
			&kcov_shm->reexec_attribution_slot_hist[i],
			__ATOMIC_RELAXED);
		slot_success[i] = __atomic_load_n(
			&kcov_shm->reexec_success_by_slot[i],
			__ATOMIC_RELAXED);
		if ((slot_hist[i] | slot_success[i]) != 0)
			any_slot = true;
	}

	for (i = 0; i < REEXEC_PENDING_PICK_HIST_NR; i++) {
		pick_success[i] = __atomic_load_n(
			&kcov_shm->reexec_pending_pick_success[i],
			__ATOMIC_RELAXED);
		if (pick_success[i] != 0)
			any_pick_success = true;
	}

	if (!armed) {
		armed = true;
		return;
	}

	if (top_count > 0) {
		stats_log_write("KCOV RedQueen syscalls (top by per-window reexec_attempts delta):\n");
		stats_log_write("  %-24s %12s %12s\n",
				"syscall", "attempts+", "ambiguous+");
		for (j = 0; j < top_count; j++) {
			struct syscallentry *entry = table[top_nr[j]].entry;
			const char *name = entry ? entry->name : "???";

			stats_log_write("  %-24s %12lu %12lu\n",
					name, top_attempts[j], top_ambiguous[j]);
		}
	}

	if (any_slot) {
		stats_log_write("KCOV RedQueen arg-slot attribution (cumulative, slot=index+1):\n");
		stats_log_write("  %-12s %10s %10s %10s %10s %10s %10s\n",
				"counter", "a1", "a2", "a3", "a4", "a5", "a6");
		stats_log_write("  %-12s %10lu %10lu %10lu %10lu %10lu %10lu\n",
				"attribute",
				slot_hist[0], slot_hist[1], slot_hist[2],
				slot_hist[3], slot_hist[4], slot_hist[5]);
		stats_log_write("  %-12s %10lu %10lu %10lu %10lu %10lu %10lu\n",
				"success",
				slot_success[0], slot_success[1], slot_success[2],
				slot_success[3], slot_success[4], slot_success[5]);
	}

	/* Per-pending-buffer-index success counter (A/B signal for
	 * --redqueen-pending-pick).  Cumulative across both pick modes:
	 * a heavy load at index 0 with a flat tail under the FIRST policy
	 * versus a spread under RANDOM tells whether trace-order bias is
	 * costing signal.  Header is the policy name so an operator
	 * eyeballing the dump knows which arm is currently active. */
	if (any_pick_success) {
		stats_log_write("KCOV RedQueen pending-buffer pick success (cumulative, policy=%s):\n",
				redqueen_pending_pick_name(
					redqueen_pending_pick_mode_arg));
		stats_log_write("  %-12s %10s %10s %10s %10s %10s %10s %10s %10s\n",
				"counter",
				"p0", "p1", "p2", "p3",
				"p4", "p5", "p6", "p7");
		stats_log_write("  %-12s %10lu %10lu %10lu %10lu %10lu %10lu %10lu %10lu\n",
				"success",
				pick_success[0], pick_success[1],
				pick_success[2], pick_success[3],
				pick_success[4], pick_success[5],
				pick_success[6], pick_success[7]);
	}
}

/*
 * Old-flat-pool vs shadow-hypothesis comparison block.  Two sub-blocks:
 *
 *   1. Flat per-pool-kind summary: per-pool consumed / pc-wins / misses /
 *      cmp-novelty cumulative + window-delta.  Lets an operator read the
 *      per-syscall vs field-pool conversion ratio at a glance without
 *      having to thread per-syscall arrays.
 *
 *   2. Per-syscall top-N table: for the top syscalls by per-window
 *      cmp-hint injection delta, print the OLD per-syscall pool's
 *      conversion (per_syscall_cmp_hint_pc_wins / per_syscall_cmp_injected)
 *      alongside the SHADOW typed-hypothesis per-syscall pc-wins (summed
 *      across the matching hyp_pools[nr][0/1] entries).  The two columns
 *      answer the t75 question directly: does the typed store predict
 *      better-converting picks than the flat pool on the same syscalls
 *      the flat pool is most active on.
 *
 * Pure SHADOW: every counter read here is bumped by paths that already
 * existed (the by-pool partition bumps land alongside the existing flat
 * counters and the cmp_hyp_credit_outcome paths); this function only
 * formats the comparison.  Independent prev_* snapshots so other dump
 * blocks that read the same arrays do not desync the window deltas here.
 */
static void kcov_cmp_oldpool_vs_shadow_block_render(long elapsed __unused__)
{
	static unsigned long prev_consumed_by_pool[CMP_HINT_POOL_KIND_NR];
	static unsigned long prev_pc_wins_by_pool[CMP_HINT_POOL_KIND_NR];
	static unsigned long prev_misses_by_pool[CMP_HINT_POOL_KIND_NR];
	static unsigned long prev_cmp_novelty_by_pool[CMP_HINT_POOL_KIND_NR];
	static unsigned long prev_per_nr_injected[MAX_NR_SYSCALL];
	static unsigned long prev_per_nr_pc_wins[MAX_NR_SYSCALL];
	static uint64_t prev_per_nr_hyp_pc_wins[MAX_NR_SYSCALL];
	static bool armed;

	unsigned long cur_consumed_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long cur_pc_wins_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long cur_misses_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long cur_cmp_novelty_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long delta_consumed_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long delta_pc_wins_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long delta_misses_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long delta_cmp_novelty_by_pool[CMP_HINT_POOL_KIND_NR];

	unsigned int top_nr[10];
	unsigned long top_injected[10];
	unsigned long top_pc_wins[10];
	unsigned long top_pc_wins_cum[10];
	unsigned long top_injected_cum[10];
	uint64_t top_hyp_pc_wins_cum[10];
	uint64_t top_hyp_pc_wins_delta[10];
	uint64_t top_hyp_consumed_cum[10];
	uint64_t top_hyp_misses_cum[10];
	unsigned int top_count = 0;

	unsigned int nr_syscalls_to_scan;
	const struct syscalltable *table;
	unsigned int k, i, j;
	bool any_pool_delta = false;

	static const char *const pool_kind_name[CMP_HINT_POOL_KIND_NR] = {
		[CMP_HINT_POOL_PER_SYSCALL] = "per-syscall",
		[CMP_HINT_POOL_FIELD]       = "field",
	};

	if (kcov_shm == NULL)
		return;

	for (k = 0; k < CMP_HINT_POOL_KIND_NR; k++) {
		cur_consumed_by_pool[k] = __atomic_load_n(
			&kcov_shm->cmp_hint_consumed_by_pool[k],
			__ATOMIC_RELAXED);
		cur_pc_wins_by_pool[k] = __atomic_load_n(
			&kcov_shm->cmp_hint_pc_wins_by_pool[k],
			__ATOMIC_RELAXED);
		cur_misses_by_pool[k] = __atomic_load_n(
			&kcov_shm->cmp_hint_misses_by_pool[k],
			__ATOMIC_RELAXED);
		cur_cmp_novelty_by_pool[k] = __atomic_load_n(
			&kcov_shm->cmp_hint_cmp_novelty_wins_by_pool[k],
			__ATOMIC_RELAXED);
	}

	if (!armed) {
		for (k = 0; k < CMP_HINT_POOL_KIND_NR; k++) {
			prev_consumed_by_pool[k] = cur_consumed_by_pool[k];
			prev_pc_wins_by_pool[k] = cur_pc_wins_by_pool[k];
			prev_misses_by_pool[k] = cur_misses_by_pool[k];
			prev_cmp_novelty_by_pool[k] = cur_cmp_novelty_by_pool[k];
		}
		/* per-nr snapshots and hyp walk are armed on the first
		 * windowed emit below; the first call seeds prev_ and skips
		 * the comparison, identical to the pattern in
		 * kcov_cmp_observability_block_render(). */
		armed = true;
		return;
	}

	for (k = 0; k < CMP_HINT_POOL_KIND_NR; k++) {
		/* Counters are monotonic but guard the subtraction defensively
		 * the same way the existing per-syscall topn does -- a torn
		 * load on a hot relaxed atomic could otherwise underflow to
		 * ~ULONG_MAX and dominate the table. */
		delta_consumed_by_pool[k] = (cur_consumed_by_pool[k] > prev_consumed_by_pool[k]) ?
			cur_consumed_by_pool[k] - prev_consumed_by_pool[k] : 0;
		delta_pc_wins_by_pool[k] = (cur_pc_wins_by_pool[k] > prev_pc_wins_by_pool[k]) ?
			cur_pc_wins_by_pool[k] - prev_pc_wins_by_pool[k] : 0;
		delta_misses_by_pool[k] = (cur_misses_by_pool[k] > prev_misses_by_pool[k]) ?
			cur_misses_by_pool[k] - prev_misses_by_pool[k] : 0;
		delta_cmp_novelty_by_pool[k] = (cur_cmp_novelty_by_pool[k] > prev_cmp_novelty_by_pool[k]) ?
			cur_cmp_novelty_by_pool[k] - prev_cmp_novelty_by_pool[k] : 0;

		if ((delta_consumed_by_pool[k] | delta_pc_wins_by_pool[k] |
		     delta_misses_by_pool[k] | delta_cmp_novelty_by_pool[k]) != 0)
			any_pool_delta = true;
	}

	if (any_pool_delta) {
		stats_log_write("KCOV CMP old-flat-pool conversion by pool kind over last %lds:\n",
				elapsed);
		stats_log_write("  %-12s %12s %12s %12s %12s %8s\n",
				"pool", "consumed+", "pc-wins+", "misses+",
				"novelty+", "pc-rate");
		for (k = 0; k < CMP_HINT_POOL_KIND_NR; k++) {
			unsigned long denom = delta_pc_wins_by_pool[k] +
					      delta_misses_by_pool[k];
			unsigned int pct = denom ?
				(unsigned int)((delta_pc_wins_by_pool[k] * 100UL) /
					       denom) : 0;
			const char *name = pool_kind_name[k];

			if (name == NULL)
				name = "?";
			stats_log_write("  %-12s %12lu %12lu %12lu %12lu %7u%%\n",
					name,
					delta_consumed_by_pool[k],
					delta_pc_wins_by_pool[k],
					delta_misses_by_pool[k],
					delta_cmp_novelty_by_pool[k],
					pct);
		}
		stats_log_write("  cumulative:\n");
		for (k = 0; k < CMP_HINT_POOL_KIND_NR; k++) {
			unsigned long denom_cum = cur_pc_wins_by_pool[k] +
						  cur_misses_by_pool[k];
			unsigned int pct_cum = denom_cum ?
				(unsigned int)((cur_pc_wins_by_pool[k] * 100UL) /
					       denom_cum) : 0;
			const char *name = pool_kind_name[k];

			if (name == NULL)
				name = "?";
			stats_log_write("  %-12s %12lu %12lu %12lu %12lu %7u%%\n",
					name,
					cur_consumed_by_pool[k],
					cur_pc_wins_by_pool[k],
					cur_misses_by_pool[k],
					cur_cmp_novelty_by_pool[k],
					pct_cum);
		}
	}

	for (k = 0; k < CMP_HINT_POOL_KIND_NR; k++) {
		prev_consumed_by_pool[k] = cur_consumed_by_pool[k];
		prev_pc_wins_by_pool[k] = cur_pc_wins_by_pool[k];
		prev_misses_by_pool[k] = cur_misses_by_pool[k];
		prev_cmp_novelty_by_pool[k] = cur_cmp_novelty_by_pool[k];
	}

	/* Per-syscall top-N: OLD per-syscall pool conversion vs SHADOW
	 * hypothesis pc-wins.  Rank rows by per-window injected delta -- the
	 * "kernel actually drove cmp-hint substitution into this syscall this
	 * window" column -- so the comparison is anchored on syscalls where
	 * the OLD pool was active enough for the conversion ratio to be
	 * meaningful.  Hyp pc-wins is summed across the parallel
	 * hyp_pools[nr][0/1] entries: the shadow store has no per-syscall
	 * scalar, but the per-hypothesis pc_wins counter is bumped by
	 * cmp_hyp_credit_outcome() from the same credit drain, so the per-
	 * syscall sum is the natural shadow counterpart. */
	nr_syscalls_to_scan = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
	if (nr_syscalls_to_scan > MAX_NR_SYSCALL)
		nr_syscalls_to_scan = MAX_NR_SYSCALL;
	table = biarch ? syscalls_64bit : syscalls;

	memset(top_injected, 0, sizeof(top_injected));
	memset(top_pc_wins, 0, sizeof(top_pc_wins));
	memset(top_pc_wins_cum, 0, sizeof(top_pc_wins_cum));
	memset(top_injected_cum, 0, sizeof(top_injected_cum));
	memset(top_hyp_pc_wins_cum, 0, sizeof(top_hyp_pc_wins_cum));
	memset(top_hyp_pc_wins_delta, 0, sizeof(top_hyp_pc_wins_delta));
	memset(top_hyp_consumed_cum, 0, sizeof(top_hyp_consumed_cum));
	memset(top_hyp_misses_cum, 0, sizeof(top_hyp_misses_cum));

	for (i = 0; i < nr_syscalls_to_scan; i++) {
		unsigned long cur_injected = __atomic_load_n(
			&kcov_shm->per_syscall_cmp_injected[i],
			__ATOMIC_RELAXED);
		unsigned long cur_pc_wins = __atomic_load_n(
			&kcov_shm->per_syscall_cmp_hint_pc_wins[i],
			__ATOMIC_RELAXED);
		uint64_t cur_hyp_pc_wins_nr = 0;
		uint64_t cur_hyp_consumed_nr = 0;
		uint64_t cur_hyp_misses_nr = 0;
		unsigned long delta_injected;
		unsigned long delta_pc_wins;
		uint64_t delta_hyp_pc_wins_nr;

		if (cmp_hints_shm != NULL) {
			unsigned int do32_i, e_i;

			for (do32_i = 0; do32_i < 2; do32_i++) {
				struct cmp_hyp_pool *p =
					&cmp_hints_shm->hyp_pools[i][do32_i];
				unsigned int n = p->count;

				if (n > CMP_HYP_PER_SYSCALL)
					n = CMP_HYP_PER_SYSCALL;
				for (e_i = 0; e_i < n; e_i++) {
					struct cmp_hypothesis *h = &p->entries[e_i];

					cur_hyp_pc_wins_nr += __atomic_load_n(
						&h->pc_wins, __ATOMIC_RELAXED);
					cur_hyp_consumed_nr += __atomic_load_n(
						&h->consumed_count, __ATOMIC_RELAXED);
					cur_hyp_misses_nr += __atomic_load_n(
						&h->misses, __ATOMIC_RELAXED);
				}
			}
		}

		delta_injected = (cur_injected > prev_per_nr_injected[i]) ?
			cur_injected - prev_per_nr_injected[i] : 0;
		delta_pc_wins  = (cur_pc_wins  > prev_per_nr_pc_wins[i])  ?
			cur_pc_wins  - prev_per_nr_pc_wins[i]  : 0;
		delta_hyp_pc_wins_nr = (cur_hyp_pc_wins_nr > prev_per_nr_hyp_pc_wins[i]) ?
			cur_hyp_pc_wins_nr - prev_per_nr_hyp_pc_wins[i] : 0;

		prev_per_nr_injected[i]    = cur_injected;
		prev_per_nr_pc_wins[i]     = cur_pc_wins;
		prev_per_nr_hyp_pc_wins[i] = cur_hyp_pc_wins_nr;

		if (delta_injected == 0)
			continue;

		for (j = top_count; j > 0 && delta_injected > top_injected[j - 1]; j--) {
			if (j < 10) {
				top_injected[j]          = top_injected[j - 1];
				top_pc_wins[j]           = top_pc_wins[j - 1];
				top_pc_wins_cum[j]       = top_pc_wins_cum[j - 1];
				top_injected_cum[j]      = top_injected_cum[j - 1];
				top_hyp_pc_wins_cum[j]   = top_hyp_pc_wins_cum[j - 1];
				top_hyp_pc_wins_delta[j] = top_hyp_pc_wins_delta[j - 1];
				top_hyp_consumed_cum[j]  = top_hyp_consumed_cum[j - 1];
				top_hyp_misses_cum[j]    = top_hyp_misses_cum[j - 1];
				top_nr[j]                = top_nr[j - 1];
			}
		}
		{
			unsigned int kk = j;

			if (kk < 10) {
				top_injected[kk]          = delta_injected;
				top_pc_wins[kk]           = delta_pc_wins;
				top_pc_wins_cum[kk]       = cur_pc_wins;
				top_injected_cum[kk]      = cur_injected;
				top_hyp_pc_wins_cum[kk]   = cur_hyp_pc_wins_nr;
				top_hyp_pc_wins_delta[kk] = delta_hyp_pc_wins_nr;
				top_hyp_consumed_cum[kk]  = cur_hyp_consumed_nr;
				top_hyp_misses_cum[kk]    = cur_hyp_misses_nr;
				top_nr[kk]                = i;
				if (top_count < 10)
					top_count++;
			}
		}
	}

	if (top_count == 0)
		return;

	stats_log_write("KCOV CMP per-syscall old-pool vs shadow-hyp pc-wins (top by injected delta):\n");
	stats_log_write("  %-24s %10s %10s %8s %10s %10s %10s %10s\n",
			"syscall", "inj+", "old-pc+", "old-pc%",
			"hyp-pc+", "hyp-pc-tot", "consume", "miss");
	for (j = 0; j < top_count; j++) {
		struct syscallentry *entry = table[top_nr[j]].entry;
		const char *name = entry ? entry->name : "???";
		unsigned int pct = top_injected_cum[j] ?
			(unsigned int)((top_pc_wins_cum[j] * 100UL) /
				       top_injected_cum[j]) : 0;

		stats_log_write("  %-24s %10lu %10lu %7u%% %10lu %10lu %10lu %10lu\n",
				name,
				top_injected[j],
				top_pc_wins[j],
				pct,
				(unsigned long)top_hyp_pc_wins_delta[j],
				(unsigned long)top_hyp_pc_wins_cum[j],
				(unsigned long)top_hyp_consumed_cum[j],
				(unsigned long)top_hyp_misses_cum[j]);
	}
}

/*
 * Per-syscall typed-hypothesis store SATURATION: top-N (nr, do32) pools
 * ranked by pool->count, with the per_kind_count[] breakdown so the
 * (nr, kind) cells that crowd the store are visible.
 *
 * pool->count and pool->per_kind_count[] have no kcov_shm scalar twin:
 * the cumulative cmp_hyp_kind_full / inserted_by_kind producer counters
 * never surface the live occupancy, so an exhausted (nr, kind) cell is
 * invisible from the cumulative producer view alone.
 *
 * Read-side only: relaxed loads against lockless observe / scrub bumps,
 * count clamped to CMP_HYP_PER_SYSCALL and per_kind to CMP_HYP_PER_KIND
 * so a torn load cannot drive a downstream divide or fixed-width column
 * past its cap.  Gated on any-occupancy so an empty store stays quiet.
 */
static void kcov_cmp_hyp_saturation_block_render(long elapsed __unused__)
{
#define KCOV_CMP_HYP_SAT_TOPN	32
	static const char * const kind_labels[CMP_HYP_KIND_NR] = {
		"exact", "range", "boundary", "bitmask",
		"enum_family", "alignment", "length",
		"foreign_value",
	};
	struct sat_row {
		unsigned int nr;
		unsigned int do32;
		unsigned int count;
		unsigned int per_kind[CMP_HYP_KIND_NR];
	};
	struct sat_row top[KCOV_CMP_HYP_SAT_TOPN];
	unsigned int top_count = 0;
	unsigned int nr_scan[2];
	unsigned int nr_i, do32_i, k, j;
	unsigned long occupied_pools = 0;
	unsigned long total_entries = 0;

	if (cmp_hints_shm == NULL)
		return;

	nr_scan[0] = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
	nr_scan[1] = biarch ? max_nr_32bit_syscalls : 0;
	for (do32_i = 0; do32_i < 2; do32_i++)
		if (nr_scan[do32_i] > MAX_NR_SYSCALL)
			nr_scan[do32_i] = MAX_NR_SYSCALL;

	for (do32_i = 0; do32_i < 2; do32_i++) {
		for (nr_i = 0; nr_i < nr_scan[do32_i]; nr_i++) {
			struct cmp_hyp_pool *p =
				&cmp_hints_shm->hyp_pools[nr_i][do32_i];
			unsigned int count = __atomic_load_n(
				&p->count, __ATOMIC_RELAXED);
			struct sat_row cand;

			if (count == 0)
				continue;
			if (count > CMP_HYP_PER_SYSCALL)
				count = CMP_HYP_PER_SYSCALL;

			occupied_pools++;
			total_entries += count;

			cand.nr = nr_i;
			cand.do32 = do32_i;
			cand.count = count;
			for (k = 0; k < CMP_HYP_KIND_NR; k++) {
				unsigned int pk = __atomic_load_n(
					&p->per_kind_count[k], __ATOMIC_RELAXED);

				if (pk > CMP_HYP_PER_KIND)
					pk = CMP_HYP_PER_KIND;
				cand.per_kind[k] = pk;
			}

			for (j = top_count;
			     j > 0 && count > top[j - 1].count;
			     j--) {
				if (j < KCOV_CMP_HYP_SAT_TOPN)
					top[j] = top[j - 1];
			}
			if (j < KCOV_CMP_HYP_SAT_TOPN) {
				top[j] = cand;
				if (top_count < KCOV_CMP_HYP_SAT_TOPN)
					top_count++;
			}
		}
	}

	if (top_count == 0)
		return;

	stats_log_write("KCOV CMP hyp store per-syscall saturation over last %lds (top-%u of %lu occupied pools, %lu entries, cap %u/pool):\n",
			elapsed, top_count, occupied_pools,
			total_entries, CMP_HYP_PER_SYSCALL);
	{
		char hdr[CMP_HYP_KIND_NR * 12 + 1];
		int off = 0;

		hdr[0] = '\0';
		for (k = 0; k < CMP_HYP_KIND_NR; k++) {
			int w = snprintf(hdr + off, sizeof(hdr) - off,
					 " %11s", kind_labels[k]);
			if (w < 0 || (size_t)w >= sizeof(hdr) - (size_t)off)
				break;
			off += w;
		}
		stats_log_write("  %-24s %4s %9s %5s%s\n",
				"syscall", "arch", "count/cap", "fill%", hdr);
	}

	for (j = 0; j < top_count; j++) {
		const struct sat_row *r = &top[j];
		const struct syscalltable *tab;
		struct syscallentry *entry;
		const char *name;
		const char *arch_tag;
		unsigned int nr_max;
		unsigned int pct;
		char count_buf[16];
		char row[CMP_HYP_KIND_NR * 12 + 1];
		int off = 0;

		if (biarch) {
			if (r->do32) {
				tab = syscalls_32bit;
				nr_max = max_nr_32bit_syscalls;
				arch_tag = "32";
			} else {
				tab = syscalls_64bit;
				nr_max = max_nr_64bit_syscalls;
				arch_tag = "64";
			}
		} else {
			tab = syscalls;
			nr_max = max_nr_syscalls;
			arch_tag = "-";
		}
		entry = (r->nr < nr_max) ? tab[r->nr].entry : NULL;
		name = entry ? entry->name : "???";
		pct = (unsigned int)(((unsigned long)r->count * 100UL) /
				     CMP_HYP_PER_SYSCALL);

		snprintf(count_buf, sizeof(count_buf), "%u/%u",
			 r->count, CMP_HYP_PER_SYSCALL);

		row[0] = '\0';
		for (k = 0; k < CMP_HYP_KIND_NR; k++) {
			int w = snprintf(row + off, sizeof(row) - off,
					 " %11u", r->per_kind[k]);
			if (w < 0 || (size_t)w >= sizeof(row) - (size_t)off)
				break;
			off += w;
		}

		stats_log_write("  %-24s %4s %9s %4u%%%s\n",
				name, arch_tag, count_buf, pct, row);
	}
#undef KCOV_CMP_HYP_SAT_TOPN
}

/*
 * Surface the KCOV CMP counters in the same 600s periodic stats-log-file
 * dump as defense_counters_periodic_dump.  Without this the cmp counters
 * are only visible from dump_stats() (run shutdown) and the JSON dump
 * (on enable), so a long overnight run produces no time-series — just a
 * single end-snapshot — making it impossible to correlate cmp_hints
 * effectiveness with edge-discovery cadence over the run.
 *
 * Three sub-blocks, each gated independently so a healthy run that has
 * no DIAG errnos doesn't carry an empty "DIAG:" line into the log:
 *  - per-window deltas + rates + cumulative totals for the three cmp
 *    counters, formatted to match defense_counters_periodic_dump;
 *  - per-mode child population (cumulative) so the realised PC/CMP
 *    mode mix is visible in the time series, not just at shutdown;
 *  - first-failure-wins errno/count per cmp-init/runtime site.
 */
void __cold kcov_cmp_stats_periodic_dump(void)
{
	static unsigned long prev_records;
	static unsigned long prev_truncated;
	static unsigned long prev_bloom_skipped;
	static unsigned long prev_strip_skipped;
	static unsigned long prev_unique;
	static unsigned long prev_try_get_attempts;
	static unsigned long prev_try_get_returned;
	static unsigned long prev_injected;
	static unsigned long prev_prop_injected;
	static unsigned long prev_chaos_suppressed;
	static unsigned long prev_count_oob;
	static unsigned long prev_canary_lock_post;
	static unsigned long prev_canary_pre;
	static unsigned long prev_canary_post;
	static unsigned long prev_reexec_attempts;
	static unsigned long prev_reexec_attempts_with_new_cmp;
	static unsigned long prev_reexec_attribution_found;
	static unsigned long prev_reexec_attribution_ambiguous;
	static unsigned long prev_reexec_attribution_width_match;
	static unsigned long prev_reexec_new_cmps_total;
	static unsigned long prev_reexec_skipped_destructive;
	static unsigned long prev_reexec_skipped_validate_silent;
	static unsigned long prev_reexec_window_cap_hit;
	static unsigned long prev_reexec_pending_dropped;
	static unsigned long prev_reexec_gate_skip_in_reexec;
	static unsigned long prev_reexec_gate_skip_disabled;
	static unsigned long prev_reexec_gate_skip_mode;
	static unsigned long prev_reexec_gate_skip_chain_mid;
	static unsigned long prev_reexec_gate_skip_no_new_cmp;
	static unsigned long prev_reexec_gate_skip_no_pending;
	static unsigned long prev_reexec_gate_skip_rate;
	static unsigned long prev_reexec_gate_pass;
	static unsigned long prev_cmp_parent_calls_enabled;
	static unsigned long prev_cmp_parent_calls_control;
	static unsigned long prev_cmp_parent_new_cmps_enabled;
	static unsigned long prev_cmp_parent_new_cmps_control;
	static unsigned long prev_cmp_hint_callsite[CMP_HINT_CALLSITE_NR];
	static unsigned long prev_prop_injected_callsite[PROP_INJECTED_CALLSITE_NR];
	static unsigned long prev_save_reject_nonconst;
	static unsigned long prev_save_reject_uninteresting;
	static unsigned long prev_save_reject_sentinel;
	static unsigned long prev_save_reject_dup;
	static unsigned long prev_save_reject_cap;
	static unsigned long prev_cmp_hints_consumed;
	static unsigned long prev_cmp_hint_wins;
	static unsigned long prev_cmp_hint_misses;
	static unsigned long prev_cmp_hint_cmp_novelty_wins;
	static unsigned long prev_cmp_hint_stash_overflow;
	static unsigned long prev_cmp_hint_credit_entry_evicted;
	static unsigned long prev_cmp_recent_inserts;
	static unsigned long prev_cmp_recent_evicts;
	static unsigned long prev_cmp_recent_would_pick;
	static unsigned long prev_cmp_recent_would_miss;
	static unsigned long prev_cmp_recent_live_picks;
	static unsigned long prev_cmp_inject_arm_a_baseline_fires;
	static unsigned long prev_cmp_inject_arm_b_baseline_fires;
	static unsigned long prev_cmp_inject_denom_diverged;
	static unsigned long prev_prop_ring_argop_arm_b_fires;
	static unsigned long prev_frontier_blend_samples;
	static unsigned long prev_remote_adaptive_samples;
	static unsigned long prev_mut_structured_shadow_divergences;
	static struct timespec last_dump;
	struct timespec now;
	long elapsed;
	unsigned long cur_records, cur_truncated, cur_bloom_skipped, cur_unique;
	unsigned long cur_strip_skipped;
	unsigned long cur_try_get_attempts, cur_try_get_returned, cur_injected;
	unsigned long cur_prop_injected;
	unsigned long cur_chaos_suppressed;
	unsigned long cur_count_oob, cur_canary_lock_post, cur_canary_pre, cur_canary_post;
	unsigned long cur_reexec_attempts, cur_reexec_attribution_found;
	unsigned long cur_reexec_attempts_with_new_cmp;
	unsigned long cur_reexec_attribution_ambiguous, cur_reexec_new_cmps_total;
	unsigned long cur_reexec_attribution_width_match;
	unsigned long cur_reexec_skipped_destructive, cur_reexec_skipped_validate_silent;
	unsigned long cur_reexec_window_cap_hit;
	unsigned long cur_reexec_pending_dropped;
	unsigned long cur_reexec_gate_skip_in_reexec;
	unsigned long cur_reexec_gate_skip_disabled;
	unsigned long cur_reexec_gate_skip_mode;
	unsigned long cur_reexec_gate_skip_chain_mid;
	unsigned long cur_reexec_gate_skip_no_new_cmp;
	unsigned long cur_reexec_gate_skip_no_pending;
	unsigned long cur_reexec_gate_skip_rate;
	unsigned long cur_reexec_gate_pass;
	unsigned long cur_cmp_parent_calls_enabled, cur_cmp_parent_calls_control;
	unsigned long cur_cmp_parent_new_cmps_enabled, cur_cmp_parent_new_cmps_control;
	unsigned long cur_cmp_hint_callsite[CMP_HINT_CALLSITE_NR];
	unsigned long cur_prop_injected_callsite[PROP_INJECTED_CALLSITE_NR];
	unsigned long cur_save_reject_nonconst, cur_save_reject_uninteresting;
	unsigned long cur_save_reject_sentinel, cur_save_reject_dup, cur_save_reject_cap;
	unsigned long delta_save_reject_nonconst, delta_save_reject_uninteresting;
	unsigned long delta_save_reject_sentinel, delta_save_reject_dup, delta_save_reject_cap;
	unsigned long delta_records, delta_truncated, delta_bloom_skipped, delta_unique;
	unsigned long delta_strip_skipped;
	unsigned long delta_try_get_attempts, delta_try_get_returned, delta_injected;
	unsigned long delta_prop_injected;
	unsigned long delta_chaos_suppressed;
	unsigned long delta_count_oob, delta_canary_lock_post, delta_canary_pre, delta_canary_post;
	unsigned long delta_reexec_attempts, delta_reexec_attribution_found;
	unsigned long delta_reexec_attempts_with_new_cmp;
	unsigned long delta_reexec_attribution_ambiguous, delta_reexec_new_cmps_total;
	unsigned long delta_reexec_attribution_width_match;
	unsigned long delta_reexec_skipped_destructive, delta_reexec_skipped_validate_silent;
	unsigned long delta_reexec_window_cap_hit;
	unsigned long delta_reexec_pending_dropped;
	unsigned long delta_reexec_gate_skip_in_reexec;
	unsigned long delta_reexec_gate_skip_disabled;
	unsigned long delta_reexec_gate_skip_mode;
	unsigned long delta_reexec_gate_skip_chain_mid;
	unsigned long delta_reexec_gate_skip_no_new_cmp;
	unsigned long delta_reexec_gate_skip_no_pending;
	unsigned long delta_reexec_gate_skip_rate;
	unsigned long delta_reexec_gate_pass;
	unsigned long delta_cmp_parent_calls_enabled, delta_cmp_parent_calls_control;
	unsigned long delta_cmp_parent_new_cmps_enabled, delta_cmp_parent_new_cmps_control;
	unsigned long delta_cmp_hint_callsite[CMP_HINT_CALLSITE_NR];
	unsigned long delta_prop_injected_callsite[PROP_INJECTED_CALLSITE_NR];
	unsigned long cur_cmp_hints_consumed, cur_cmp_hint_wins, cur_cmp_hint_misses;
	unsigned long cur_cmp_hint_cmp_novelty_wins;
	unsigned long cur_cmp_hint_stash_overflow, cur_cmp_hint_credit_entry_evicted;
	unsigned long cur_cmp_recent_inserts, cur_cmp_recent_evicts;
	unsigned long cur_cmp_recent_would_pick, cur_cmp_recent_would_miss;
	unsigned long cur_cmp_recent_live_picks;
	unsigned long delta_cmp_hints_consumed, delta_cmp_hint_wins, delta_cmp_hint_misses;
	unsigned long delta_cmp_hint_cmp_novelty_wins;
	unsigned long delta_cmp_hint_stash_overflow, delta_cmp_hint_credit_entry_evicted;
	unsigned long delta_cmp_recent_inserts, delta_cmp_recent_evicts;
	unsigned long delta_cmp_recent_would_pick, delta_cmp_recent_would_miss;
	unsigned long delta_cmp_recent_live_picks;
	unsigned long cur_cmp_inject_arm_a_baseline_fires, cur_cmp_inject_arm_b_baseline_fires;
	unsigned long cur_cmp_inject_denom_diverged;
	unsigned long delta_cmp_inject_arm_a_baseline_fires, delta_cmp_inject_arm_b_baseline_fires;
	unsigned long delta_cmp_inject_denom_diverged;
	unsigned int  cur_cmp_inject_arm_a_children, cur_cmp_inject_arm_b_children;
	unsigned long cur_prop_ring_argop_arm_b_fires, delta_prop_ring_argop_arm_b_fires;
	unsigned int  cur_prop_ring_argop_arm_a_children, cur_prop_ring_argop_arm_b_children;
	unsigned long cur_frontier_blend_samples, delta_frontier_blend_samples;
	unsigned int  cur_frontier_blend_arm_a_children, cur_frontier_blend_arm_b_children;
	unsigned long cur_remote_adaptive_samples, delta_remote_adaptive_samples;
	unsigned long cur_remote_adaptive_would_demote;
	unsigned long cur_remote_adaptive_would_promote;
	unsigned long cur_remote_adaptive_would_force;
	unsigned long cur_remote_adaptive_would_gate_promote;
	unsigned long cur_remote_adaptive_agree;
	unsigned long cur_arg_meta_addr_with_meta;
	unsigned long cur_arg_meta_addr_without_meta;
	unsigned long cur_arg_meta_argtype_stale;
	unsigned long cur_arg_meta_scrub_would_destroy_in;
	unsigned long cur_arg_meta_scrub_would_preserve_out;
	unsigned long cur_blanket_address_scrub_slots_walked;
	unsigned int  cur_remote_adaptive_arm_a_children, cur_remote_adaptive_arm_b_children;
	unsigned long cur_mut_structured_shadow_samples;
	unsigned long cur_mut_structured_shadow_divergences;
	unsigned long delta_mut_structured_shadow_divergences;
	unsigned int  cur_mut_structured_arm_a_children, cur_mut_structured_arm_b_children;
	bool any_callsite_delta = false;
	bool any_prop_callsite_delta = false;
	unsigned int pc_kids, cmp_kids;

	if (kcov_shm == NULL)
		return;

	clock_gettime(CLOCK_MONOTONIC, &now);

	cur_records       = __atomic_load_n(&kcov_shm->cmp_records_collected,   __ATOMIC_RELAXED);
	cur_truncated     = __atomic_load_n(&kcov_shm->cmp_trace_truncated,     __ATOMIC_RELAXED);
	cur_bloom_skipped = __atomic_load_n(&kcov_shm->cmp_hints_bloom_skipped, __ATOMIC_RELAXED);
	cur_strip_skipped = __atomic_load_n(&kcov_shm->cmp_hints_strip_skipped, __ATOMIC_RELAXED);
	cur_unique        = __atomic_load_n(&kcov_shm->cmp_hints_unique_inserts, __ATOMIC_RELAXED);
	/* Source from parent_stats: cmp_hints_try_get_ex() now enqueues
	 * +1 per attempt/return via the per-child stats_ring; the kcov_shm
	 * scalars are gone, removing a fuzzer-visible wild-write target. */
	cur_try_get_attempts = parent_stats.cmp_hints_try_get_attempts;
	cur_try_get_returned = parent_stats.cmp_hints_try_get_returned;
	cur_injected         = __atomic_load_n(&kcov_shm->cmp_hints_injected,         __ATOMIC_RELAXED);
	cur_prop_injected    = __atomic_load_n(&kcov_shm->propagation_injected,       __ATOMIC_RELAXED);
	cur_chaos_suppressed = __atomic_load_n(&kcov_shm->cmp_hints_chaos_suppressed, __ATOMIC_RELAXED);
	cur_count_oob        = __atomic_load_n(&kcov_shm->cmp_hints_count_oob,               __ATOMIC_RELAXED);
	cur_canary_lock_post = __atomic_load_n(&kcov_shm->cmp_hints_canary_lock_post_corrupt, __ATOMIC_RELAXED);
	cur_canary_pre       = __atomic_load_n(&kcov_shm->cmp_hints_canary_pre_corrupt,      __ATOMIC_RELAXED);
	cur_canary_post      = __atomic_load_n(&kcov_shm->cmp_hints_canary_post_corrupt,     __ATOMIC_RELAXED);
	cur_reexec_attempts                = __atomic_load_n(&kcov_shm->reexec_attempts,                __ATOMIC_RELAXED);
	cur_reexec_attempts_with_new_cmp   = __atomic_load_n(&kcov_shm->reexec_attempts_with_new_cmp,   __ATOMIC_RELAXED);
	cur_reexec_attribution_found       = __atomic_load_n(&kcov_shm->reexec_attribution_found,       __ATOMIC_RELAXED);
	cur_reexec_attribution_ambiguous   = __atomic_load_n(&kcov_shm->reexec_attribution_ambiguous,   __ATOMIC_RELAXED);
	cur_reexec_attribution_width_match = __atomic_load_n(&kcov_shm->reexec_attribution_width_match, __ATOMIC_RELAXED);
	cur_reexec_new_cmps_total          = __atomic_load_n(&kcov_shm->reexec_new_cmps_total,          __ATOMIC_RELAXED);
	cur_reexec_skipped_destructive     = __atomic_load_n(&kcov_shm->reexec_skipped_destructive,     __ATOMIC_RELAXED);
	cur_reexec_skipped_validate_silent = __atomic_load_n(&kcov_shm->reexec_skipped_validate_silent, __ATOMIC_RELAXED);
	cur_reexec_window_cap_hit          = __atomic_load_n(&kcov_shm->reexec_window_cap_hit,          __ATOMIC_RELAXED);
	cur_reexec_pending_dropped         = __atomic_load_n(&kcov_shm->reexec_pending_dropped,         __ATOMIC_RELAXED);
	cur_reexec_gate_skip_in_reexec     = __atomic_load_n(&kcov_shm->reexec_gate_skip_in_reexec,     __ATOMIC_RELAXED);
	cur_reexec_gate_skip_disabled      = __atomic_load_n(&kcov_shm->reexec_gate_skip_disabled,      __ATOMIC_RELAXED);
	cur_reexec_gate_skip_mode          = __atomic_load_n(&kcov_shm->reexec_gate_skip_mode,          __ATOMIC_RELAXED);
	cur_reexec_gate_skip_chain_mid     = __atomic_load_n(&kcov_shm->reexec_gate_skip_chain_mid,     __ATOMIC_RELAXED);
	cur_reexec_gate_skip_no_new_cmp    = __atomic_load_n(&kcov_shm->reexec_gate_skip_no_new_cmp,    __ATOMIC_RELAXED);
	cur_reexec_gate_skip_no_pending    = __atomic_load_n(&kcov_shm->reexec_gate_skip_no_pending,    __ATOMIC_RELAXED);
	cur_reexec_gate_skip_rate          = __atomic_load_n(&kcov_shm->reexec_gate_skip_rate,          __ATOMIC_RELAXED);
	cur_reexec_gate_pass               = __atomic_load_n(&kcov_shm->reexec_gate_pass,               __ATOMIC_RELAXED);
	cur_cmp_parent_calls_enabled       = __atomic_load_n(&kcov_shm->cmp_parent_calls_enabled,       __ATOMIC_RELAXED);
	cur_cmp_parent_calls_control       = __atomic_load_n(&kcov_shm->cmp_parent_calls_control,       __ATOMIC_RELAXED);
	cur_cmp_parent_new_cmps_enabled    = __atomic_load_n(&kcov_shm->cmp_parent_new_cmps_enabled,    __ATOMIC_RELAXED);
	cur_cmp_parent_new_cmps_control    = __atomic_load_n(&kcov_shm->cmp_parent_new_cmps_control,    __ATOMIC_RELAXED);
	cur_save_reject_nonconst      = __atomic_load_n(&kcov_shm->cmp_hints_save_reject_nonconst,      __ATOMIC_RELAXED);
	cur_save_reject_uninteresting = __atomic_load_n(&kcov_shm->cmp_hints_save_reject_uninteresting, __ATOMIC_RELAXED);
	cur_save_reject_sentinel      = __atomic_load_n(&kcov_shm->cmp_hints_save_reject_sentinel,      __ATOMIC_RELAXED);
	cur_save_reject_dup           = __atomic_load_n(&kcov_shm->cmp_hints_save_reject_dup,           __ATOMIC_RELAXED);
	cur_save_reject_cap           = __atomic_load_n(&kcov_shm->cmp_hints_save_reject_cap,           __ATOMIC_RELAXED);
	{
		unsigned int cs;
		for (cs = 0; cs < CMP_HINT_CALLSITE_NR; cs++)
			cur_cmp_hint_callsite[cs] = __atomic_load_n(
				&kcov_shm->cmp_hint_callsite_injected[cs],
				__ATOMIC_RELAXED);
	}
	{
		unsigned int cs;
		for (cs = 0; cs < PROP_INJECTED_CALLSITE_NR; cs++)
			cur_prop_injected_callsite[cs] = __atomic_load_n(
				&kcov_shm->propagation_injected_callsite[cs],
				__ATOMIC_RELAXED);
	}
	cur_cmp_hints_consumed             = __atomic_load_n(&kcov_shm->cmp_hints_consumed,             __ATOMIC_RELAXED);
	cur_cmp_hint_wins                  = __atomic_load_n(&kcov_shm->cmp_hint_wins,                  __ATOMIC_RELAXED);
	cur_cmp_hint_misses                = __atomic_load_n(&kcov_shm->cmp_hint_misses,                __ATOMIC_RELAXED);
	cur_cmp_hint_cmp_novelty_wins      = __atomic_load_n(&kcov_shm->cmp_hint_cmp_novelty_wins,      __ATOMIC_RELAXED);
	cur_cmp_hint_stash_overflow        = __atomic_load_n(&kcov_shm->cmp_hint_stash_overflow,        __ATOMIC_RELAXED);
	cur_cmp_hint_credit_entry_evicted  = __atomic_load_n(&kcov_shm->cmp_hint_credit_entry_evicted,  __ATOMIC_RELAXED);
	cur_cmp_recent_inserts             = __atomic_load_n(&kcov_shm->cmp_recent_inserts,             __ATOMIC_RELAXED);
	cur_cmp_recent_evicts              = __atomic_load_n(&kcov_shm->cmp_recent_evicts,              __ATOMIC_RELAXED);
	cur_cmp_recent_would_pick          = __atomic_load_n(&kcov_shm->cmp_recent_would_pick,          __ATOMIC_RELAXED);
	cur_cmp_recent_would_miss          = __atomic_load_n(&kcov_shm->cmp_recent_would_miss,          __ATOMIC_RELAXED);
	cur_cmp_recent_live_picks          = __atomic_load_n(&kcov_shm->cmp_recent_live_picks,          __ATOMIC_RELAXED);
	cur_cmp_inject_arm_a_baseline_fires = __atomic_load_n(&kcov_shm->cmp_inject_arm_a_baseline_fires, __ATOMIC_RELAXED);
	cur_cmp_inject_arm_b_baseline_fires = __atomic_load_n(&kcov_shm->cmp_inject_arm_b_baseline_fires, __ATOMIC_RELAXED);
	cur_cmp_inject_denom_diverged       = __atomic_load_n(&kcov_shm->cmp_inject_denom_diverged,       __ATOMIC_RELAXED);
	cur_cmp_inject_arm_a_children       = __atomic_load_n(&kcov_shm->cmp_inject_arm_a_children,       __ATOMIC_RELAXED);
	cur_cmp_inject_arm_b_children       = __atomic_load_n(&kcov_shm->cmp_inject_arm_b_children,       __ATOMIC_RELAXED);
	cur_prop_ring_argop_arm_b_fires     = __atomic_load_n(&kcov_shm->prop_ring_argop_arm_b_fires,     __ATOMIC_RELAXED);
	cur_prop_ring_argop_arm_a_children  = __atomic_load_n(&kcov_shm->prop_ring_argop_arm_a_children,  __ATOMIC_RELAXED);
	cur_prop_ring_argop_arm_b_children  = __atomic_load_n(&kcov_shm->prop_ring_argop_arm_b_children,  __ATOMIC_RELAXED);
	/* frontier_blend_samples lives in shm->stats (bumped per fire from
	 * both arms in lock-step), the cohort children counters live in
	 * kcov_shm (bumped once per child).  Read both here so the cohort
	 * dump row can be delta-gated on the fire counter, matching the
	 * prop_ring_argop template. */
	cur_frontier_blend_samples          = __atomic_load_n(&shm->stats.frontier_blend_samples,         __ATOMIC_RELAXED);
	cur_frontier_blend_arm_a_children   = __atomic_load_n(&kcov_shm->frontier_blend_arm_a_children,   __ATOMIC_RELAXED);
	cur_frontier_blend_arm_b_children   = __atomic_load_n(&kcov_shm->frontier_blend_arm_b_children,   __ATOMIC_RELAXED);
	cur_remote_adaptive_samples         = __atomic_load_n(&shm->stats.remote_adaptive_samples,        __ATOMIC_RELAXED);
	cur_remote_adaptive_would_demote    = __atomic_load_n(&shm->stats.remote_adaptive_would_demote,   __ATOMIC_RELAXED);
	cur_remote_adaptive_would_promote   = __atomic_load_n(&shm->stats.remote_adaptive_would_promote,  __ATOMIC_RELAXED);
	cur_remote_adaptive_would_force     = __atomic_load_n(&shm->stats.remote_adaptive_would_force,    __ATOMIC_RELAXED);
	cur_remote_adaptive_would_gate_promote = __atomic_load_n(&shm->stats.remote_adaptive_would_gate_promote, __ATOMIC_RELAXED);
	cur_remote_adaptive_agree           = __atomic_load_n(&shm->stats.remote_adaptive_agree,          __ATOMIC_RELAXED);
	cur_remote_adaptive_arm_a_children  = __atomic_load_n(&kcov_shm->remote_adaptive_arm_a_children,  __ATOMIC_RELAXED);
	cur_remote_adaptive_arm_b_children  = __atomic_load_n(&kcov_shm->remote_adaptive_arm_b_children,  __ATOMIC_RELAXED);
	cur_arg_meta_addr_with_meta            = __atomic_load_n(&shm->stats.arg_meta_addr_with_meta,            __ATOMIC_RELAXED);
	cur_arg_meta_addr_without_meta         = __atomic_load_n(&shm->stats.arg_meta_addr_without_meta,         __ATOMIC_RELAXED);
	cur_arg_meta_argtype_stale             = __atomic_load_n(&shm->stats.arg_meta_argtype_stale,             __ATOMIC_RELAXED);
	cur_arg_meta_scrub_would_destroy_in    = __atomic_load_n(&shm->stats.arg_meta_scrub_would_destroy_in,    __ATOMIC_RELAXED);
	cur_arg_meta_scrub_would_preserve_out  = __atomic_load_n(&shm->stats.arg_meta_scrub_would_preserve_out,  __ATOMIC_RELAXED);
	cur_blanket_address_scrub_slots_walked = __atomic_load_n(&shm->stats.blanket_address_scrub_slots_walked, __ATOMIC_RELAXED);
	/* SHADOW structure-aware picker A/B cohort + divergence counters live
	 * in minicorpus_shm rather than kcov_shm because the picker is a
	 * mutate_arg concern, not a kcov-cmp concern.  Guard the load so a
	 * degenerate run with kcov on but minicorpus unmapped does not chase
	 * a NULL pointer; the dump row's delta gate keeps a zero from
	 * polluting the kcov-cmp window output. */
	if (minicorpus_shm != NULL) {
		cur_mut_structured_shadow_samples     = __atomic_load_n(&minicorpus_shm->mut_structured_shadow_samples,     __ATOMIC_RELAXED);
		cur_mut_structured_shadow_divergences = __atomic_load_n(&minicorpus_shm->mut_structured_shadow_divergences, __ATOMIC_RELAXED);
		cur_mut_structured_arm_a_children     = __atomic_load_n(&minicorpus_shm->mut_structured_arm_a_children,     __ATOMIC_RELAXED);
		cur_mut_structured_arm_b_children     = __atomic_load_n(&minicorpus_shm->mut_structured_arm_b_children,     __ATOMIC_RELAXED);
	} else {
		cur_mut_structured_shadow_samples     = 0;
		cur_mut_structured_shadow_divergences = 0;
		cur_mut_structured_arm_a_children     = 0;
		cur_mut_structured_arm_b_children     = 0;
	}

	/* First call: arm the window so any pre-existing counts carried
	 * over from earlier in the run are not mis-attributed to the
	 * first window, mirroring defense_counters_periodic_dump. */
	if (last_dump.tv_sec == 0) {
		last_dump = now;
		prev_records       = cur_records;
		prev_truncated     = cur_truncated;
		prev_bloom_skipped = cur_bloom_skipped;
		prev_strip_skipped = cur_strip_skipped;
		prev_unique        = cur_unique;
		prev_try_get_attempts = cur_try_get_attempts;
		prev_try_get_returned = cur_try_get_returned;
		prev_injected         = cur_injected;
		prev_prop_injected    = cur_prop_injected;
		prev_chaos_suppressed = cur_chaos_suppressed;
		prev_count_oob        = cur_count_oob;
		prev_canary_lock_post = cur_canary_lock_post;
		prev_canary_pre       = cur_canary_pre;
		prev_canary_post      = cur_canary_post;
		prev_reexec_attempts                = cur_reexec_attempts;
		prev_reexec_attempts_with_new_cmp   = cur_reexec_attempts_with_new_cmp;
		prev_reexec_attribution_found       = cur_reexec_attribution_found;
		prev_reexec_attribution_ambiguous   = cur_reexec_attribution_ambiguous;
		prev_reexec_attribution_width_match = cur_reexec_attribution_width_match;
		prev_reexec_new_cmps_total          = cur_reexec_new_cmps_total;
		prev_reexec_skipped_destructive     = cur_reexec_skipped_destructive;
		prev_reexec_skipped_validate_silent = cur_reexec_skipped_validate_silent;
		prev_reexec_window_cap_hit          = cur_reexec_window_cap_hit;
		prev_reexec_pending_dropped         = cur_reexec_pending_dropped;
		prev_reexec_gate_skip_in_reexec     = cur_reexec_gate_skip_in_reexec;
		prev_reexec_gate_skip_disabled      = cur_reexec_gate_skip_disabled;
		prev_reexec_gate_skip_mode          = cur_reexec_gate_skip_mode;
		prev_reexec_gate_skip_chain_mid     = cur_reexec_gate_skip_chain_mid;
		prev_reexec_gate_skip_no_new_cmp    = cur_reexec_gate_skip_no_new_cmp;
		prev_reexec_gate_skip_no_pending    = cur_reexec_gate_skip_no_pending;
		prev_reexec_gate_skip_rate          = cur_reexec_gate_skip_rate;
		prev_reexec_gate_pass               = cur_reexec_gate_pass;
		prev_cmp_parent_calls_enabled       = cur_cmp_parent_calls_enabled;
		prev_cmp_parent_calls_control       = cur_cmp_parent_calls_control;
		prev_cmp_parent_new_cmps_enabled    = cur_cmp_parent_new_cmps_enabled;
		prev_cmp_parent_new_cmps_control    = cur_cmp_parent_new_cmps_control;
		prev_save_reject_nonconst      = cur_save_reject_nonconst;
		prev_save_reject_uninteresting = cur_save_reject_uninteresting;
		prev_save_reject_sentinel      = cur_save_reject_sentinel;
		prev_save_reject_dup           = cur_save_reject_dup;
		prev_save_reject_cap           = cur_save_reject_cap;
		{
			unsigned int cs;
			for (cs = 0; cs < CMP_HINT_CALLSITE_NR; cs++)
				prev_cmp_hint_callsite[cs] = cur_cmp_hint_callsite[cs];
		}
		{
			unsigned int cs;
			for (cs = 0; cs < PROP_INJECTED_CALLSITE_NR; cs++)
				prev_prop_injected_callsite[cs] = cur_prop_injected_callsite[cs];
		}
		prev_cmp_hints_consumed             = cur_cmp_hints_consumed;
		prev_cmp_hint_wins                  = cur_cmp_hint_wins;
		prev_cmp_hint_misses                = cur_cmp_hint_misses;
		prev_cmp_hint_cmp_novelty_wins      = cur_cmp_hint_cmp_novelty_wins;
		prev_cmp_hint_stash_overflow        = cur_cmp_hint_stash_overflow;
		prev_cmp_hint_credit_entry_evicted  = cur_cmp_hint_credit_entry_evicted;
		prev_cmp_recent_inserts             = cur_cmp_recent_inserts;
		prev_cmp_recent_evicts              = cur_cmp_recent_evicts;
		prev_cmp_recent_would_pick          = cur_cmp_recent_would_pick;
		prev_cmp_recent_would_miss          = cur_cmp_recent_would_miss;
		prev_cmp_recent_live_picks          = cur_cmp_recent_live_picks;
		prev_cmp_inject_arm_a_baseline_fires = cur_cmp_inject_arm_a_baseline_fires;
		prev_cmp_inject_arm_b_baseline_fires = cur_cmp_inject_arm_b_baseline_fires;
		prev_cmp_inject_denom_diverged       = cur_cmp_inject_denom_diverged;
		prev_prop_ring_argop_arm_b_fires     = cur_prop_ring_argop_arm_b_fires;
		prev_frontier_blend_samples          = cur_frontier_blend_samples;
		prev_remote_adaptive_samples         = cur_remote_adaptive_samples;
		prev_mut_structured_shadow_divergences = cur_mut_structured_shadow_divergences;
		return;
	}

	elapsed = now.tv_sec - last_dump.tv_sec;
	if (elapsed < DEFENSE_DUMP_INTERVAL_SEC)
		return;

	delta_records       = cur_records       - prev_records;
	delta_truncated     = cur_truncated     - prev_truncated;
	delta_bloom_skipped = cur_bloom_skipped - prev_bloom_skipped;
	delta_strip_skipped = cur_strip_skipped - prev_strip_skipped;
	delta_unique        = cur_unique        - prev_unique;
	delta_try_get_attempts = cur_try_get_attempts - prev_try_get_attempts;
	delta_try_get_returned = cur_try_get_returned - prev_try_get_returned;
	delta_injected         = cur_injected         - prev_injected;
	delta_prop_injected    = cur_prop_injected    - prev_prop_injected;
	delta_chaos_suppressed = cur_chaos_suppressed - prev_chaos_suppressed;
	delta_count_oob        = cur_count_oob        - prev_count_oob;
	delta_canary_lock_post = cur_canary_lock_post - prev_canary_lock_post;
	delta_canary_pre       = cur_canary_pre       - prev_canary_pre;
	delta_canary_post      = cur_canary_post      - prev_canary_post;
	delta_reexec_attempts                = cur_reexec_attempts                - prev_reexec_attempts;
	delta_reexec_attempts_with_new_cmp   = cur_reexec_attempts_with_new_cmp   - prev_reexec_attempts_with_new_cmp;
	delta_reexec_attribution_found       = cur_reexec_attribution_found       - prev_reexec_attribution_found;
	delta_reexec_attribution_ambiguous   = cur_reexec_attribution_ambiguous   - prev_reexec_attribution_ambiguous;
	delta_reexec_attribution_width_match = cur_reexec_attribution_width_match - prev_reexec_attribution_width_match;
	delta_reexec_new_cmps_total          = cur_reexec_new_cmps_total          - prev_reexec_new_cmps_total;
	delta_reexec_skipped_destructive     = cur_reexec_skipped_destructive     - prev_reexec_skipped_destructive;
	delta_reexec_skipped_validate_silent = cur_reexec_skipped_validate_silent - prev_reexec_skipped_validate_silent;
	delta_reexec_window_cap_hit          = cur_reexec_window_cap_hit          - prev_reexec_window_cap_hit;
	delta_reexec_pending_dropped         = cur_reexec_pending_dropped         - prev_reexec_pending_dropped;
	delta_reexec_gate_skip_in_reexec     = cur_reexec_gate_skip_in_reexec     - prev_reexec_gate_skip_in_reexec;
	delta_reexec_gate_skip_disabled      = cur_reexec_gate_skip_disabled      - prev_reexec_gate_skip_disabled;
	delta_reexec_gate_skip_mode          = cur_reexec_gate_skip_mode          - prev_reexec_gate_skip_mode;
	delta_reexec_gate_skip_chain_mid     = cur_reexec_gate_skip_chain_mid     - prev_reexec_gate_skip_chain_mid;
	delta_reexec_gate_skip_no_new_cmp    = cur_reexec_gate_skip_no_new_cmp    - prev_reexec_gate_skip_no_new_cmp;
	delta_reexec_gate_skip_no_pending    = cur_reexec_gate_skip_no_pending    - prev_reexec_gate_skip_no_pending;
	delta_reexec_gate_skip_rate          = cur_reexec_gate_skip_rate          - prev_reexec_gate_skip_rate;
	delta_reexec_gate_pass               = cur_reexec_gate_pass               - prev_reexec_gate_pass;
	delta_cmp_parent_calls_enabled       = cur_cmp_parent_calls_enabled       - prev_cmp_parent_calls_enabled;
	delta_cmp_parent_calls_control       = cur_cmp_parent_calls_control       - prev_cmp_parent_calls_control;
	delta_cmp_parent_new_cmps_enabled    = cur_cmp_parent_new_cmps_enabled    - prev_cmp_parent_new_cmps_enabled;
	delta_cmp_parent_new_cmps_control    = cur_cmp_parent_new_cmps_control    - prev_cmp_parent_new_cmps_control;
	delta_save_reject_nonconst      = cur_save_reject_nonconst      - prev_save_reject_nonconst;
	delta_save_reject_uninteresting = cur_save_reject_uninteresting - prev_save_reject_uninteresting;
	delta_save_reject_sentinel      = cur_save_reject_sentinel      - prev_save_reject_sentinel;
	delta_save_reject_dup           = cur_save_reject_dup           - prev_save_reject_dup;
	delta_save_reject_cap           = cur_save_reject_cap           - prev_save_reject_cap;
	{
		unsigned int cs;
		for (cs = 0; cs < CMP_HINT_CALLSITE_NR; cs++) {
			delta_cmp_hint_callsite[cs] =
				cur_cmp_hint_callsite[cs] - prev_cmp_hint_callsite[cs];
			if (delta_cmp_hint_callsite[cs] != 0)
				any_callsite_delta = true;
		}
	}
	{
		unsigned int cs;
		for (cs = 0; cs < PROP_INJECTED_CALLSITE_NR; cs++) {
			delta_prop_injected_callsite[cs] =
				cur_prop_injected_callsite[cs] - prev_prop_injected_callsite[cs];
			if (delta_prop_injected_callsite[cs] != 0)
				any_prop_callsite_delta = true;
		}
	}
	delta_cmp_hints_consumed             = cur_cmp_hints_consumed             - prev_cmp_hints_consumed;
	delta_cmp_hint_wins                  = cur_cmp_hint_wins                  - prev_cmp_hint_wins;
	delta_cmp_hint_misses                = cur_cmp_hint_misses                - prev_cmp_hint_misses;
	delta_cmp_hint_cmp_novelty_wins      = cur_cmp_hint_cmp_novelty_wins      - prev_cmp_hint_cmp_novelty_wins;
	delta_cmp_hint_stash_overflow        = cur_cmp_hint_stash_overflow        - prev_cmp_hint_stash_overflow;
	delta_cmp_hint_credit_entry_evicted  = cur_cmp_hint_credit_entry_evicted  - prev_cmp_hint_credit_entry_evicted;
	delta_cmp_recent_inserts             = cur_cmp_recent_inserts             - prev_cmp_recent_inserts;
	delta_cmp_recent_evicts              = cur_cmp_recent_evicts              - prev_cmp_recent_evicts;
	delta_cmp_recent_would_pick          = cur_cmp_recent_would_pick          - prev_cmp_recent_would_pick;
	delta_cmp_recent_would_miss          = cur_cmp_recent_would_miss          - prev_cmp_recent_would_miss;
	delta_cmp_recent_live_picks          = cur_cmp_recent_live_picks          - prev_cmp_recent_live_picks;
	delta_cmp_inject_arm_a_baseline_fires = cur_cmp_inject_arm_a_baseline_fires - prev_cmp_inject_arm_a_baseline_fires;
	delta_cmp_inject_arm_b_baseline_fires = cur_cmp_inject_arm_b_baseline_fires - prev_cmp_inject_arm_b_baseline_fires;
	delta_cmp_inject_denom_diverged       = cur_cmp_inject_denom_diverged       - prev_cmp_inject_denom_diverged;
	delta_prop_ring_argop_arm_b_fires     = cur_prop_ring_argop_arm_b_fires     - prev_prop_ring_argop_arm_b_fires;
	delta_frontier_blend_samples          = cur_frontier_blend_samples          - prev_frontier_blend_samples;
	delta_remote_adaptive_samples         = cur_remote_adaptive_samples         - prev_remote_adaptive_samples;
	delta_mut_structured_shadow_divergences = cur_mut_structured_shadow_divergences - prev_mut_structured_shadow_divergences;

	if ((delta_records | delta_truncated | delta_bloom_skipped | delta_strip_skipped |
	     delta_unique | delta_try_get_attempts | delta_try_get_returned |
	     delta_injected | delta_prop_injected |
	     delta_chaos_suppressed | delta_count_oob |
	     delta_canary_lock_post |
	     delta_canary_pre | delta_canary_post |
	     delta_reexec_attempts | delta_reexec_attempts_with_new_cmp |
	     delta_reexec_attribution_found |
	     delta_reexec_attribution_ambiguous | delta_reexec_attribution_width_match |
	     delta_reexec_new_cmps_total |
	     delta_reexec_skipped_destructive | delta_reexec_skipped_validate_silent |
	     delta_reexec_window_cap_hit | delta_reexec_pending_dropped |
	     delta_reexec_gate_skip_in_reexec | delta_reexec_gate_skip_disabled |
	     delta_reexec_gate_skip_mode | delta_reexec_gate_skip_chain_mid |
	     delta_reexec_gate_skip_no_new_cmp | delta_reexec_gate_skip_no_pending |
	     delta_reexec_gate_skip_rate | delta_reexec_gate_pass |
	     delta_cmp_parent_calls_enabled | delta_cmp_parent_calls_control |
	     delta_cmp_parent_new_cmps_enabled | delta_cmp_parent_new_cmps_control |
	     delta_save_reject_nonconst | delta_save_reject_uninteresting |
	     delta_save_reject_sentinel | delta_save_reject_dup |
	     delta_save_reject_cap |
	     delta_cmp_hints_consumed | delta_cmp_hint_wins | delta_cmp_hint_misses |
	     delta_cmp_hint_cmp_novelty_wins | delta_cmp_hint_stash_overflow |
	     delta_cmp_hint_credit_entry_evicted |
	     delta_cmp_recent_inserts | delta_cmp_recent_evicts |
	     delta_cmp_recent_would_pick | delta_cmp_recent_would_miss |
	     delta_cmp_recent_live_picks |
	     delta_cmp_inject_arm_a_baseline_fires |
	     delta_cmp_inject_arm_b_baseline_fires |
	     delta_cmp_inject_denom_diverged |
	     delta_prop_ring_argop_arm_b_fires |
	     delta_remote_adaptive_samples |
	     delta_mut_structured_shadow_divergences) != 0 ||
	    any_callsite_delta || any_prop_callsite_delta) {
		stats_log_write("KCOV CMP stats over last %lds:\n", elapsed);

		if (delta_records) {
			unsigned long rate_milli = (delta_records * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_records_collected", delta_records,
					rate_milli / 1000, rate_milli % 1000, cur_records);
		}
		if (delta_truncated) {
			unsigned long rate_milli = (delta_truncated * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_trace_truncated", delta_truncated,
					rate_milli / 1000, rate_milli % 1000, cur_truncated);
		}
		if (delta_bloom_skipped) {
			unsigned long rate_milli = (delta_bloom_skipped * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_bloom_skipped", delta_bloom_skipped,
					rate_milli / 1000, rate_milli % 1000, cur_bloom_skipped);
		}
		if (delta_strip_skipped) {
			unsigned long rate_milli = (delta_strip_skipped * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_strip_skipped", delta_strip_skipped,
					rate_milli / 1000, rate_milli % 1000, cur_strip_skipped);
		}
		if (delta_unique) {
			unsigned long rate_milli = (delta_unique * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_unique_inserts", delta_unique,
					rate_milli / 1000, rate_milli % 1000, cur_unique);
		}
		if (delta_save_reject_nonconst) {
			unsigned long rate_milli = (delta_save_reject_nonconst * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_save_reject_nonconst", delta_save_reject_nonconst,
					rate_milli / 1000, rate_milli % 1000, cur_save_reject_nonconst);
		}
		if (delta_save_reject_uninteresting) {
			unsigned long rate_milli = (delta_save_reject_uninteresting * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_save_reject_uninteresting", delta_save_reject_uninteresting,
					rate_milli / 1000, rate_milli % 1000, cur_save_reject_uninteresting);
		}
		if (delta_save_reject_sentinel) {
			unsigned long rate_milli = (delta_save_reject_sentinel * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_save_reject_sentinel", delta_save_reject_sentinel,
					rate_milli / 1000, rate_milli % 1000, cur_save_reject_sentinel);
		}
		if (delta_save_reject_dup) {
			unsigned long rate_milli = (delta_save_reject_dup * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_save_reject_dup", delta_save_reject_dup,
					rate_milli / 1000, rate_milli % 1000, cur_save_reject_dup);
		}
		if (delta_save_reject_cap) {
			unsigned long rate_milli = (delta_save_reject_cap * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_save_reject_cap", delta_save_reject_cap,
					rate_milli / 1000, rate_milli % 1000, cur_save_reject_cap);
		}
		if (delta_try_get_attempts) {
			unsigned long rate_milli = (delta_try_get_attempts * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_try_get_attempts", delta_try_get_attempts,
					rate_milli / 1000, rate_milli % 1000, cur_try_get_attempts);
		}
		if (delta_try_get_returned) {
			unsigned long rate_milli = (delta_try_get_returned * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_try_get_returned", delta_try_get_returned,
					rate_milli / 1000, rate_milli % 1000, cur_try_get_returned);
		}
		if (delta_injected) {
			unsigned long rate_milli = (delta_injected * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_injected", delta_injected,
					rate_milli / 1000, rate_milli % 1000, cur_injected);
		}
		if (delta_prop_injected) {
			unsigned long rate_milli = (delta_prop_injected * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"propagation_injected", delta_prop_injected,
					rate_milli / 1000, rate_milli % 1000, cur_prop_injected);
		}
		if (delta_chaos_suppressed) {
			unsigned long rate_milli = (delta_chaos_suppressed * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu, chaos_active=%d)\n",
					"cmp_hints_chaos_suppressed", delta_chaos_suppressed,
					rate_milli / 1000, rate_milli % 1000, cur_chaos_suppressed,
					cmp_hints_chaos_query() ? 1 : 0);
		}
		/* Wild-write detection: any non-zero delta is news, and the
		 * 0/s rate noise of a one-shot stomp is fine -- the canary
		 * counters surface a real corruption channel, not a hot-path
		 * statistic, so the same row format is used as the rest. */
		if (delta_count_oob) {
			unsigned long rate_milli = (delta_count_oob * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_count_oob", delta_count_oob,
					rate_milli / 1000, rate_milli % 1000, cur_count_oob);
		}
		if (delta_canary_lock_post) {
			unsigned long rate_milli = (delta_canary_lock_post * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_canary_lock_post_corrupt", delta_canary_lock_post,
					rate_milli / 1000, rate_milli % 1000, cur_canary_lock_post);
		}
		if (delta_canary_pre) {
			unsigned long rate_milli = (delta_canary_pre * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_canary_pre_corrupt", delta_canary_pre,
					rate_milli / 1000, rate_milli % 1000, cur_canary_pre);
		}
		if (delta_canary_post) {
			unsigned long rate_milli = (delta_canary_post * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_canary_post_corrupt", delta_canary_post,
					rate_milli / 1000, rate_milli % 1000, cur_canary_post);
		}
		if (delta_reexec_attempts) {
			unsigned long rate_milli = (delta_reexec_attempts * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_attempts", delta_reexec_attempts,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_attempts);
		}
		if (delta_reexec_attempts_with_new_cmp) {
			unsigned long rate_milli = (delta_reexec_attempts_with_new_cmp * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_attempts_with_new_cmp", delta_reexec_attempts_with_new_cmp,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_attempts_with_new_cmp);
		}
		if (delta_reexec_attribution_found) {
			unsigned long rate_milli = (delta_reexec_attribution_found * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_attribution_found", delta_reexec_attribution_found,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_attribution_found);
		}
		if (delta_reexec_attribution_ambiguous) {
			unsigned long rate_milli = (delta_reexec_attribution_ambiguous * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_attribution_ambiguous", delta_reexec_attribution_ambiguous,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_attribution_ambiguous);
		}
		if (delta_reexec_attribution_width_match) {
			unsigned long rate_milli = (delta_reexec_attribution_width_match * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_attribution_width_match", delta_reexec_attribution_width_match,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_attribution_width_match);
		}
		if (delta_reexec_new_cmps_total) {
			unsigned long rate_milli = (delta_reexec_new_cmps_total * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_new_cmps_total", delta_reexec_new_cmps_total,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_new_cmps_total);
		}
		if (delta_reexec_skipped_destructive) {
			unsigned long rate_milli = (delta_reexec_skipped_destructive * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_skipped_destructive", delta_reexec_skipped_destructive,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_skipped_destructive);
		}
		if (delta_reexec_skipped_validate_silent) {
			unsigned long rate_milli = (delta_reexec_skipped_validate_silent * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_skipped_validate_silent", delta_reexec_skipped_validate_silent,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_skipped_validate_silent);
		}
		if (delta_reexec_window_cap_hit) {
			unsigned long rate_milli = (delta_reexec_window_cap_hit * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_window_cap_hit", delta_reexec_window_cap_hit,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_window_cap_hit);
		}
		if (delta_reexec_pending_dropped) {
			unsigned long rate_milli = (delta_reexec_pending_dropped * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_pending_dropped", delta_reexec_pending_dropped,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_pending_dropped);
		}
		/* Re-exec gate skip-reason breakdown.  Counters are mutually
		 * exclusive: every dispatch_step that reaches the tail bumps
		 * exactly one of {skip_in_reexec, skip_disabled, skip_mode,
		 * skip_chain_mid, skip_no_new_cmp, skip_no_pending, skip_rate,
		 * pass}.  The sum across the eight is the parent-call
		 * population the gate samples from -- read the per-reason
		 * fractions to see why reexec_attribution_found shrinks to
		 * reexec_attempts (rate-gate skip vs destructive vs pending-
		 * full vs pass), instead of inferring it from a single delta.
		 * Skip-row order mirrors the evaluation order in
		 * random-syscall.c so the funnel reads top-to-bottom. */
		if (delta_reexec_gate_skip_in_reexec) {
			unsigned long rate_milli = (delta_reexec_gate_skip_in_reexec * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_gate_skip_in_reexec", delta_reexec_gate_skip_in_reexec,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_gate_skip_in_reexec);
		}
		if (delta_reexec_gate_skip_disabled) {
			unsigned long rate_milli = (delta_reexec_gate_skip_disabled * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_gate_skip_disabled", delta_reexec_gate_skip_disabled,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_gate_skip_disabled);
		}
		if (delta_reexec_gate_skip_mode) {
			unsigned long rate_milli = (delta_reexec_gate_skip_mode * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_gate_skip_mode", delta_reexec_gate_skip_mode,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_gate_skip_mode);
		}
		if (delta_reexec_gate_skip_chain_mid) {
			unsigned long rate_milli = (delta_reexec_gate_skip_chain_mid * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_gate_skip_chain_mid", delta_reexec_gate_skip_chain_mid,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_gate_skip_chain_mid);
		}
		if (delta_reexec_gate_skip_no_new_cmp) {
			unsigned long rate_milli = (delta_reexec_gate_skip_no_new_cmp * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_gate_skip_no_new_cmp", delta_reexec_gate_skip_no_new_cmp,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_gate_skip_no_new_cmp);
		}
		if (delta_reexec_gate_skip_no_pending) {
			unsigned long rate_milli = (delta_reexec_gate_skip_no_pending * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_gate_skip_no_pending", delta_reexec_gate_skip_no_pending,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_gate_skip_no_pending);
		}
		if (delta_reexec_gate_skip_rate) {
			unsigned long rate_milli = (delta_reexec_gate_skip_rate * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_gate_skip_rate", delta_reexec_gate_skip_rate,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_gate_skip_rate);
		}
		if (delta_reexec_gate_pass) {
			unsigned long rate_milli = (delta_reexec_gate_pass * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_gate_pass", delta_reexec_gate_pass,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_gate_pass);
		}
		if (delta_cmp_parent_calls_enabled) {
			unsigned long rate_milli = (delta_cmp_parent_calls_enabled * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_parent_calls_enabled", delta_cmp_parent_calls_enabled,
					rate_milli / 1000, rate_milli % 1000, cur_cmp_parent_calls_enabled);
		}
		if (delta_cmp_parent_calls_control) {
			unsigned long rate_milli = (delta_cmp_parent_calls_control * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_parent_calls_control", delta_cmp_parent_calls_control,
					rate_milli / 1000, rate_milli % 1000, cur_cmp_parent_calls_control);
		}
		if (delta_cmp_parent_new_cmps_enabled) {
			unsigned long rate_milli = (delta_cmp_parent_new_cmps_enabled * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_parent_new_cmps_enabled", delta_cmp_parent_new_cmps_enabled,
					rate_milli / 1000, rate_milli % 1000, cur_cmp_parent_new_cmps_enabled);
		}
		if (delta_cmp_parent_new_cmps_control) {
			unsigned long rate_milli = (delta_cmp_parent_new_cmps_control * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_parent_new_cmps_control", delta_cmp_parent_new_cmps_control,
					rate_milli / 1000, rate_milli % 1000, cur_cmp_parent_new_cmps_control);
		}
		if (any_callsite_delta) {
			static const char * const callsite_names[CMP_HINT_CALLSITE_NR] = {
				[CMP_HINT_CALLSITE_ARG_OP]          = "ARG_OP",
				[CMP_HINT_CALLSITE_ARG_LIST]        = "ARG_LIST",
				[CMP_HINT_CALLSITE_ARG_UNDEFINED]   = "ARG_UNDEFINED",
				[CMP_HINT_CALLSITE_ARG_STRUCT_SIZE] = "ARG_STRUCT_SIZE",
				[CMP_HINT_CALLSITE_STRUCT_FIELD]    = "STRUCT_FIELD",
				[CMP_HINT_CALLSITE_OTHER]           = "OTHER",
			};
			unsigned int cs;

			stats_log_write("  cmp_hint_callsite_injected (per-callsite delta / cumulative):\n");
			for (cs = 0; cs < CMP_HINT_CALLSITE_NR; cs++) {
				if (delta_cmp_hint_callsite[cs] == 0 &&
				    cur_cmp_hint_callsite[cs] == 0)
					continue;
				stats_log_write("    %-20s +%lu  (total %lu)\n",
						callsite_names[cs],
						delta_cmp_hint_callsite[cs],
						cur_cmp_hint_callsite[cs]);
			}
		}
		if (any_prop_callsite_delta) {
			static const char * const prop_callsite_names[PROP_INJECTED_CALLSITE_NR] = {
				[PROP_INJECTED_CALLSITE_ARG_OP]        = "ARG_OP",
				[PROP_INJECTED_CALLSITE_ARG_UNDEFINED] = "ARG_UNDEFINED",
			};
			unsigned int cs;

			stats_log_write("  propagation_injected_callsite (per-callsite delta / cumulative):\n");
			for (cs = 0; cs < PROP_INJECTED_CALLSITE_NR; cs++) {
				if (delta_prop_injected_callsite[cs] == 0 &&
				    cur_prop_injected_callsite[cs] == 0)
					continue;
				stats_log_write("    %-20s +%lu  (total %lu)\n",
						prop_callsite_names[cs],
						delta_prop_injected_callsite[cs],
						cur_prop_injected_callsite[cs]);
			}
		}
		/* SHADOW per-entry feedback scoring counters
		 * ([11-feedback-loop] PHASE 4).  Live pool selection is
		 * uniform here -- these counters record outcomes for a future
		 * A/B-gated live-pick weight to read.  cmp_hint_wins /
		 * cmp_hint_misses are PC-edge only; cmp_hint_cmp_novelty_wins
		 * is the SEPARATE CMP-mode novelty channel (kept out of the
		 * PC-edge score). */
		if (delta_cmp_hints_consumed) {
			unsigned long rate_milli = (delta_cmp_hints_consumed * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_consumed", delta_cmp_hints_consumed,
					rate_milli / 1000, rate_milli % 1000, cur_cmp_hints_consumed);
		}
		if (delta_cmp_hint_wins) {
			unsigned long rate_milli = (delta_cmp_hint_wins * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hint_wins", delta_cmp_hint_wins,
					rate_milli / 1000, rate_milli % 1000, cur_cmp_hint_wins);
		}
		if (delta_cmp_hint_misses) {
			unsigned long rate_milli = (delta_cmp_hint_misses * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hint_misses", delta_cmp_hint_misses,
					rate_milli / 1000, rate_milli % 1000, cur_cmp_hint_misses);
		}
		if (delta_cmp_hint_cmp_novelty_wins) {
			unsigned long rate_milli = (delta_cmp_hint_cmp_novelty_wins * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hint_cmp_novelty_wins",
					delta_cmp_hint_cmp_novelty_wins,
					rate_milli / 1000, rate_milli % 1000,
					cur_cmp_hint_cmp_novelty_wins);
		}
		if (delta_cmp_hint_stash_overflow) {
			unsigned long rate_milli = (delta_cmp_hint_stash_overflow * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hint_stash_overflow",
					delta_cmp_hint_stash_overflow,
					rate_milli / 1000, rate_milli % 1000,
					cur_cmp_hint_stash_overflow);
		}
		if (delta_cmp_hint_credit_entry_evicted) {
			unsigned long rate_milli = (delta_cmp_hint_credit_entry_evicted * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hint_credit_entry_evicted",
					delta_cmp_hint_credit_entry_evicted,
					rate_milli / 1000, rate_milli % 1000,
					cur_cmp_hint_credit_entry_evicted);
		}
		/* SHADOW recent-CMP-pool tier: inserts/evicts measure the
		 * absorbed-but-otherwise-dropped throughput; would_pick /
		 * would_miss is the plateau-window try_get population the
		 * recent-first arm would sample from (legible from the default
		 * durable-first run); live_picks stays at zero until the A/B
		 * flag is flipped to recent-first; promotions is the recording-
		 * only conversion counter the follow-up commit will route into
		 * a recent->durable promotion.  Without these rows the tier
		 * looks identical to "disabled" in the logs -- a non-zero
		 * would_pick rate with cmp_recent_inserts == 0 is the empty-
		 * ring signature; a healthy non-zero would_pick alongside
		 * inserts says the recent-first arm has real signal to draw
		 * from. */
		if (delta_cmp_recent_inserts) {
			unsigned long rate_milli = (delta_cmp_recent_inserts * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_recent_inserts", delta_cmp_recent_inserts,
					rate_milli / 1000, rate_milli % 1000, cur_cmp_recent_inserts);
		}
		if (delta_cmp_recent_evicts) {
			unsigned long rate_milli = (delta_cmp_recent_evicts * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_recent_evicts", delta_cmp_recent_evicts,
					rate_milli / 1000, rate_milli % 1000, cur_cmp_recent_evicts);
		}
		if (delta_cmp_recent_would_pick) {
			unsigned long rate_milli = (delta_cmp_recent_would_pick * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_recent_would_pick", delta_cmp_recent_would_pick,
					rate_milli / 1000, rate_milli % 1000, cur_cmp_recent_would_pick);
		}
		if (delta_cmp_recent_would_miss) {
			unsigned long rate_milli = (delta_cmp_recent_would_miss * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_recent_would_miss", delta_cmp_recent_would_miss,
					rate_milli / 1000, rate_milli % 1000, cur_cmp_recent_would_miss);
		}
		if (delta_cmp_recent_live_picks) {
			unsigned long rate_milli = (delta_cmp_recent_live_picks * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_recent_live_picks", delta_cmp_recent_live_picks,
					rate_milli / 1000, rate_milli % 1000, cur_cmp_recent_live_picks);
		}
		/* A/B baseline inject denom (Arm A = 16, Arm B = 12).  Print
		 * the realised cohort split + per-arm baseline-fire deltas +
		 * the per-call divergence count so the operator can size the
		 * A/B effect on PC-edge yield against population-normalised
		 * fire rates without recomputing from cmp_hint_callsite[]. */
		if (delta_cmp_inject_arm_a_baseline_fires) {
			unsigned long rate_milli = (delta_cmp_inject_arm_a_baseline_fires * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu, children %u)\n",
					"cmp_inject_arm_a_baseline_fires",
					delta_cmp_inject_arm_a_baseline_fires,
					rate_milli / 1000, rate_milli % 1000,
					cur_cmp_inject_arm_a_baseline_fires,
					cur_cmp_inject_arm_a_children);
		}
		if (delta_cmp_inject_arm_b_baseline_fires) {
			unsigned long rate_milli = (delta_cmp_inject_arm_b_baseline_fires * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu, children %u)\n",
					"cmp_inject_arm_b_baseline_fires",
					delta_cmp_inject_arm_b_baseline_fires,
					rate_milli / 1000, rate_milli % 1000,
					cur_cmp_inject_arm_b_baseline_fires,
					cur_cmp_inject_arm_b_children);
		}
		if (delta_cmp_inject_denom_diverged) {
			unsigned long rate_milli = (delta_cmp_inject_denom_diverged * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_inject_denom_diverged",
					delta_cmp_inject_denom_diverged,
					rate_milli / 1000, rate_milli % 1000,
					cur_cmp_inject_denom_diverged);
		}
		/* A/B handle_arg_op prop_ring cohort (Arm A = no pull, Arm B =
		 * low-prob pull).  Print the realised cohort split + the Arm B
		 * fire delta so the operator can size the per-row contribution
		 * to propagation_injected against the population-normalised fire
		 * rate.  Arm A has no symmetric fire counter by design (control
		 * arm skips the pull entirely). */
		if (delta_prop_ring_argop_arm_b_fires) {
			unsigned long rate_milli = (delta_prop_ring_argop_arm_b_fires * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu, children a=%u b=%u)\n",
					"prop_ring_argop_arm_b_fires",
					delta_prop_ring_argop_arm_b_fires,
					rate_milli / 1000, rate_milli % 1000,
					cur_prop_ring_argop_arm_b_fires,
					cur_prop_ring_argop_arm_a_children,
					cur_prop_ring_argop_arm_b_children);
		}
		/* frontier_cold_weight blend A/B cohort (Arm A = return historical
		 * OLD weight, Arm B = promote blended weight including the
		 * transition term to the picker).  Both arms fire the would-be
		 * divergence sampler frontier_blend_samples in lock-step, so the
		 * delta gate uses that fire counter and the row prints the
		 * realised cohort split as the denominator the operator
		 * normalises the live Arm B promotion against.  Neither arm has
		 * a per-arm fire counter by design -- the blend logic itself is
		 * untouched. */
		if (delta_frontier_blend_samples) {
			unsigned long rate_milli = (delta_frontier_blend_samples * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu, children a=%u b=%u)\n",
					"frontier_blend_samples",
					delta_frontier_blend_samples,
					rate_milli / 1000, rate_milli % 1000,
					cur_frontier_blend_samples,
					cur_frontier_blend_arm_a_children,
					cur_frontier_blend_arm_b_children);
		}
		/* Adaptive remote-KCOV mode A/B cohort (Arm A = static remote-
		 * mode policy / byte-identical to pre-row baseline, Arm B = the
		 * adaptive demote/promote disposition from
		 * remote_adaptive_decide() substituted as the live remote_mode).
		 * Both arms feed the would-be disposition counters in lock-
		 * step, so the headline samples row uses the realised cohort
		 * split as the denominator the operator normalises the Arm-B-
		 * only live divergence against.  The three sub-rows print
		 * unconditionally inside the gate so the breakdown is visible
		 * even on windows where one disposition is zero (the absence
		 * itself is the diagnostic signal). */
		if (delta_remote_adaptive_samples) {
			unsigned long rate_milli = (delta_remote_adaptive_samples * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu, children a=%u b=%u)\n",
					"remote_adaptive_samples",
					delta_remote_adaptive_samples,
					rate_milli / 1000, rate_milli % 1000,
					cur_remote_adaptive_samples,
					cur_remote_adaptive_arm_a_children,
					cur_remote_adaptive_arm_b_children);
			stats_log_write("  %-32s total %lu\n",
					"remote_adaptive_would_demote",
					cur_remote_adaptive_would_demote);
			stats_log_write("  %-32s total %lu\n",
					"remote_adaptive_would_promote",
					cur_remote_adaptive_would_promote);
			stats_log_write("  %-32s total %lu\n",
					"remote_adaptive_would_force",
					cur_remote_adaptive_would_force);
			stats_log_write("  %-32s total %lu\n",
					"remote_adaptive_would_gate_promote",
					cur_remote_adaptive_would_gate_promote);
			stats_log_write("  %-32s total %lu\n",
					"remote_adaptive_agree",
					cur_remote_adaptive_agree);
		}
		/* SHADOW per-arg ownership-metadata sidecar + blanket-scrub
		 * contradiction census.  Telemetry only -- the arg_meta_init
		 * seed pass and blanket_address_scrub walk are byte-unchanged;
		 * no live decision reads dir/owner/flags.  Cumulative totals
		 * (no per-window delta) match the remote_adaptive_would_*
		 * neighbours above: the shadow PROOF here is the ratio between
		 * the with_meta / without_meta rows and the destroy_in /
		 * preserve_out skew the operator is sizing future metadata-
		 * aware scrub coverage against.  Unconditional render so the
		 * baseline (all zero until per-generator coverage populates
		 * dir/owner) is itself visible. */
		stats_log_write("  %-32s total %lu\n",
				"blanket_address_scrub_slots_walked",
				cur_blanket_address_scrub_slots_walked);
		stats_log_write("  %-32s total %lu\n",
				"arg_meta_addr_with_meta",
				cur_arg_meta_addr_with_meta);
		stats_log_write("  %-32s total %lu\n",
				"arg_meta_addr_without_meta",
				cur_arg_meta_addr_without_meta);
		stats_log_write("  %-32s total %lu\n",
				"arg_meta_argtype_stale",
				cur_arg_meta_argtype_stale);
		stats_log_write("  %-32s total %lu\n",
				"arg_meta_scrub_would_destroy_in",
				cur_arg_meta_scrub_would_destroy_in);
		stats_log_write("  %-32s total %lu\n",
				"arg_meta_scrub_would_preserve_out",
				cur_arg_meta_scrub_would_preserve_out);
		/* SHADOW structure-aware picker A/B cohort (Arm A = no shadow
		 * draw / RNG byte-identical to pre-shadow control, Arm B =
		 * doubled-pool shadow draw on structured-eligible slots).  Print
		 * the Arm B divergence delta paired with the cumulative sample
		 * base and the realised cohort split so the operator can size
		 * the shadow's per-window steer-rate against the population-
		 * normalised denominator.  Arm A has no symmetric divergence
		 * counter by design (control arm skips the shadow draw entirely);
		 * samples and divergences are both Arm-B-only accumulators. */
		if (delta_mut_structured_shadow_divergences) {
			unsigned long rate_milli = (delta_mut_structured_shadow_divergences * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu, samples %lu, children a=%u b=%u)\n",
					"mut_structured_shadow_divergences",
					delta_mut_structured_shadow_divergences,
					rate_milli / 1000, rate_milli % 1000,
					cur_mut_structured_shadow_divergences,
					cur_mut_structured_shadow_samples,
					cur_mut_structured_arm_a_children,
					cur_mut_structured_arm_b_children);
		}
	}

	/*
	 * SHADOW typed-CMP-hypothesis store render block.
	 *
	 * Self-contained mini-section so the skeleton's all-zero counters do
	 * not need to be folded into the giant delta-gate above.  All eleven
	 * counters read zero in this commit: the observation hook is a no-op
	 * and no inference / consumer / feedback path bumps any of them yet.
	 * The renders fire once the follow-up units land and the deltas
	 * become non-zero; the section header itself is gated on any-delta
	 * so the log stays quiet in the meantime.
	 */
	{
		static unsigned long prev_hyp_observations;
		static unsigned long prev_hyp_inserted;
		static unsigned long prev_hyp_pool_full;
		static unsigned long prev_hyp_pool_overflow;
		static unsigned long prev_hyp_kind_full;
		static unsigned long prev_hyp_consumed;
		static unsigned long prev_hyp_pc_wins;
		static unsigned long prev_hyp_transition_wins;
		static unsigned long prev_hyp_cmp_novelty_wins;
		static unsigned long prev_hyp_misses;
		static unsigned long prev_hyp_disabled_skips;
		static unsigned long prev_hyp_corpus_save;
		static unsigned long prev_hyp_destructive;
		static unsigned long prev_hyp_context_skip;
		unsigned long cur_hyp_observations =
			__atomic_load_n(&kcov_shm->cmp_hyp_observations, __ATOMIC_RELAXED);
		unsigned long cur_hyp_inserted =
			__atomic_load_n(&kcov_shm->cmp_hyp_inserted, __ATOMIC_RELAXED);
		unsigned long cur_hyp_pool_full =
			__atomic_load_n(&kcov_shm->cmp_hyp_pool_full, __ATOMIC_RELAXED);
		unsigned long cur_hyp_pool_overflow =
			__atomic_load_n(&kcov_shm->cmp_hyp_pool_overflow, __ATOMIC_RELAXED);
		unsigned long cur_hyp_kind_full =
			__atomic_load_n(&kcov_shm->cmp_hyp_kind_full, __ATOMIC_RELAXED);
		unsigned long cur_hyp_consumed =
			__atomic_load_n(&kcov_shm->cmp_hyp_consumed, __ATOMIC_RELAXED);
		unsigned long cur_hyp_pc_wins =
			__atomic_load_n(&kcov_shm->cmp_hyp_pc_wins, __ATOMIC_RELAXED);
		unsigned long cur_hyp_transition_wins =
			__atomic_load_n(&kcov_shm->cmp_hyp_transition_wins, __ATOMIC_RELAXED);
		unsigned long cur_hyp_cmp_novelty_wins =
			__atomic_load_n(&kcov_shm->cmp_hyp_cmp_novelty_wins, __ATOMIC_RELAXED);
		unsigned long cur_hyp_misses =
			__atomic_load_n(&kcov_shm->cmp_hyp_misses, __ATOMIC_RELAXED);
		unsigned long cur_hyp_disabled_skips =
			__atomic_load_n(&kcov_shm->cmp_hyp_disabled_skips, __ATOMIC_RELAXED);
		unsigned long cur_hyp_corpus_save =
			__atomic_load_n(&kcov_shm->cmp_hyp_corpus_save, __ATOMIC_RELAXED);
		unsigned long cur_hyp_destructive =
			__atomic_load_n(&kcov_shm->cmp_hyp_destructive, __ATOMIC_RELAXED);
		unsigned long cur_hyp_context_skip =
			__atomic_load_n(&kcov_shm->cmp_hyp_context_skip, __ATOMIC_RELAXED);
		unsigned long delta_hyp_observations = cur_hyp_observations - prev_hyp_observations;
		unsigned long delta_hyp_inserted = cur_hyp_inserted - prev_hyp_inserted;
		unsigned long delta_hyp_pool_full = cur_hyp_pool_full - prev_hyp_pool_full;
		unsigned long delta_hyp_pool_overflow = cur_hyp_pool_overflow - prev_hyp_pool_overflow;
		unsigned long delta_hyp_kind_full = cur_hyp_kind_full - prev_hyp_kind_full;
		unsigned long delta_hyp_consumed = cur_hyp_consumed - prev_hyp_consumed;
		unsigned long delta_hyp_pc_wins = cur_hyp_pc_wins - prev_hyp_pc_wins;
		unsigned long delta_hyp_transition_wins = cur_hyp_transition_wins - prev_hyp_transition_wins;
		unsigned long delta_hyp_cmp_novelty_wins = cur_hyp_cmp_novelty_wins - prev_hyp_cmp_novelty_wins;
		unsigned long delta_hyp_misses = cur_hyp_misses - prev_hyp_misses;
		unsigned long delta_hyp_disabled_skips = cur_hyp_disabled_skips - prev_hyp_disabled_skips;
		unsigned long delta_hyp_corpus_save = cur_hyp_corpus_save - prev_hyp_corpus_save;
		unsigned long delta_hyp_destructive = cur_hyp_destructive - prev_hyp_destructive;
		unsigned long delta_hyp_context_skip = cur_hyp_context_skip - prev_hyp_context_skip;

		if ((delta_hyp_observations | delta_hyp_inserted | delta_hyp_pool_full |
		     delta_hyp_pool_overflow | delta_hyp_kind_full |
		     delta_hyp_consumed | delta_hyp_pc_wins |
		     delta_hyp_transition_wins | delta_hyp_cmp_novelty_wins |
		     delta_hyp_misses | delta_hyp_disabled_skips |
		     delta_hyp_corpus_save | delta_hyp_destructive |
		     delta_hyp_context_skip) != 0) {
			stats_log_write("KCOV CMP hyp shadow stats over last %lds:\n", elapsed);
			stats_log_write("  %-32s +%lu  (total %lu)\n",
					"cmp_hyp_observations", delta_hyp_observations, cur_hyp_observations);
			stats_log_write("  %-32s +%lu  (total %lu)\n",
					"cmp_hyp_inserted", delta_hyp_inserted, cur_hyp_inserted);
			stats_log_write("  %-32s +%lu  (total %lu)\n",
					"cmp_hyp_pool_full", delta_hyp_pool_full, cur_hyp_pool_full);
			stats_log_write("  %-32s +%lu  (total %lu)\n",
					"cmp_hyp_pool_overflow",
					delta_hyp_pool_overflow, cur_hyp_pool_overflow);
			stats_log_write("  %-32s +%lu  (total %lu)\n",
					"cmp_hyp_kind_full", delta_hyp_kind_full, cur_hyp_kind_full);
			stats_log_write("  %-32s +%lu  (total %lu)\n",
					"cmp_hyp_consumed", delta_hyp_consumed, cur_hyp_consumed);
			stats_log_write("  %-32s +%lu  (total %lu)\n",
					"cmp_hyp_pc_wins", delta_hyp_pc_wins, cur_hyp_pc_wins);
			stats_log_write("  %-32s +%lu  (total %lu)\n",
					"cmp_hyp_transition_wins",
					delta_hyp_transition_wins, cur_hyp_transition_wins);
			stats_log_write("  %-32s +%lu  (total %lu)\n",
					"cmp_hyp_cmp_novelty_wins",
					delta_hyp_cmp_novelty_wins, cur_hyp_cmp_novelty_wins);
			stats_log_write("  %-32s +%lu  (total %lu)\n",
					"cmp_hyp_misses", delta_hyp_misses, cur_hyp_misses);
			stats_log_write("  %-32s +%lu  (total %lu)\n",
					"cmp_hyp_disabled_skips",
					delta_hyp_disabled_skips, cur_hyp_disabled_skips);
			stats_log_write("  %-32s +%lu  (total %lu)\n",
					"cmp_hyp_corpus_save",
					delta_hyp_corpus_save, cur_hyp_corpus_save);
			stats_log_write("  %-32s +%lu  (total %lu)\n",
					"cmp_hyp_destructive",
					delta_hyp_destructive, cur_hyp_destructive);
			stats_log_write("  %-32s +%lu  (total %lu)\n",
					"cmp_hyp_context_skip",
					delta_hyp_context_skip, cur_hyp_context_skip);

			/* Per-kind census: accepted (inserted_by_kind) vs dropped
			 * at the per-kind sub-cap (kind_full_by_kind) vs dropped
			 * at the total pool cap (pool_full_by_kind -- an attempted
			 * hypothesis of this kind was rejected because the TOTAL
			 * pool was full, NOT that this kind filled the pool).
			 * Surfaces which kind dominates cmp_hyp_kind_full so the
			 * CMP_HYP_PER_KIND cap can be tuned at the right kind, and
			 * which kinds are most often the would-be insertion when
			 * CMP_HYP_PER_SYSCALL is reached. */
			{
				static const char * const kind_labels[CMP_HYP_KIND_NR] = {
					"exact", "range", "boundary", "bitmask",
					"enum_family", "alignment", "length",
					"foreign_value",
				};
				static unsigned long prev_hyp_ins_kind[CMP_HYP_KIND_NR];
				static unsigned long prev_hyp_full_kind[CMP_HYP_KIND_NR];
				static unsigned long prev_hyp_pool_full_kind[CMP_HYP_KIND_NR];
				unsigned int k;

				for (k = 0; k < CMP_HYP_KIND_NR; k++) {
					unsigned long cur_ins = __atomic_load_n(
						&kcov_shm->cmp_hyp_inserted_by_kind[k],
						__ATOMIC_RELAXED);
					unsigned long cur_full = __atomic_load_n(
						&kcov_shm->cmp_hyp_kind_full_by_kind[k],
						__ATOMIC_RELAXED);
					unsigned long cur_pool_full = __atomic_load_n(
						&kcov_shm->cmp_hyp_pool_full_by_kind[k],
						__ATOMIC_RELAXED);

					stats_log_write(
						"  cmp_hyp[%-13s] inserted +%lu (total %lu)  kind_full +%lu (total %lu)  pool_full +%lu (total %lu)\n",
						kind_labels[k],
						cur_ins - prev_hyp_ins_kind[k], cur_ins,
						cur_full - prev_hyp_full_kind[k], cur_full,
						cur_pool_full - prev_hyp_pool_full_kind[k], cur_pool_full);
					prev_hyp_ins_kind[k] = cur_ins;
					prev_hyp_full_kind[k] = cur_full;
					prev_hyp_pool_full_kind[k] = cur_pool_full;
				}
			}

			/* Per-kind census of typed-hypothesis consumes.  Bumped in
			 * lock-step with the scalar cmp_hyp_consumed from
			 * cmp_hyp_credit_consume(); sum across kinds equals
			 * cmp_hyp_consumed modulo concurrent sampling.  Paired
			 * with cmp_hyp_inserted_by_kind this shows, per kind, the
			 * share of insertions the typed consumer is pulling. */
			{
				static const char * const kind_labels[CMP_HYP_KIND_NR] = {
					"exact", "range", "boundary", "bitmask",
					"enum_family", "alignment", "length",
					"foreign_value",
				};
				static unsigned long prev_hyp_consumed_kind[CMP_HYP_KIND_NR];
				unsigned int k;

				for (k = 0; k < CMP_HYP_KIND_NR; k++) {
					unsigned long cur_cons = __atomic_load_n(
						&kcov_shm->cmp_hyp_consumed_by_kind[k],
						__ATOMIC_RELAXED);

					stats_log_write(
						"  cmp_hyp[%-13s] consumed +%lu (total %lu)\n",
						kind_labels[k],
						cur_cons - prev_hyp_consumed_kind[k], cur_cons);
					prev_hyp_consumed_kind[k] = cur_cons;
				}
			}

			/* Picker decision census by h->state.  Bumped from
			 * cmp_hyp_would_pick_locked() on every non-NULL
			 * return: PROMOTED should dominate steady-state,
			 * OBSERVED holds the cold-site share, DEMOTED
			 * reflects the 1/CMP_HYP_DEMOTED_RETRY_DENOM
			 * re-roll surfacing.  Companion counters:
			 * skipped_retired tallies RETIRED slots walked past;
			 * demoted_reroll_picked tallies fired re-rolls.
			 * Together these are the directly-measurable proof
			 * that the state-aware picker is doing what it
			 * should. */
			{
				static const char * const state_labels[CMP_HYP_STATE_NR] = {
					"observed", "testing", "promoted",
					"demoted",  "retired",
				};
				static unsigned long prev_picked[CMP_HYP_STATE_NR];
				static unsigned long prev_skipped_retired;
				static unsigned long prev_demoted_reroll;
				unsigned long cur_skipped = __atomic_load_n(
					&kcov_shm->cmp_hyp_skipped_retired,
					__ATOMIC_RELAXED);
				unsigned long cur_demoted_reroll = __atomic_load_n(
					&kcov_shm->cmp_hyp_demoted_reroll_picked,
					__ATOMIC_RELAXED);
				unsigned int s;

				for (s = 0; s < CMP_HYP_STATE_NR; s++) {
					unsigned long cur = __atomic_load_n(
						&kcov_shm->cmp_hyp_picked_by_state[s],
						__ATOMIC_RELAXED);
					unsigned long delta = cur - prev_picked[s];

					prev_picked[s] = cur;
					if (delta == 0 && cur == 0)
						continue;
					stats_log_write(
						"  cmp_hyp_picked[%-8s] +%lu  (total %lu)\n",
						state_labels[s], delta, cur);
				}
				if (cur_skipped != 0 || prev_skipped_retired != 0) {
					stats_log_write(
						"  cmp_hyp_skipped_retired +%lu  (total %lu)\n",
						cur_skipped - prev_skipped_retired,
						cur_skipped);
					prev_skipped_retired = cur_skipped;
				}
				if (cur_demoted_reroll != 0 || prev_demoted_reroll != 0) {
					stats_log_write(
						"  cmp_hyp_demoted_reroll_picked +%lu  (total %lu)\n",
						cur_demoted_reroll - prev_demoted_reroll,
						cur_demoted_reroll);
					prev_demoted_reroll = cur_demoted_reroll;
				}
			}

			/* h->state live transition census.  Bumped from
			 * cmp_hyp_credit_outcome() once per state mutation.
			 * Pairs with the would_promote_by_kind /
			 * would_demote_by_kind shadow counters above: the
			 * shadow counters report "would the live state
			 * machine fire", the transitions matrix reports
			 * "did it".  Only the active off-diagonal slots
			 * print (zero rows suppressed). */
			{
				static const char * const state_labels[CMP_HYP_STATE_NR] = {
					"observed", "testing", "promoted",
					"demoted",  "retired",
				};
				static unsigned long prev_trans[CMP_HYP_STATE_NR][CMP_HYP_STATE_NR];
				unsigned int from, to;

				for (from = 0; from < CMP_HYP_STATE_NR; from++) {
					for (to = 0; to < CMP_HYP_STATE_NR; to++) {
						unsigned long cur;
						unsigned long delta;

						if (from == to)
							continue;
						cur = __atomic_load_n(
							&kcov_shm->cmp_hyp_state_transitions[from][to],
							__ATOMIC_RELAXED);
						delta = cur - prev_trans[from][to];
						prev_trans[from][to] = cur;
						if (delta == 0 && cur == 0)
							continue;
						stats_log_write(
							"  cmp_hyp_state[%-8s -> %-8s] +%lu  (total %lu)\n",
							state_labels[from],
							state_labels[to],
							delta, cur);
					}
				}
			}

			/* Per-kind outcome partition.  Lock-step with the flat
			 * cmp_hyp_pc_wins / _transition_wins / _misses /
			 * _corpus_save / _destructive / _context_skip /
			 * _cmp_novelty_wins above; the per-kind drilldown tells
			 * which hypothesis kind is converting versus which kind
			 * is consuming credit without conversion. */
			{
				static const char * const kind_labels[CMP_HYP_KIND_NR] = {
					"exact", "range", "boundary", "bitmask",
					"enum_family", "alignment", "length",
					"foreign_value",
				};
				static unsigned long prev_pc[CMP_HYP_KIND_NR];
				static unsigned long prev_tr[CMP_HYP_KIND_NR];
				static unsigned long prev_ms[CMP_HYP_KIND_NR];
				static unsigned long prev_cs[CMP_HYP_KIND_NR];
				static unsigned long prev_ds[CMP_HYP_KIND_NR];
				static unsigned long prev_ks[CMP_HYP_KIND_NR];
				static unsigned long prev_nv[CMP_HYP_KIND_NR];
				unsigned int k;

				for (k = 0; k < CMP_HYP_KIND_NR; k++) {
					unsigned long pc = __atomic_load_n(
						&kcov_shm->cmp_hyp_pc_wins_by_kind[k], __ATOMIC_RELAXED);
					unsigned long tr = __atomic_load_n(
						&kcov_shm->cmp_hyp_transition_wins_by_kind[k], __ATOMIC_RELAXED);
					unsigned long ms = __atomic_load_n(
						&kcov_shm->cmp_hyp_misses_by_kind[k], __ATOMIC_RELAXED);
					unsigned long cs = __atomic_load_n(
						&kcov_shm->cmp_hyp_corpus_save_by_kind[k], __ATOMIC_RELAXED);
					unsigned long ds = __atomic_load_n(
						&kcov_shm->cmp_hyp_destructive_by_kind[k], __ATOMIC_RELAXED);
					unsigned long ks = __atomic_load_n(
						&kcov_shm->cmp_hyp_context_skip_by_kind[k], __ATOMIC_RELAXED);
					unsigned long nv = __atomic_load_n(
						&kcov_shm->cmp_hyp_cmp_novelty_wins_by_kind[k], __ATOMIC_RELAXED);

					stats_log_write(
						"  cmp_hyp[%-13s] outcome  pc +%lu  tr +%lu  ms +%lu  cs +%lu  ds +%lu  ks +%lu  nv +%lu\n",
						kind_labels[k],
						pc - prev_pc[k], tr - prev_tr[k],
						ms - prev_ms[k], cs - prev_cs[k],
						ds - prev_ds[k], ks - prev_ks[k],
						nv - prev_nv[k]);
					prev_pc[k] = pc;
					prev_tr[k] = tr;
					prev_ms[k] = ms;
					prev_cs[k] = cs;
					prev_ds[k] = ds;
					prev_ks[k] = ks;
					prev_nv[k] = nv;
				}
			}
		}

		prev_hyp_observations = cur_hyp_observations;
		prev_hyp_inserted = cur_hyp_inserted;
		prev_hyp_pool_full = cur_hyp_pool_full;
		prev_hyp_pool_overflow = cur_hyp_pool_overflow;
		prev_hyp_kind_full = cur_hyp_kind_full;
		prev_hyp_consumed = cur_hyp_consumed;
		prev_hyp_pc_wins = cur_hyp_pc_wins;
		prev_hyp_transition_wins = cur_hyp_transition_wins;
		prev_hyp_cmp_novelty_wins = cur_hyp_cmp_novelty_wins;
		prev_hyp_misses = cur_hyp_misses;
		prev_hyp_disabled_skips = cur_hyp_disabled_skips;
		prev_hyp_corpus_save = cur_hyp_corpus_save;
		prev_hyp_destructive = cur_hyp_destructive;
		prev_hyp_context_skip = cur_hyp_context_skip;
	}

	/*
	 * SHADOW would-pick telemetry from cmp_hints_try_get_ex().  Bumped
	 * per successful raw pool return after the typed hypothesis store
	 * is walked through the EXACT > ENUM_FAMILY > BITMASK > RANGE
	 * ladder for the same (cmp_ip, width).  Independent any-delta
	 * gate: a SHADOW run with an empty typed store still bumps
	 * would_miss on every pull, and that is exactly the signal worth
	 * surfacing once the consumer demand picks up.
	 */
	{
		static const char * const kind_labels[CMP_HYP_KIND_NR] = {
			"exact", "range", "boundary", "bitmask",
			"enum_family", "alignment", "length",
			"foreign_value",
		};
		static unsigned long prev_hyp_would_pick_kind[CMP_HYP_KIND_NR];
		static unsigned long prev_hyp_would_miss_kind[CMP_HYP_KIND_NR];
		static unsigned long prev_hyp_would_value_differs;
		unsigned long cur_hyp_would_pick_kind[CMP_HYP_KIND_NR];
		unsigned long cur_hyp_would_miss_kind[CMP_HYP_KIND_NR];
		unsigned long cur_hyp_would_value_differs;
		unsigned long delta_hyp_would_value_differs;
		unsigned long any_would_delta = 0;
		unsigned int k;

		for (k = 0; k < CMP_HYP_KIND_NR; k++) {
			cur_hyp_would_pick_kind[k] = __atomic_load_n(
				&kcov_shm->cmp_hyp_would_pick_by_kind[k],
				__ATOMIC_RELAXED);
			cur_hyp_would_miss_kind[k] = __atomic_load_n(
				&kcov_shm->cmp_hyp_would_miss_by_kind[k],
				__ATOMIC_RELAXED);
			any_would_delta |=
				(cur_hyp_would_pick_kind[k] - prev_hyp_would_pick_kind[k]) |
				(cur_hyp_would_miss_kind[k] - prev_hyp_would_miss_kind[k]);
		}
		cur_hyp_would_value_differs = __atomic_load_n(
			&kcov_shm->cmp_hyp_would_value_differs, __ATOMIC_RELAXED);
		delta_hyp_would_value_differs =
			cur_hyp_would_value_differs - prev_hyp_would_value_differs;
		any_would_delta |= delta_hyp_would_value_differs;

		if (any_would_delta != 0) {
			stats_log_write("KCOV CMP hyp would-pick shadow stats over last %lds:\n",
					elapsed);
			for (k = 0; k < CMP_HYP_KIND_NR; k++) {
				stats_log_write(
					"  cmp_hyp_would[%-13s] pick +%lu (total %lu)  miss +%lu (total %lu)\n",
					kind_labels[k],
					cur_hyp_would_pick_kind[k] - prev_hyp_would_pick_kind[k],
					cur_hyp_would_pick_kind[k],
					cur_hyp_would_miss_kind[k] - prev_hyp_would_miss_kind[k],
					cur_hyp_would_miss_kind[k]);
			}
			stats_log_write("  %-32s +%lu  (total %lu)\n",
					"cmp_hyp_would_value_differs",
					delta_hyp_would_value_differs,
					cur_hyp_would_value_differs);
		}

		for (k = 0; k < CMP_HYP_KIND_NR; k++) {
			prev_hyp_would_pick_kind[k] = cur_hyp_would_pick_kind[k];
			prev_hyp_would_miss_kind[k] = cur_hyp_would_miss_kind[k];
		}
		prev_hyp_would_value_differs = cur_hyp_would_value_differs;
	}

	/*
	 * LIVE typed-hypothesis inject arm telemetry.  Fleet-level view of
	 * the conservative inject arm rate from cmp_hints_try_get_ex():
	 * how often the gate passed, how often the resolver produced a
	 * derived value, and the per-kind partition of those produced
	 * values.  The pair (gate_passed, injected) separates "the arm
	 * fired and there was nothing in the typed store" from "the arm
	 * fired and substituted a derived value", which is what bounds
	 * the achievable conversion ceiling; the explicit no_pick gap
	 * (gate_passed - injected) names that empty-site case directly.
	 * Rendered every window with no delta gate so a quiet arm reads
	 * as zeros rather than silence -- the validation question is "did
	 * a typed-derived pick lift cmp_hyp_pc_wins" and that requires
	 * being able to tell "fired with zero wins" from "never fired".
	 * Conversion outcomes (pc_wins/misses) are credited only to
	 * live-arm entries and render in the cmp_hyp shadow stats block
	 * above; not duplicated here.
	 */
	{
		static const char * const kind_labels[CMP_HYP_KIND_NR] = {
			"exact", "range", "boundary", "bitmask",
			"enum_family", "alignment", "length",
			"foreign_value",
		};
		static unsigned long prev_hyp_live_injected;
		static unsigned long prev_hyp_live_gate_passed;
		static unsigned long prev_hyp_live_injected_kind[CMP_HYP_KIND_NR];
		/*
		 * Load injected before gate_passed.  cmp_hints_try_get_ex()
		 * bumps gate_passed first and only later bumps injected on a
		 * successful pick+derive, so producer-side gate_passed >=
		 * injected always.  Reading injected first means a paired
		 * (gate_passed, injected) increment in flight between the two
		 * loads gets snapshotted as a gate_passed-only bump (over-
		 * counting no_pick by 1) rather than as an injected-only bump
		 * (which would make cur gap go negative under RELAXED).
		 */
		unsigned long cur_hyp_live_injected = __atomic_load_n(
			&kcov_shm->cmp_hyp_live_injected, __ATOMIC_RELAXED);
		unsigned long cur_hyp_live_gate_passed = __atomic_load_n(
			&kcov_shm->cmp_hyp_live_inject_gate_passed,
			__ATOMIC_RELAXED);
		unsigned long cur_hyp_live_injected_kind[CMP_HYP_KIND_NR];
		unsigned long delta_hyp_live_injected =
			cur_hyp_live_injected - prev_hyp_live_injected;
		unsigned long delta_hyp_live_gate_passed =
			cur_hyp_live_gate_passed - prev_hyp_live_gate_passed;
		/*
		 * gate_passed and injected are loaded separately with RELAXED
		 * ordering.  injected-first keeps the gap non-negative for the
		 * common steady state, but once the live-inject arm fires a
		 * sample can observe injected > gate_passed (the gate counter
		 * is bumped slightly after the inject counter on the producer
		 * side).  An unguarded unsigned subtraction wraps to ~ULONG_MAX
		 * in the rendered total; clamp.
		 */
		unsigned long cur_hyp_live_inject_no_pick =
			(cur_hyp_live_gate_passed >= cur_hyp_live_injected)
				? (cur_hyp_live_gate_passed - cur_hyp_live_injected)
				: 0;
		/*
		 * delta_gate_passed - delta_injected can wrap when the over-
		 * count drift in the previous sample exceeded the over-count
		 * drift in this sample (cur gap < prev gap), even though the
		 * underlying no_pick total is monotone non-decreasing.  Clamp.
		 */
		unsigned long delta_hyp_live_inject_no_pick =
			(delta_hyp_live_gate_passed >= delta_hyp_live_injected)
				? (delta_hyp_live_gate_passed - delta_hyp_live_injected)
				: 0;
		unsigned int k;

		for (k = 0; k < CMP_HYP_KIND_NR; k++) {
			cur_hyp_live_injected_kind[k] = __atomic_load_n(
				&kcov_shm->cmp_hyp_live_injected_by_kind[k],
				__ATOMIC_RELAXED);
		}

		stats_log_write("KCOV CMP hyp live inject stats over last %lds:\n",
				elapsed);
		stats_log_write("  %-32s +%lu  (total %lu)\n",
				"cmp_hyp_live_inject_gate_passed",
				delta_hyp_live_gate_passed,
				cur_hyp_live_gate_passed);
		stats_log_write("  %-32s +%lu  (total %lu)\n",
				"cmp_hyp_live_injected",
				delta_hyp_live_injected,
				cur_hyp_live_injected);
		stats_log_write("  %-32s +%lu  (total %lu)\n",
				"cmp_hyp_live_inject_no_pick",
				delta_hyp_live_inject_no_pick,
				cur_hyp_live_inject_no_pick);
		for (k = 0; k < CMP_HYP_KIND_NR; k++) {
			stats_log_write(
				"  cmp_hyp_live_inject[%-13s] +%lu (total %lu)\n",
				kind_labels[k],
				cur_hyp_live_injected_kind[k] -
					prev_hyp_live_injected_kind[k],
				cur_hyp_live_injected_kind[k]);
		}
		stats_log_write(
			"  (conversion outcomes: see cmp_hyp_pc_wins / cmp_hyp_misses in cmp_hyp shadow stats above)\n");

		prev_hyp_live_injected = cur_hyp_live_injected;
		prev_hyp_live_gate_passed = cur_hyp_live_gate_passed;
		for (k = 0; k < CMP_HYP_KIND_NR; k++)
			prev_hyp_live_injected_kind[k] = cur_hyp_live_injected_kind[k];
	}

	/*
	 * Per-reason gate-close partition for the LIVE inject path.  Each
	 * slot names a distinct early-return / reject site so a
	 * gate_passed=0 diagnosis can be attributed to a specific gate
	 * rather than stay opaque.  Pure observability -- mirrors the
	 * counters bumped from cmp_hyp_try_live_inject() and its
	 * accept-gated caller in cmp_hints.c.  Section stays quiet until
	 * something on the inject path actually fires.
	 */
	{
		static const char * const reason_labels[CMP_HYP_LIVE_INJECT_REASON_NR] = {
			[CMP_HYP_LIVE_INJECT_REASON_NOT_PLATEAU]     = "not_plateau",
			[CMP_HYP_LIVE_INJECT_REASON_DICE_MISS]       = "dice_miss",
			[CMP_HYP_LIVE_INJECT_REASON_NO_MATCH]        = "no_match",
			[CMP_HYP_LIVE_INJECT_REASON_DERIVE_FAIL]     = "derive_fail",
			[CMP_HYP_LIVE_INJECT_REASON_ACCEPT_REJECT]   = "accept_reject",
			[CMP_HYP_LIVE_INJECT_REASON_BOOTSTRAP]       = "bootstrap",
			[CMP_HYP_LIVE_INJECT_REASON_PROMOTED_BYPASS] = "promoted_bypass",
		};
		static unsigned long prev_hyp_live_inject_reason[CMP_HYP_LIVE_INJECT_REASON_NR];
		unsigned long cur_hyp_live_inject_reason[CMP_HYP_LIVE_INJECT_REASON_NR];
		unsigned long any_delta = 0;
		unsigned int r;

		for (r = 0; r < CMP_HYP_LIVE_INJECT_REASON_NR; r++) {
			cur_hyp_live_inject_reason[r] = __atomic_load_n(
				&kcov_shm->cmp_hyp_live_inject_reason[r],
				__ATOMIC_RELAXED);
			any_delta |=
				(cur_hyp_live_inject_reason[r] -
				 prev_hyp_live_inject_reason[r]);
		}

		if (any_delta != 0) {
			stats_log_write("KCOV CMP live-inject gate-close reasons over last %lds:\n",
					elapsed);
			for (r = 0; r < CMP_HYP_LIVE_INJECT_REASON_NR; r++) {
				stats_log_write(
					"  cmp_hyp_live_inject_reason[%-13s] +%lu (total %lu)\n",
					reason_labels[r],
					cur_hyp_live_inject_reason[r] -
						prev_hyp_live_inject_reason[r],
					cur_hyp_live_inject_reason[r]);
			}
		}

		for (r = 0; r < CMP_HYP_LIVE_INJECT_REASON_NR; r++)
			prev_hyp_live_inject_reason[r] = cur_hyp_live_inject_reason[r];
	}

	/*
	 * BOUNDARY-arm scorecard.  Pulls the existing boundary-kind
	 * shadow counters into one render so the operator can read the
	 * inserted-vs-consumed ratio at a glance: how often a BOUNDARY
	 * hypothesis was created, how often one was available at a
	 * served pick site, how often the value-keyed would-pick ladder
	 * picked it (expected near zero -- EXACT outranks), how often
	 * the live inject arm derived from it, and how often a credited
	 * PC / transition resolved to BOUNDARY via the |v - exemplar|
	 * <= 2 window.  Gated on any-delta so a quiet run reads as
	 * silence, matching the sibling cmp_hyp shadow blocks above.
	 */
	{
		static unsigned long prev_b_inserted;
		static unsigned long prev_b_candidate_available;
		static unsigned long prev_b_credit_window_hits;
		static unsigned long prev_b_would_pick;
		static unsigned long prev_b_would_miss;
		static unsigned long prev_b_live_injected;
		static unsigned long prev_b_consumed;
		unsigned long cur_b_inserted = __atomic_load_n(
			&kcov_shm->cmp_hyp_boundary_inserted, __ATOMIC_RELAXED);
		unsigned long cur_b_candidate_available = __atomic_load_n(
			&kcov_shm->cmp_hyp_boundary_candidate_available,
			__ATOMIC_RELAXED);
		unsigned long cur_b_credit_window_hits = __atomic_load_n(
			&kcov_shm->cmp_hyp_boundary_credit_window_hits,
			__ATOMIC_RELAXED);
		unsigned long cur_b_would_pick = __atomic_load_n(
			&kcov_shm->cmp_hyp_would_pick_by_kind[CMP_HYP_BOUNDARY],
			__ATOMIC_RELAXED);
		unsigned long cur_b_would_miss = __atomic_load_n(
			&kcov_shm->cmp_hyp_would_miss_by_kind[CMP_HYP_BOUNDARY],
			__ATOMIC_RELAXED);
		unsigned long cur_b_live_injected = __atomic_load_n(
			&kcov_shm->cmp_hyp_live_injected_by_kind[CMP_HYP_BOUNDARY],
			__ATOMIC_RELAXED);
		unsigned long cur_b_consumed = __atomic_load_n(
			&kcov_shm->cmp_hyp_consumed_by_kind[CMP_HYP_BOUNDARY],
			__ATOMIC_RELAXED);
		unsigned long any_delta =
			(cur_b_inserted - prev_b_inserted) |
			(cur_b_candidate_available - prev_b_candidate_available) |
			(cur_b_credit_window_hits - prev_b_credit_window_hits) |
			(cur_b_would_pick - prev_b_would_pick) |
			(cur_b_would_miss - prev_b_would_miss) |
			(cur_b_live_injected - prev_b_live_injected) |
			(cur_b_consumed - prev_b_consumed);

		if (any_delta != 0) {
			stats_log_write("KCOV CMP hyp BOUNDARY-arm scorecard over last %lds:\n",
					elapsed);
			stats_log_write("  %-40s +%lu  (total %lu)\n",
					"cmp_hyp_boundary_inserted",
					cur_b_inserted - prev_b_inserted,
					cur_b_inserted);
			stats_log_write("  %-40s +%lu  (total %lu)\n",
					"cmp_hyp_boundary_candidate_available",
					cur_b_candidate_available - prev_b_candidate_available,
					cur_b_candidate_available);
			stats_log_write("  %-40s +%lu  (total %lu)\n",
					"cmp_hyp_would_pick_by_kind[boundary]",
					cur_b_would_pick - prev_b_would_pick,
					cur_b_would_pick);
			stats_log_write("  %-40s +%lu  (total %lu)\n",
					"cmp_hyp_would_miss_by_kind[boundary]",
					cur_b_would_miss - prev_b_would_miss,
					cur_b_would_miss);
			stats_log_write("  %-40s +%lu  (total %lu)\n",
					"cmp_hyp_live_injected_by_kind[boundary]",
					cur_b_live_injected - prev_b_live_injected,
					cur_b_live_injected);
			stats_log_write("  %-40s +%lu  (total %lu)\n",
					"cmp_hyp_consumed_by_kind[boundary]",
					cur_b_consumed - prev_b_consumed,
					cur_b_consumed);
			stats_log_write("  %-40s +%lu  (total %lu)\n",
					"cmp_hyp_boundary_credit_window_hits",
					cur_b_credit_window_hits - prev_b_credit_window_hits,
					cur_b_credit_window_hits);
		}

		prev_b_inserted = cur_b_inserted;
		prev_b_candidate_available = cur_b_candidate_available;
		prev_b_credit_window_hits = cur_b_credit_window_hits;
		prev_b_would_pick = cur_b_would_pick;
		prev_b_would_miss = cur_b_would_miss;
		prev_b_live_injected = cur_b_live_injected;
		prev_b_consumed = cur_b_consumed;
	}

	/*
	 * SHADOW would-promote / would-demote eval from
	 * cmp_hyp_credit_outcome().  Bumped per credit landing after the
	 * per-hyp outcome counter is updated: would_promote when any of
	 * (pc_wins, transition_wins, corpus_save_wins) is set, would_demote
	 * when misses >= 8 and none of the win counters are set.  Pure
	 * observation -- h->state stays CMP_HYP_STATE_OBSERVED.  Render
	 * gated on any-delta so the section stays quiet until credit sites
	 * start firing.
	 */
	{
		static const char * const kind_labels[CMP_HYP_KIND_NR] = {
			"exact", "range", "boundary", "bitmask",
			"enum_family", "alignment", "length",
			"foreign_value",
		};
		static unsigned long prev_hyp_would_promote_kind[CMP_HYP_KIND_NR];
		static unsigned long prev_hyp_would_demote_kind[CMP_HYP_KIND_NR];
		unsigned long cur_hyp_would_promote_kind[CMP_HYP_KIND_NR];
		unsigned long cur_hyp_would_demote_kind[CMP_HYP_KIND_NR];
		unsigned long any_delta = 0;
		unsigned int k;

		for (k = 0; k < CMP_HYP_KIND_NR; k++) {
			cur_hyp_would_promote_kind[k] = __atomic_load_n(
				&kcov_shm->cmp_hyp_would_promote_by_kind[k],
				__ATOMIC_RELAXED);
			cur_hyp_would_demote_kind[k] = __atomic_load_n(
				&kcov_shm->cmp_hyp_would_demote_by_kind[k],
				__ATOMIC_RELAXED);
			any_delta |=
				(cur_hyp_would_promote_kind[k] - prev_hyp_would_promote_kind[k]) |
				(cur_hyp_would_demote_kind[k] - prev_hyp_would_demote_kind[k]);
		}

		if (any_delta != 0) {
			stats_log_write("KCOV CMP hyp would-promote/demote shadow stats over last %lds:\n",
					elapsed);
			for (k = 0; k < CMP_HYP_KIND_NR; k++) {
				stats_log_write(
					"  cmp_hyp_would[%-13s] promote +%lu (total %lu)  demote +%lu (total %lu)\n",
					kind_labels[k],
					cur_hyp_would_promote_kind[k] - prev_hyp_would_promote_kind[k],
					cur_hyp_would_promote_kind[k],
					cur_hyp_would_demote_kind[k] - prev_hyp_would_demote_kind[k],
					cur_hyp_would_demote_kind[k]);
			}
		}

		for (k = 0; k < CMP_HYP_KIND_NR; k++) {
			prev_hyp_would_promote_kind[k] = cur_hyp_would_promote_kind[k];
			prev_hyp_would_demote_kind[k] = cur_hyp_would_demote_kind[k];
		}
	}

	/*
	 * SHADOW 8-band histogram of the per-hypothesis score_bucket value
	 * computed in cmp_hyp_credit_outcome().  Bumped lock-step with the
	 * h->score_bucket store, using the bucket value just written.
	 * Bands: 0 idle, 1 penalty-only, 2 heavy net-neg, 3 slight net-neg,
	 * 4 break-even, 5 small net-pos, 6 moderate net-pos, 7 strong net-pos.
	 * Render gated on any-delta so the section stays quiet until credit
	 * sites start firing.
	 */
	{
		static const char * const bucket_labels[8] = {
			"idle",
			"penalty_only",
			"heavy_net_neg",
			"slight_net_neg",
			"break_even",
			"small_net_pos",
			"moderate_net_pos",
			"strong_net_pos",
		};
		static unsigned long prev_hyp_score_bucket[8];
		unsigned long cur_hyp_score_bucket[8];
		unsigned long any_delta = 0;
		unsigned int k;

		for (k = 0; k < 8; k++) {
			cur_hyp_score_bucket[k] = __atomic_load_n(
				&kcov_shm->cmp_hyp_score_bucket_census[k],
				__ATOMIC_RELAXED);
			any_delta |= cur_hyp_score_bucket[k] - prev_hyp_score_bucket[k];
		}

		if (any_delta != 0) {
			stats_log_write("KCOV CMP hyp score-bucket distribution (bands 0..7) over last %lds:\n",
					elapsed);
			for (k = 0; k < 8; k++) {
				stats_log_write(
					"  cmp_hyp_score_bucket[%u %-16s] +%lu  (total %lu)\n",
					k, bucket_labels[k],
					cur_hyp_score_bucket[k] - prev_hyp_score_bucket[k],
					cur_hyp_score_bucket[k]);
			}
		}

		for (k = 0; k < 8; k++)
			prev_hyp_score_bucket[k] = cur_hyp_score_bucket[k];
	}

	/*
	 * SHADOW per-probe-class histogram of cmp_hyp_derive_value()
	 * emissions.  Bumped lock-step (RELAXED) at the out_bump label in
	 * cmp_hints.c using the class the derivation just produced; *out is
	 * unchanged from the pre-census ladder, so the live inject arm
	 * receives a byte-identical value.  Render gated on any-delta so
	 * the section stays quiet until the derivation path fires.  The
	 * bound CMP_HYP_PROBE_CLASS_NR matches the on-shm array (see the
	 * enum and struct kcov_shared in include/kcov.h); using designated
	 * initialisers on class_labels[] keeps every label pinned to its
	 * enum name so a future re-order of the enum cannot silently
	 * mislabel a bucket.  Counters are monotonic on the producer side
	 * but the snapshot / prev pair is loaded across separate RELAXED
	 * reads; guard the delta with cur >= prev so a reordered
	 * observation cannot underflow into a multi-GB delta print.
	 */
	{
		static const char * const class_labels[CMP_HYP_PROBE_CLASS_NR] = {
			[CMP_HYP_PROBE_CLASS_EXACT_EXEMPLAR]     = "exact_exemplar",
			[CMP_HYP_PROBE_CLASS_ENUM_EXEMPLAR]      = "enum_exemplar",
			[CMP_HYP_PROBE_CLASS_ENUM_LO]            = "enum_lo",
			[CMP_HYP_PROBE_CLASS_ENUM_HI]            = "enum_hi",
			[CMP_HYP_PROBE_CLASS_BITMASK_SINGLE_BIT] = "bitmask_single_bit",
			[CMP_HYP_PROBE_CLASS_EXEMPLAR_FALLBACK]  = "exemplar_fallback",
			[CMP_HYP_PROBE_CLASS_RANGE_LO]           = "range_lo",
			[CMP_HYP_PROBE_CLASS_RANGE_HI]           = "range_hi",
			[CMP_HYP_PROBE_CLASS_RANGE_MIDPOINT]     = "range_midpoint",
			[CMP_HYP_PROBE_CLASS_BOUNDARY_MINUS1]    = "boundary_minus1",
			[CMP_HYP_PROBE_CLASS_BOUNDARY_PLUS1]     = "boundary_plus1",
			[CMP_HYP_PROBE_CLASS_BOUNDARY_EXACT]     = "boundary_exact",
			[CMP_HYP_PROBE_CLASS_BOUNDARY_SWEEP]     = "boundary_sweep",
		};
		static unsigned long prev_hyp_probe_class[CMP_HYP_PROBE_CLASS_NR];
		unsigned long cur_hyp_probe_class[CMP_HYP_PROBE_CLASS_NR];
		unsigned long any_delta = 0;
		unsigned int k;

		for (k = 0; k < CMP_HYP_PROBE_CLASS_NR; k++) {
			cur_hyp_probe_class[k] = __atomic_load_n(
				&kcov_shm->cmp_hyp_probe_class_hist[k],
				__ATOMIC_RELAXED);
			if (cur_hyp_probe_class[k] >= prev_hyp_probe_class[k])
				any_delta |= cur_hyp_probe_class[k] -
					     prev_hyp_probe_class[k];
		}

		if (any_delta != 0) {
			stats_log_write("KCOV CMP hyp probe-class histogram over last %lds:\n",
					elapsed);
			for (k = 0; k < CMP_HYP_PROBE_CLASS_NR; k++) {
				unsigned long delta = 0;

				if (cur_hyp_probe_class[k] >= prev_hyp_probe_class[k])
					delta = cur_hyp_probe_class[k] -
						prev_hyp_probe_class[k];
				stats_log_write(
					"  cmp_hyp_probe_class[%2u %-18s] +%lu  (total %lu)\n",
					k, class_labels[k],
					delta,
					cur_hyp_probe_class[k]);
			}
		}

		for (k = 0; k < CMP_HYP_PROBE_CLASS_NR; k++)
			prev_hyp_probe_class[k] = cur_hyp_probe_class[k];
	}

	/*
	 * SHADOW per-hypothesis outcome aggregates that have no kcov_shm
	 * flat-counter twin (corpus_save_wins / destructive_skips /
	 * context_skips).  Walk the hyp_pools[][] grid once per window and
	 * sum the per-entry u64s; render gated on any-delta so the section
	 * stays quiet until a future credit site fires.  The walk is bounded
	 * (MAX_NR_SYSCALL * 2 pools * CMP_HYP_PER_SYSCALL entries) and runs
	 * at parent stats cadence, well below any noticeable cost.  Reads
	 * are RELAXED against credit-side bumps; a torn sum at most under-
	 * counts a single in-flight credit on this window and converges on
	 * the next render.
	 */
	if (cmp_hints_shm != NULL) {
		static uint64_t prev_hyp_corpus_save_wins;
		static uint64_t prev_hyp_destructive_skips;
		static uint64_t prev_hyp_context_skips;
		uint64_t cur_hyp_corpus_save_wins = 0;
		uint64_t cur_hyp_destructive_skips = 0;
		uint64_t cur_hyp_context_skips = 0;
		uint64_t delta_hyp_corpus_save_wins;
		uint64_t delta_hyp_destructive_skips;
		uint64_t delta_hyp_context_skips;
		unsigned int nr_i, do32_i, e_i;

		for (nr_i = 0; nr_i < MAX_NR_SYSCALL; nr_i++) {
			for (do32_i = 0; do32_i < 2; do32_i++) {
				struct cmp_hyp_pool *p =
					&cmp_hints_shm->hyp_pools[nr_i][do32_i];
				unsigned int n = p->count;

				if (n > CMP_HYP_PER_SYSCALL)
					n = CMP_HYP_PER_SYSCALL;
				for (e_i = 0; e_i < n; e_i++) {
					struct cmp_hypothesis *h = &p->entries[e_i];

					cur_hyp_corpus_save_wins +=
						__atomic_load_n(&h->corpus_save_wins,
								__ATOMIC_RELAXED);
					cur_hyp_destructive_skips +=
						__atomic_load_n(&h->destructive_skips,
								__ATOMIC_RELAXED);
					cur_hyp_context_skips +=
						__atomic_load_n(&h->context_skips,
								__ATOMIC_RELAXED);
				}
			}
		}

		delta_hyp_corpus_save_wins = cur_hyp_corpus_save_wins - prev_hyp_corpus_save_wins;
		delta_hyp_destructive_skips = cur_hyp_destructive_skips - prev_hyp_destructive_skips;
		delta_hyp_context_skips = cur_hyp_context_skips - prev_hyp_context_skips;

		if ((delta_hyp_corpus_save_wins | delta_hyp_destructive_skips |
		     delta_hyp_context_skips) != 0) {
			stats_log_write("KCOV CMP hyp per-hypothesis aggregates over last %lds:\n", elapsed);
			stats_log_write("  %-32s +%lu  (total %lu)\n",
					"cmp_hyp_corpus_save_wins",
					(unsigned long)delta_hyp_corpus_save_wins,
					(unsigned long)cur_hyp_corpus_save_wins);
			stats_log_write("  %-32s +%lu  (total %lu)\n",
					"cmp_hyp_destructive_skips",
					(unsigned long)delta_hyp_destructive_skips,
					(unsigned long)cur_hyp_destructive_skips);
			stats_log_write("  %-32s +%lu  (total %lu)\n",
					"cmp_hyp_context_skips",
					(unsigned long)delta_hyp_context_skips,
					(unsigned long)cur_hyp_context_skips);
		}

		prev_hyp_corpus_save_wins = cur_hyp_corpus_save_wins;
		prev_hyp_destructive_skips = cur_hyp_destructive_skips;
		prev_hyp_context_skips = cur_hyp_context_skips;
	}

	/*
	 * Standalone grep-friendly cumulative lines for counters whose only
	 * stat output above is delta-gated (skipped at zero) and whose bare
	 * tokens recur in narrative -- JSON dumps, header comments, atomic
	 * fetch sites -- so `grep -c <counter>` against a long-running log
	 * counts narrative occurrences rather than the counter, the same
	 * triage trap post_handler_corrupt_ptr_cumulative was added to
	 * close.  Emit one line per dump window per counter (even at zero
	 * so trend tracking has a t=0 anchor) with a distinctive
	 * _cumulative suffix; operators can `grep <counter>_cumulative
	 * out.log | tail -1` for the current total or grep -c the suffix
	 * to count windows.  Placed outside the delta-gated block above so
	 * they fire every window regardless of cmp activity.
	 */
	output(0, "[main] cmp_hints_chaos_suppressed_cumulative=%lu\n",
	       cur_chaos_suppressed);
	output(0, "[main] propagation_injected_cumulative=%lu\n",
	       cur_prop_injected);

	pc_kids  = __atomic_load_n(&kcov_shm->pc_mode_children,  __ATOMIC_RELAXED);
	cmp_kids = __atomic_load_n(&kcov_shm->cmp_mode_children, __ATOMIC_RELAXED);

	if ((pc_kids | cmp_kids) != 0) {
		stats_log_write("KCOV CMP modes (cumulative):\n");
		stats_log_write("  pc_mode_children=%u cmp_mode_children=%u\n",
				pc_kids, cmp_kids);
	}

	{
		char init_buf[256];
		char rt_buf[256];
		int ni, nr;

		ni = kcov_cmp_diag_format(init_buf, sizeof(init_buf),
					  KCOV_CMP_DIAG_INIT);
		nr = kcov_cmp_diag_format(rt_buf, sizeof(rt_buf),
					  KCOV_CMP_DIAG_RUNTIME);

		if (ni > 0 || nr > 0) {
			stats_log_write("KCOV CMP DIAG errnos (first-failure-wins, cumulative count):\n");
			if (ni > 0)
				stats_log_write(" %s\n", init_buf);
			if (nr > 0)
				stats_log_write(" %s\n", rt_buf);
		}
	}

	{
		char pc_buf[256];
		int np;

		np = kcov_pc_diag_format(pc_buf, sizeof(pc_buf));
		if (np > 0) {
			stats_log_write("KCOV PC DIAG (first-failure-wins errnos + retry counters, cumulative):\n");
			stats_log_write(" %s\n", pc_buf);
		}
	}

	kcov_cmp_observability_block_render(elapsed);
	kcov_redqueen_observability_block_render(elapsed);
	kcov_cmp_oldpool_vs_shadow_block_render(elapsed);
	kcov_cmp_hyp_saturation_block_render(elapsed);

	prev_records       = cur_records;
	prev_truncated     = cur_truncated;
	prev_bloom_skipped = cur_bloom_skipped;
	prev_strip_skipped = cur_strip_skipped;
	prev_unique        = cur_unique;
	prev_try_get_attempts = cur_try_get_attempts;
	prev_try_get_returned = cur_try_get_returned;
	prev_injected         = cur_injected;
	prev_prop_injected    = cur_prop_injected;
	prev_chaos_suppressed = cur_chaos_suppressed;
	prev_count_oob        = cur_count_oob;
	prev_canary_lock_post = cur_canary_lock_post;
	prev_canary_pre       = cur_canary_pre;
	prev_canary_post      = cur_canary_post;
	prev_reexec_attempts                = cur_reexec_attempts;
	prev_reexec_attempts_with_new_cmp   = cur_reexec_attempts_with_new_cmp;
	prev_reexec_attribution_found       = cur_reexec_attribution_found;
	prev_reexec_attribution_ambiguous   = cur_reexec_attribution_ambiguous;
	prev_reexec_attribution_width_match = cur_reexec_attribution_width_match;
	prev_reexec_new_cmps_total          = cur_reexec_new_cmps_total;
	prev_reexec_skipped_destructive     = cur_reexec_skipped_destructive;
	prev_reexec_skipped_validate_silent = cur_reexec_skipped_validate_silent;
	prev_reexec_window_cap_hit          = cur_reexec_window_cap_hit;
	prev_reexec_pending_dropped         = cur_reexec_pending_dropped;
	prev_reexec_gate_skip_in_reexec     = cur_reexec_gate_skip_in_reexec;
	prev_reexec_gate_skip_disabled      = cur_reexec_gate_skip_disabled;
	prev_reexec_gate_skip_mode          = cur_reexec_gate_skip_mode;
	prev_reexec_gate_skip_chain_mid     = cur_reexec_gate_skip_chain_mid;
	prev_reexec_gate_skip_no_new_cmp    = cur_reexec_gate_skip_no_new_cmp;
	prev_reexec_gate_skip_no_pending    = cur_reexec_gate_skip_no_pending;
	prev_reexec_gate_skip_rate          = cur_reexec_gate_skip_rate;
	prev_reexec_gate_pass               = cur_reexec_gate_pass;
	prev_cmp_parent_calls_enabled       = cur_cmp_parent_calls_enabled;
	prev_cmp_parent_calls_control       = cur_cmp_parent_calls_control;
	prev_cmp_parent_new_cmps_enabled    = cur_cmp_parent_new_cmps_enabled;
	prev_cmp_parent_new_cmps_control    = cur_cmp_parent_new_cmps_control;
	prev_save_reject_nonconst      = cur_save_reject_nonconst;
	prev_save_reject_uninteresting = cur_save_reject_uninteresting;
	prev_save_reject_sentinel      = cur_save_reject_sentinel;
	prev_save_reject_dup           = cur_save_reject_dup;
	prev_save_reject_cap           = cur_save_reject_cap;
	{
		unsigned int cs;
		for (cs = 0; cs < CMP_HINT_CALLSITE_NR; cs++)
			prev_cmp_hint_callsite[cs] = cur_cmp_hint_callsite[cs];
	}
	prev_cmp_hints_consumed             = cur_cmp_hints_consumed;
	prev_cmp_hint_wins                  = cur_cmp_hint_wins;
	prev_cmp_hint_misses                = cur_cmp_hint_misses;
	prev_cmp_hint_cmp_novelty_wins      = cur_cmp_hint_cmp_novelty_wins;
	prev_cmp_hint_stash_overflow        = cur_cmp_hint_stash_overflow;
	prev_cmp_hint_credit_entry_evicted  = cur_cmp_hint_credit_entry_evicted;
	prev_cmp_recent_inserts             = cur_cmp_recent_inserts;
	prev_cmp_recent_evicts              = cur_cmp_recent_evicts;
	prev_cmp_recent_would_pick          = cur_cmp_recent_would_pick;
	prev_cmp_recent_would_miss          = cur_cmp_recent_would_miss;
	prev_cmp_recent_live_picks          = cur_cmp_recent_live_picks;
	prev_cmp_inject_arm_a_baseline_fires = cur_cmp_inject_arm_a_baseline_fires;
	prev_cmp_inject_arm_b_baseline_fires = cur_cmp_inject_arm_b_baseline_fires;
	prev_cmp_inject_denom_diverged       = cur_cmp_inject_denom_diverged;
	prev_prop_ring_argop_arm_b_fires     = cur_prop_ring_argop_arm_b_fires;
	prev_frontier_blend_samples          = cur_frontier_blend_samples;
	prev_remote_adaptive_samples         = cur_remote_adaptive_samples;
	prev_mut_structured_shadow_divergences = cur_mut_structured_shadow_divergences;
	last_dump = now;
}

void __cold minicorpus_mut_attrib_canary_check(void)
{
	static time_t last_check_mono;
	static bool first_witness_emitted;
	struct timespec ts;
	time_t now;
	unsigned int i;

	if (minicorpus_shm == NULL)
		return;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	now = ts.tv_sec;

	/* First call seeds the gate without scanning -- mirrors the
	 * kcov_bitmap_canary_check() first-call seed.  Subsequent calls
	 * scan no more than once per MUT_ATTRIB_CANARY_INTERVAL_SEC, with
	 * the timestamp stamped from CLOCK_MONOTONIC so a backward NTP
	 * step cannot suppress an otherwise-due check. */
	if (last_check_mono == 0) {
		last_check_mono = now;
		return;
	}
	if ((unsigned long)(now - last_check_mono) <
	    MUT_ATTRIB_CANARY_INTERVAL_SEC)
		return;
	last_check_mono = now;

	/* Sample trials BEFORE wins for each pair so any in-flight
	 * producer that bumps both between the two loads biases the
	 * observed (wins - trials) DOWNWARD (the matching trial bump is
	 * already in the trials sample, the matching win bump may not
	 * be in the wins sample yet) and cannot manufacture a false
	 * inversion.  The opposite order is the one with the per-CPU
	 * skew window, hence the load order. */
	for (i = 0; i < MUT_NUM_OPS; i++) {
		unsigned long t  = __atomic_load_n(&minicorpus_shm->mut_trials[i],
						   __ATOMIC_RELAXED);
		unsigned long w  = __atomic_load_n(&minicorpus_shm->mut_wins[i],
						   __ATOMIC_RELAXED);
		unsigned long st = __atomic_load_n(
			&minicorpus_shm->mut_structured_trials[i],
			__ATOMIC_RELAXED);
		unsigned long sw = __atomic_load_n(
			&minicorpus_shm->mut_structured_wins[i],
			__ATOMIC_RELAXED);

		if (w > t + MUT_ATTRIB_INVERSION_TOL) {
			__atomic_fetch_add(&shm->stats.mut_attrib_inversion_caught,
					   1UL, __ATOMIC_RELAXED);
			if (!first_witness_emitted) {
				stats_log_write("CANARY: minicorpus mut_wins[%u]=%lu > mut_trials[%u]=%lu (tol=%lu, op=%s) -- counter word scribbled\n",
						i, w, i, t,
						MUT_ATTRIB_INVERSION_TOL,
						op_names[i]);
				first_witness_emitted = true;
			}
		}

		if (sw > st + MUT_ATTRIB_INVERSION_TOL) {
			__atomic_fetch_add(&shm->stats.mut_attrib_inversion_caught,
					   1UL, __ATOMIC_RELAXED);
			if (!first_witness_emitted) {
				stats_log_write("CANARY: minicorpus mut_structured_wins[%u]=%lu > mut_structured_trials[%u]=%lu (tol=%lu, op=%s) -- counter word scribbled\n",
						i, sw, i, st,
						MUT_ATTRIB_INVERSION_TOL,
						op_names[i]);
				first_witness_emitted = true;
			}
		}
	}
}

/* Per-syscall KCOV diagnostic blocks.  One block per counter in
 * struct kcov_per_syscall_diag, emitted as a top-20-non-zero list
 * sorted descending by counter value.  The block is skipped entirely
 * when no (nr, arch) slot has a non-zero value -- silence is the
 * diagnostic signal for the truncation/overflow counters in a
 * well-sized run, and an empty top-20 stanza would only be noise.
 *
 * Counter ordering across the dump is alphabetical by counter name.
 * Keep it that way: future additions to kcov_per_syscall_diag slot
 * in deterministically and log-grep over historical dumps stays
 * stable.
 */

#define KCOV_DIAG_TOPN	20

struct kcov_diag_entry {
	unsigned int nr;
	bool do32;
	uint64_t value;
};

static uint64_t kcov_diag_load(const struct kcov_per_syscall_diag *d,
			       enum kcov_diag_counter c)
{
	switch (c) {
	case KCOV_DIAG_BUCKET_BITS_REAL:
		return __atomic_load_n(&d->bucket_bits_real, __ATOMIC_RELAXED);
	case KCOV_DIAG_CMP_TRACE_TRUNCATED:
		return __atomic_load_n(&d->cmp_trace_truncated, __ATOMIC_RELAXED);
	case KCOV_DIAG_DEDUP_PROBE_OVERFLOW:
		return __atomic_load_n(&d->dedup_probe_overflow, __ATOMIC_RELAXED);
	case KCOV_DIAG_DISTINCT_PCS:
		return __atomic_load_n(&d->distinct_pcs, __ATOMIC_RELAXED);
	case KCOV_DIAG_MAX_TRACE_SIZE:
		return __atomic_load_n(&d->max_trace_size, __ATOMIC_RELAXED);
	case KCOV_DIAG_TRACE_TRUNCATED:
		return __atomic_load_n(&d->trace_truncated, __ATOMIC_RELAXED);
	}
	return 0;
}

void kcov_diag_emit_block(const char *counter_name,
				 enum kcov_diag_counter counter)
{
	struct kcov_diag_entry top[KCOV_DIAG_TOPN];
	unsigned int top_count = 0;
	unsigned int nr_per_arch[2];
	unsigned int arch, i;
	int j;

	/* Mirror the arch-dim scan bounds used by the existing per-syscall
	 * top-N blocks: under biarch iterate both tables, under uniarch
	 * only the single active table.  do32=true rows are always zero in
	 * uniarch builds and the (skipped) arch=1 column drops out
	 * naturally. */
	if (biarch) {
		nr_per_arch[0] = max_nr_64bit_syscalls;
		nr_per_arch[1] = max_nr_32bit_syscalls;
	} else {
		nr_per_arch[0] = max_nr_syscalls;
		nr_per_arch[1] = 0;
	}
	for (arch = 0; arch < 2; arch++)
		if (nr_per_arch[arch] > MAX_NR_SYSCALL)
			nr_per_arch[arch] = MAX_NR_SYSCALL;

	for (arch = 0; arch < 2; arch++) {
		bool do32 = (arch == 1);

		for (i = 0; i < nr_per_arch[arch]; i++) {
			uint64_t value = kcov_diag_load(
				&kcov_shm->per_syscall_diag[i][do32 ? 1 : 0],
				counter);

			if (value == 0)
				continue;

			/* Insertion sort, descending by value, capped at
			 * KCOV_DIAG_TOPN -- same shape as the sibling
			 * top-edges block above. */
			for (j = (int)top_count;
			     j > 0 && value > top[j - 1].value; j--) {
				if (j < KCOV_DIAG_TOPN)
					top[j] = top[j - 1];
			}
			if (j < KCOV_DIAG_TOPN) {
				top[j].nr = i;
				top[j].do32 = do32;
				top[j].value = value;
				if (top_count < KCOV_DIAG_TOPN)
					top_count++;
			}
		}
	}

	if (top_count == 0)
		return;

	output(0, "Top syscalls by %s:\n", counter_name);
	for (j = 0; j < (int)top_count; j++) {
		const char *name = print_syscall_name(top[j].nr, top[j].do32);

		output(0, "  nr=%u (%s) [arch=%s] %" PRIu64 "\n",
		       top[j].nr, name,
		       top[j].do32 ? "32" : "64",
		       top[j].value);
	}
}

/* combined top-N table joining
 * per-syscall trace_truncated + cmp_trace_truncated + max_trace_size
 * (with its share of KCOV_TRACE_SIZE) on the same row, plus a single
 * summary line for dedup-probe-overflow.
 *
 * Sibling kcov_diag_emit_block calls already rank each counter on its
 * own; that flattens the cross-counter signal -- a syscall whose trace
 * mostly saturates without an outright truncation event drops off the
 * trace_truncated block, and one whose CMP buffer truncates appears in
 * a separate stanza from the trace one.  This combined view ranks by
 * max(trace_truncated, max_trace_size) so saturation-without-trunc and
 * trunc-with-modest-max both surface, and prints the CMP counterpart in
 * the same row -- the data needed to decide between a global
 * --kcov-trace-size knob and a targeted large-trace child pool
 * (buffer knob).  Diagnostic only; no collection, buffer, or
 * reward path is touched.
 */
#define KCOV_DIAG_TRUNC_TOPN	10

struct kcov_diag_trunc_entry {
	unsigned int nr;
	bool do32;
	uint64_t trace_truncated;
	uint64_t cmp_trace_truncated;
	uint64_t max_trace_size;
	/* per_syscall_calls[] and per_syscall_edges[] are indexed by nr
	 * only, not by arch; under biarch both rows for the same nr show
	 * the same denominator.  The ratio still answers "what share of
	 * this syscall's calls produced an arch-N trunc" / "how many
	 * edge-winning calls landed for each truncation on this syscall". */
	uint64_t calls;
	uint64_t edge_wins;
	uint64_t rank;
};

void kcov_diag_emit_truncation_topn(void)
{
	struct kcov_diag_trunc_entry top[KCOV_DIAG_TRUNC_TOPN];
	unsigned int top_count = 0;
	unsigned int nr_per_arch[2];
	unsigned int arch, i;
	int j;
	uint64_t dedup_per_syscall_sum = 0;
	uint64_t dedup_global;
	unsigned int dedup_syscall_count = 0;

	if (biarch) {
		nr_per_arch[0] = max_nr_64bit_syscalls;
		nr_per_arch[1] = max_nr_32bit_syscalls;
	} else {
		nr_per_arch[0] = max_nr_syscalls;
		nr_per_arch[1] = 0;
	}
	for (arch = 0; arch < 2; arch++)
		if (nr_per_arch[arch] > MAX_NR_SYSCALL)
			nr_per_arch[arch] = MAX_NR_SYSCALL;

	for (arch = 0; arch < 2; arch++) {
		bool do32 = (arch == 1);

		for (i = 0; i < nr_per_arch[arch]; i++) {
			const struct kcov_per_syscall_diag *d =
				&kcov_shm->per_syscall_diag[i][do32 ? 1 : 0];
			uint64_t tt = __atomic_load_n(&d->trace_truncated,
						      __ATOMIC_RELAXED);
			uint64_t ct = __atomic_load_n(&d->cmp_trace_truncated,
						      __ATOMIC_RELAXED);
			uint64_t mt = __atomic_load_n(&d->max_trace_size,
						      __ATOMIC_RELAXED);
			uint64_t dpo = __atomic_load_n(&d->dedup_probe_overflow,
						       __ATOMIC_RELAXED);
			uint64_t calls = __atomic_load_n(
				&kcov_shm->per_syscall_calls[i],
				__ATOMIC_RELAXED);
			uint64_t ew = __atomic_load_n(
				&kcov_shm->per_syscall_edges[i],
				__ATOMIC_RELAXED);
			uint64_t rank;

			if (dpo > 0) {
				dedup_per_syscall_sum += dpo;
				dedup_syscall_count++;
			}

			rank = (tt > mt) ? tt : mt;
			if (rank == 0 && ct == 0)
				continue;
			if (rank == 0)
				rank = ct;

			for (j = (int)top_count;
			     j > 0 && rank > top[j - 1].rank; j--) {
				if (j < KCOV_DIAG_TRUNC_TOPN)
					top[j] = top[j - 1];
			}
			if (j < KCOV_DIAG_TRUNC_TOPN) {
				top[j].nr = i;
				top[j].do32 = do32;
				top[j].trace_truncated = tt;
				top[j].cmp_trace_truncated = ct;
				top[j].max_trace_size = mt;
				top[j].calls = calls;
				top[j].edge_wins = ew;
				top[j].rank = rank;
				if (top_count < KCOV_DIAG_TRUNC_TOPN)
					top_count++;
			}
		}
	}

	if (top_count > 0) {
		output(0, "Top syscalls by trace truncation / max trace (kcov_trace_size=%u longs):\n",
		       kcov_trace_size);
		output(0, "  %5s %-24s %-4s %14s %14s %14s %7s %8s %8s\n",
		       "nr", "name", "arch",
		       "trace_trunc", "cmp_trace_tr", "max_trace",
		       "pct_max", "tt/call", "ew/tt");
		for (j = 0; j < (int)top_count; j++) {
			const char *name = print_syscall_name(top[j].nr,
							      top[j].do32);
			unsigned int pct10 = (unsigned int)
				((top[j].max_trace_size * 1000ULL) /
				 (uint64_t)kcov_trace_size);
			char tt_call_str[32];
			char ew_tt_str[32];

			if (top[j].calls > 0) {
				uint64_t p = (top[j].trace_truncated * 1000ULL) /
					     top[j].calls;
				snprintf(tt_call_str, sizeof(tt_call_str),
					 "%5" PRIu64 ".%" PRIu64 "%%",
					 p / 10, p % 10);
			} else {
				snprintf(tt_call_str, sizeof(tt_call_str),
					 "%8s", "-");
			}
			if (top[j].trace_truncated > 0) {
				uint64_t p = (top[j].edge_wins * 1000ULL) /
					     top[j].trace_truncated;
				snprintf(ew_tt_str, sizeof(ew_tt_str),
					 "%5" PRIu64 ".%" PRIu64 "%%",
					 p / 10, p % 10);
			} else {
				snprintf(ew_tt_str, sizeof(ew_tt_str),
					 "%8s", "-");
			}

			output(0, "  %5u %-24s %-4s %14" PRIu64
				  " %14" PRIu64 " %14" PRIu64
				  " %4u.%u%% %8s %8s\n",
			       top[j].nr, name,
			       top[j].do32 ? "32" : "64",
			       top[j].trace_truncated,
			       top[j].cmp_trace_truncated,
			       top[j].max_trace_size,
			       pct10 / 10, pct10 % 10,
			       tt_call_str, ew_tt_str);
		}
	}

	dedup_global = __atomic_load_n(&kcov_shm->dedup_probe_overflow,
				       __ATOMIC_RELAXED);
	if (dedup_global > 0 || dedup_per_syscall_sum > 0) {
		output(0, "kcov dedup probe overflow: global=%" PRIu64
			  " per_syscall_sum=%" PRIu64
			  " syscalls_affected=%u\n",
		       dedup_global, dedup_per_syscall_sum,
		       dedup_syscall_count);
	}
}

/* --------------------------------------------------------------------
 * Run-identity block: provenance + post-warm-load start baseline +
 * shutdown deltas.  Closes the stale-cache-key trap from the 2026-06-14
 * triage where comparing two final cache snapshots made a fully
 * productive cold run look like zero growth (the warm cache had been
 * silently reused under a stale key).  The own-start delta is immune
 * to that: it is the work this process actually did, regardless of
 * what the carrier looked like before the run started.
 * -------------------------------------------------------------------- */

struct run_start_baseline {
	bool captured;
	time_t monotonic_at_start;
	unsigned long edges_found;
	unsigned long distinct_edges;
	unsigned long edges_warm_loaded;
	unsigned long distinct_edges_warm_loaded;
	unsigned long corpus_entries;
	/* Snapshot of the persisted cmp-hints pool taken AFTER the loader
	 * has populated cmp_hints_shm but BEFORE the fuzz loop starts.
	 * The carrier warm/cold classification has to read this -- not the
	 * runtime cmp_records_collected counter, which is zero at snapshot
	 * time and would label a warm-loaded run "cold". */
	unsigned long cmp_hints_loaded_values;
	unsigned long cmp_hints_loaded_syscalls;
};

static struct run_start_baseline run_start;

/* CLOCK_MONOTONIC second counter -- duplicate of child-canary.c's
 * file-static helper (kept private to avoid exposing it through a
 * widely-included header for two callers).  Wall-clock-skew-immune,
 * so a negative duration cannot trip a spurious panic on an NTP
 * step. */
static time_t runid_monotonic_seconds(void)
{
	struct timespec ts;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

/* Sum every per-syscall ring's entry count to get the parent's view
 * of total corpus size.  Reads each ring's count with __ATOMIC_RELAXED
 * since the snapshot is observability-only -- a torn read against a
 * concurrent writer at most miscounts by one entry per syscall, well
 * inside the noise floor of a "did this run grow the corpus" check.
 *
 * Each per-ring count is clamped to CORPUS_RING_SIZE before contributing
 * to the sum, matching the picker (minicorpus.c) and the snapshot
 * walker.  Both save paths (in-run minicorpus_save_with_reason and the
 * on-disk loader) cap count at CORPUS_RING_SIZE before publishing, so
 * count > CORPUS_RING_SIZE is structurally impossible through the
 * documented writer flow -- a value above the cap is a zero-false-
 * positive signal that the ring's count word has been scribbled by a
 * sibling wild write.  Without the clamp a single garbage count word
 * inflated the headline corpus_entries figure into the millions and
 * masked the underlying corruption.  On detection, bump the per-event
 * counter and (once per run) emit a first-witness line naming the ring
 * nr and the unclamped count value so the next triage pass can
 * attribute the scribbler. */
static unsigned long runid_corpus_entries_total(void)
{
	static bool overcap_warned;
	unsigned long total = 0;
	unsigned int i;

	if (minicorpus_shm == NULL)
		return 0;

	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		unsigned int count = __atomic_load_n(
			&minicorpus_shm->rings[i].count, __ATOMIC_RELAXED);

		if (unlikely(count > CORPUS_RING_SIZE)) {
			__atomic_add_fetch(
				&shm->stats.corpus_count_overcap_caught,
				1UL, __ATOMIC_RELAXED);
			if (!overcap_warned) {
				overcap_warned = true;
				output(0,
				       "[main] WARNING corpus_count_overcap "
				       "nr=%u count=%u clamped_to=%u "
				       "(first witness)\n",
				       i, count, CORPUS_RING_SIZE);
			}
			count = CORPUS_RING_SIZE;
		}
		total += count;
	}
	return total;
}

/* Render the 32-byte kallsyms fingerprint as a short hex prefix
 * suitable for an at-a-glance identity line; truncated to 16 hex
 * chars (8 bytes of entropy) is far past what a human eyeballs but
 * short enough to fit on one line beside the other identity fields.
 * Returns true iff the fingerprint was available -- a v5+ kcov path
 * that cannot resolve _text leaves it unavailable on this run. */
static bool runid_kallsyms_hex(char *out, size_t outlen)
{
	uint8_t fp[32];
	size_t i, want;

	if (outlen < 17)
		return false;
	if (!kcov_get_kernel_fp(fp))
		return false;
	want = 8;
	for (i = 0; i < want; i++)
		snprintf(out + (i * 2), outlen - (i * 2), "%02x", fp[i]);
	out[want * 2] = '\0';
	return true;
}

/* Read /proc/sys/kernel/random/boot_id into a NUL-terminated string
 * (the on-disk value is a 36-char UUID followed by a newline).
 * Returns true on success.  The boot_id is no longer used as a
 * cache-key guard (KCOV bitmap moved to canonicalised PCs at file
 * version 5), but it remains the single most useful "did the kernel
 * reboot between these two runs" anchor for the run-identity block. */
static bool runid_read_boot_id(char *out, size_t outlen)
{
	int fd;
	ssize_t n;

	if (outlen < 37)
		return false;

	fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
	if (fd < 0)
		return false;
	n = read(fd, out, outlen - 1);
	close(fd);
	if (n <= 0)
		return false;
	out[n] = '\0';
	/* Strip the trailing newline so the value renders inline. */
	if (n > 0 && out[n - 1] == '\n')
		out[n - 1] = '\0';
	return true;
}

void __cold stats_runid_snapshot_start(void)
{
	if (run_start.captured)
		return;

	run_start.monotonic_at_start = runid_monotonic_seconds();
	if (kcov_shm != NULL) {
		run_start.edges_found = __atomic_load_n(
			&kcov_shm->edges_found, __ATOMIC_RELAXED);
		run_start.distinct_edges = __atomic_load_n(
			&kcov_shm->distinct_edges, __ATOMIC_RELAXED);
		run_start.edges_warm_loaded = __atomic_load_n(
			&kcov_shm->edges_warm_loaded, __ATOMIC_RELAXED);
		run_start.distinct_edges_warm_loaded = __atomic_load_n(
			&kcov_shm->distinct_edges_warm_loaded,
			__ATOMIC_RELAXED);
	}
	run_start.corpus_entries = runid_corpus_entries_total();

	/* Sum the persisted cmp-hints pool as it stands right after the
	 * loader has finished -- this is the authoritative "did a prior
	 * run hand us a warm cache" answer for the cmp_hints carrier.
	 * Per-arch slots count individually, matching the JSON / text
	 * pool histograms emitted elsewhere in this file. */
	run_start.cmp_hints_loaded_values = 0;
	run_start.cmp_hints_loaded_syscalls = 0;
	if (cmp_hints_shm != NULL) {
		unsigned int i, a;

		for (i = 0; i < MAX_NR_SYSCALL; i++) {
			for (a = 0; a < 2; a++) {
				unsigned int n = cmp_hints_pool_safe_count(
					&cmp_hints_shm->pools[i][a]);

				if (n > 0) {
					run_start.cmp_hints_loaded_values += n;
					run_start.cmp_hints_loaded_syscalls++;
				}
			}
		}
	}

	run_start.captured = true;
}

static const char *runid_warm_state(bool gated_off, unsigned long start_value)
{
	if (gated_off)
		return "disabled";
	return start_value > 0 ? "warm" : "cold";
}

static const char *runid_transition_coverage_name(void)
{
	switch (kcov_transition_coverage_mode) {
	case KCOV_TRANSITION_COVERAGE_OFF:    return "off";
	case KCOV_TRANSITION_COVERAGE_SHADOW: return "shadow";
	}
	return "?";
}

static const char *runid_transition_reward_name(void)
{
	switch (kcov_transition_reward_mode) {
	case KCOV_TRANSITION_REWARD_OFF:         return "off";
	case KCOV_TRANSITION_REWARD_SHADOW_ONLY: return "shadow_only";
	case KCOV_TRANSITION_REWARD_COMBINED:    return "combined";
	}
	return "?";
}

/*
 * Append "<name>=<value>" to the manifest buffer, prefixed with a
 * separating space when the buffer is non-empty.  Returns the new
 * tail offset; on truncation the buffer stays NUL-terminated at its
 * prior contents and the same offset is returned so subsequent
 * appends become no-ops (the caller still sees off > 0 and prints
 * what fit, not "all defaults").
 */
static size_t runid_knob_append(char *buf, size_t buflen, size_t off,
				const char *name, const char *value)
{
	int n;

	if (off >= buflen)
		return off;
	n = snprintf(buf + off, buflen - off, "%s%s=%s",
		     off > 0 ? " " : "", name, value);
	if (n < 0 || (size_t)n >= buflen - off) {
		buf[off] = '\0';
		return off;
	}
	return off + (size_t)n;
}

static const char *runid_frontier_live_cooldown_mode_name(void)
{
	switch (frontier_live_cooldown_mode) {
	case FRONTIER_LIVE_COOLDOWN_MODE_OFF:         return "off";
	case FRONTIER_LIVE_COOLDOWN_MODE_SHADOW_ONLY: return "shadow-only";
	case FRONTIER_LIVE_COOLDOWN_MODE_COMBINED:    return "combined";
	}
	return "?";
}

static const char *runid_frontier_saturation_cooldown_mode_name(void)
{
	switch (frontier_saturation_cooldown_mode) {
	case FRONTIER_SATURATION_COOLDOWN_MODE_OFF:         return "off";
	case FRONTIER_SATURATION_COOLDOWN_MODE_SHADOW_ONLY: return "shadow-only";
	case FRONTIER_SATURATION_COOLDOWN_MODE_COMBINED:    return "combined";
	}
	return "?";
}

static const char *runid_frontier_group_antilock_mode_name(void)
{
	switch (frontier_group_antilock_mode) {
	case FRONTIER_GROUP_ANTILOCK_MODE_OFF:         return "off";
	case FRONTIER_GROUP_ANTILOCK_MODE_SHADOW_ONLY: return "shadow-only";
	case FRONTIER_GROUP_ANTILOCK_MODE_COMBINED:    return "combined";
	}
	return "?";
}

static const char *runid_cost_pool_selector_mode_name(void)
{
	switch (cost_pool_selector_mode) {
	case COST_POOL_SELECTOR_MODE_OFF:         return "off";
	case COST_POOL_SELECTOR_MODE_SHADOW_ONLY: return "shadow-only";
	case COST_POOL_SELECTOR_MODE_COMBINED:    return "combined";
	}
	return "?";
}

static const char *runid_expensive_adaptive_mode_name(void)
{
	switch (expensive_adaptive_mode) {
	case EXPENSIVE_ADAPTIVE_MODE_OFF:         return "off";
	case EXPENSIVE_ADAPTIVE_MODE_SHADOW_ONLY: return "shadow-only";
	case EXPENSIVE_ADAPTIVE_MODE_COMBINED:    return "combined";
	}
	return "?";
}

static const char *runid_reach_band_mode_name(void)
{
	switch (__atomic_load_n(&reach_band_mode, __ATOMIC_RELAXED)) {
	case REACH_BAND_OFF:         return "off";
	case REACH_BAND_SHADOW_ONLY: return "shadow-only";
	case REACH_BAND_COMBINED:    return "combined";
	}
	return "?";
}

static const char *runid_arg_len_semantics_mode_name(void)
{
	switch (__atomic_load_n(&arg_len_semantics_mode, __ATOMIC_RELAXED)) {
	case ARG_LEN_SEMANTICS_OFF: return "off";
	case ARG_LEN_SEMANTICS_ON:  return "on";
	}
	return "?";
}

static const char *runid_childop_kcov_attr_mode_name(void)
{
	switch (childop_kcov_attr_mode) {
	case CHILDOP_KCOV_ATTR_OFF:  return "off";
	case CHILDOP_KCOV_ATTR_DUAL: return "dual";
	case CHILDOP_KCOV_ATTR_ON:   return "on";
	}
	return "?";
}

static const char *runid_childop_cmp_harvest_mode_name(void)
{
	switch (childop_cmp_harvest_mode) {
	case CHILDOP_CMP_HARVEST_OFF: return "off";
	case CHILDOP_CMP_HARVEST_ON:  return "on";
	}
	return "?";
}

/*
 * Emit a single line listing every experimental knob whose current
 * value differs from its compile-time default.  Knobs at their
 * default value are intentionally omitted to keep the line scannable;
 * a run with nothing overridden prints "all defaults" so the line
 * still appears unconditionally and a downstream parser can rely on
 * its presence.  Default-OFF booleans render as "<name>=on" so the
 * value column is uniform with the enum knobs.
 *
 * Knobs whose default is not OFF (childop-kcov-attribution = dual,
 * kcov-transition-coverage = shadow, kcov-transition-reward =
 * combined, strategy = bandit-ucb1) compare against their actual
 * default, not zero, so flipping COMBINED back to shadow_only shows
 * up in the manifest rather than hiding behind an enum-zero check.
 */
static void runid_knob_manifest_render(void)
{
	char buf[1024];
	size_t off = 0;

	buf[0] = '\0';

	if (picker_mode_arg != PICKER_BANDIT_UCB1)
		off = runid_knob_append(buf, sizeof(buf), off,
					"strategy",
					picker_mode_name(picker_mode_arg));
	if (group_bias)
		off = runid_knob_append(buf, sizeof(buf), off,
					"group-bias", "on");
	if (cred_throttle)
		off = runid_knob_append(buf, sizeof(buf), off,
					"cred-throttle", "on");
	if (frontier_live_cooldown_mode != FRONTIER_LIVE_COOLDOWN_MODE_OFF)
		off = runid_knob_append(buf, sizeof(buf), off,
					"frontier-live-cooldown-mode",
					runid_frontier_live_cooldown_mode_name());
	if (frontier_saturation_cooldown_mode !=
	    FRONTIER_SATURATION_COOLDOWN_MODE_OFF)
		off = runid_knob_append(buf, sizeof(buf), off,
					"frontier-saturation-cooldown",
					runid_frontier_saturation_cooldown_mode_name());
	if (frontier_group_antilock_mode !=
	    FRONTIER_GROUP_ANTILOCK_MODE_OFF)
		off = runid_knob_append(buf, sizeof(buf), off,
					"frontier-group-antilock",
					runid_frontier_group_antilock_mode_name());
	if (cost_pool_selector_mode != COST_POOL_SELECTOR_MODE_OFF)
		off = runid_knob_append(buf, sizeof(buf), off,
					"cost-pool-selector",
					runid_cost_pool_selector_mode_name());
	if (__atomic_load_n(&reach_band_mode, __ATOMIC_RELAXED) !=
	    REACH_BAND_OFF)
		off = runid_knob_append(buf, sizeof(buf), off,
					"reach-band",
					runid_reach_band_mode_name());
	if (__atomic_load_n(&arg_len_semantics_mode, __ATOMIC_RELAXED) !=
	    ARG_LEN_SEMANTICS_OFF)
		off = runid_knob_append(buf, sizeof(buf), off,
					"arg-len-semantics",
					runid_arg_len_semantics_mode_name());
	if (expensive_adaptive_mode != EXPENSIVE_ADAPTIVE_MODE_OFF)
		off = runid_knob_append(buf, sizeof(buf), off,
					"expensive-adaptive",
					runid_expensive_adaptive_mode_name());
	if (redqueen_pending_pick_mode_arg != REDQUEEN_PENDING_PICK_RANDOM)
		off = runid_knob_append(buf, sizeof(buf), off,
					"redqueen-pending-pick",
					redqueen_pending_pick_name(redqueen_pending_pick_mode_arg));
	if (childop_kcov_attr_mode != CHILDOP_KCOV_ATTR_DUAL)
		off = runid_knob_append(buf, sizeof(buf), off,
					"childop-kcov-attribution",
					runid_childop_kcov_attr_mode_name());
	if (childop_cmp_harvest_mode != CHILDOP_CMP_HARVEST_OFF)
		off = runid_knob_append(buf, sizeof(buf), off,
					"childop-cmp-harvest",
					runid_childop_cmp_harvest_mode_name());
	if (kcov_transition_coverage_mode != KCOV_TRANSITION_COVERAGE_SHADOW)
		off = runid_knob_append(buf, sizeof(buf), off,
					"kcov-transition-coverage",
					runid_transition_coverage_name());
	if (kcov_transition_reward_mode != KCOV_TRANSITION_REWARD_COMBINED)
		off = runid_knob_append(buf, sizeof(buf), off,
					"kcov-transition-reward",
					runid_transition_reward_name());
	if (corpus_save_errno_grad_live)
		off = runid_knob_append(buf, sizeof(buf), off,
					"corpus-save-errno-grad-live", "on");
	if (fork_pressure_drain)
		off = runid_knob_append(buf, sizeof(buf), off,
					"fork-pressure-drain", "on");

	output(0, "run-id knobs: %s\n", off > 0 ? buf : "all defaults");
}

void __cold stats_runid_render(void)
{
	unsigned long end_edges = 0;
	unsigned long end_distinct = 0;
	unsigned long end_corpus = 0;
	unsigned long edges_delta = 0;
	unsigned long distinct_delta = 0;
	unsigned long corpus_delta = 0;
	time_t now = runid_monotonic_seconds();
	long elapsed = 0;
	struct utsname uts;
	bool have_uname;
	char kallsyms_hex[17] = "(unavailable)";
	char boot_id[64] = "(unavailable)";
	const char *kcov_state;
	const char *corpus_state;
	const char *cmp_state;

	have_uname = (uname(&uts) == 0);
	(void)runid_kallsyms_hex(kallsyms_hex, sizeof(kallsyms_hex));
	(void)runid_read_boot_id(boot_id, sizeof(boot_id));

	if (kcov_shm != NULL) {
		end_edges = __atomic_load_n(&kcov_shm->edges_found,
					    __ATOMIC_RELAXED);
		end_distinct = __atomic_load_n(&kcov_shm->distinct_edges,
					       __ATOMIC_RELAXED);
	}
	end_corpus = runid_corpus_entries_total();

	output(0, "\n");
	output(0, "===== run identity =====\n");

	/* Identity / provenance triple: the three values that together
	 * decide whether a persisted warm cache will load on the next run.
	 * Cache-key drift across runs is the failure mode the 2026-06-14
	 * triage chased; printing the triple at shutdown makes the drift
	 * visible without needing the loader's verbose path. */
	output(0, "run-id provenance: build=%s kernel=%s%s%s kallsyms=%s "
		  "boot_id=%s asan=%s\n",
	       GIT_HASH,
	       have_uname ? uts.release : "(uname-failed)",
	       have_uname ? " " : "",
	       have_uname ? uts.version : "",
	       kallsyms_hex,
	       boot_id,
#ifdef __SANITIZE_ADDRESS__
	       "on"
#else
	       "off"
#endif
	       );

	/* Cohort + the parent-side knobs that change selection at the
	 * coarse level.  Per-child A/B stamps (redqueen_enabled,
	 * cmp_hint_inject_arm_b, ...) are not parent-visible globals and
	 * are intentionally omitted -- they belong in the per-child
	 * attribution dumps, not this identity line. */
	output(0, "run-id cohort: children=%u alt_op_children=%u "
		  "canary_slots=%u canary_window_iters=%u canary_queue=%s "
		  "transition_coverage=%s transition_reward=%s\n",
	       max_children, alt_op_children,
	       canary_slots, canary_window_iters,
	       canary_queue_disabled ? "off" : "on",
	       runid_transition_coverage_name(),
	       runid_transition_reward_name());

	/* Cold/warm classification of each cross-run carrier.  "disabled"
	 * means the --no-*-warm-start opt-out is in effect (no save and no
	 * load this run); "warm" means the carrier had a non-zero starting
	 * baseline at snapshot time (a prior run's state survived into
	 * this one); "cold" means the carrier started empty (genuine
	 * first-run-on-this-cache-key). */
	kcov_state = runid_warm_state(no_kcov_warm_start,
				      run_start.edges_warm_loaded);
	corpus_state = runid_warm_state(no_warm_start,
					run_start.corpus_entries);
	/* Classify cmp_hints from the post-load pool snapshot, not from
	 * the runtime cmp_records_collected counter -- the latter is zero
	 * at start-snapshot time and would mislabel a warm-loaded run
	 * (e.g. 4636 entries / 290 syscalls reloaded by the persistence
	 * layer) as "cold". */
	cmp_state = runid_warm_state(no_cmp_hints_warm_start,
				     run_start.cmp_hints_loaded_values);
	output(0, "run-id carriers: kcov=%s minicorpus=%s cmp_hints=%s "
		  "kcov_warm_loaded_edges=%lu kcov_warm_loaded_distinct=%lu "
		  "cmp_hints_loaded_values=%lu cmp_hints_loaded_syscalls=%lu\n",
	       kcov_state, corpus_state, cmp_state,
	       run_start.edges_warm_loaded,
	       run_start.distinct_edges_warm_loaded,
	       run_start.cmp_hints_loaded_values,
	       run_start.cmp_hints_loaded_syscalls);

	if (!run_start.captured) {
		/* Reached the shutdown render without ever taking the
		 * start snapshot (early-exit dump path or a regression
		 * in the main_loop hook).  Print the end values alone so
		 * the operator still has the identity block, but suppress
		 * the deltas rather than emit a misleading "start=0
		 * end=N delta=N" line that would re-create the exact
		 * 2026-06-14 trap (mistaking a known-prior carrier for
		 * coverage this run discovered). */
		output(0, "run-id baseline: NOT CAPTURED -- deltas suppressed; "
			  "end edges_found=%lu distinct_edges=%lu "
			  "corpus_entries=%lu\n",
		       end_edges, end_distinct, end_corpus);
		runid_knob_manifest_render();
		output(0, "===== end run identity =====\n");
		return;
	}

	if (end_edges >= run_start.edges_found)
		edges_delta = end_edges - run_start.edges_found;
	if (end_distinct >= run_start.distinct_edges)
		distinct_delta = end_distinct - run_start.distinct_edges;
	if (end_corpus >= run_start.corpus_entries)
		corpus_delta = end_corpus - run_start.corpus_entries;
	if (now >= run_start.monotonic_at_start)
		elapsed = (long)(now - run_start.monotonic_at_start);

	output(0, "run-id baseline: start edges_found=%lu distinct_edges=%lu "
		  "corpus_entries=%lu\n",
	       run_start.edges_found, run_start.distinct_edges,
	       run_start.corpus_entries);
	output(0, "run-id shutdown: end   edges_found=%lu distinct_edges=%lu "
		  "corpus_entries=%lu elapsed=%lds\n",
	       end_edges, end_distinct, end_corpus, elapsed);
	output(0, "run-id own-start deltas: edges_found=+%lu "
		  "distinct_edges=+%lu corpus_entries=+%lu\n",
	       edges_delta, distinct_delta, corpus_delta);

	runid_knob_manifest_render();

	output(0, "===== end run identity =====\n");
}

static void dump_stats_runtime_header(void)
{
	time_t start = shm->start_time;
	time_t now = time(NULL);
	long elapsed = (start > 0 && now >= start) ? (long)(now - start) : 0;
	struct tm tm;
	char ts[32];

	if (start > 0 && localtime_r(&start, &tm) != NULL &&
	    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm) > 0) {
		output(1, "runtime: %ldh%02ldm%02lds (since %s)\n",
		       elapsed / 3600,
		       (elapsed / 60) % 60,
		       elapsed % 60,
		       ts);
	}
}

static void dump_stats_per_syscall_tables(void)
{
	unsigned int i;

	if (biarch == true) {
		output(0, "32bit:\n");
		for_each_32bit_syscall(i) {
			dump_entry(syscalls_32bit, i);
		}
		output(0, "64bit:\n");
		for_each_64bit_syscall(i) {
			dump_entry(syscalls_64bit, i);
		}
	} else {
		for_each_syscall(i) {
			dump_entry(syscalls, i);
		}
	}

	stats_emit_header();
}

/*
 * SHADOW-ONLY shutdown attribution for the per-syscall stuck-child
 * accounting (see the comment on shm->stats.syscall_wedge_count[]
 * in include/stats.h).  Renders a
 * top-N row sorted by cumulative wedged microseconds, with the per-
 * syscall event count rendered alongside so the operator can
 * distinguish "one rare syscall that wedges for ages" from "many
 * short wedges in a hot syscall".  Read-only: no live-path decision
 * is taken from either array yet; this dump exists so the next
 * iteration has data to choose throttle / isolation targets from.
 *
 * Biarch table choice follows top_syscalls_periodic_dump() exactly --
 * only the 64-bit table is iterated under biarch because 32-bit nrs
 * collide with 64-bit ones in the same index space and would shadow
 * them in the display.  Empty-block gate: if no wedge has ever been
 * accounted (count_total == 0), the block is skipped entirely
 * rather than emit an all-zero header.
 */
#define WEDGE_TOPN	10

static void dump_stats_top_wedging_syscalls(void)
{
	struct wedge_top_entry {
		unsigned int nr;
		unsigned long count;
		unsigned long long total_us;
	} top[WEDGE_TOPN];
	unsigned int top_count = 0;
	unsigned long count_total = 0;
	unsigned long long us_total = 0;
	unsigned int nr_to_scan;
	bool is32bit;
	unsigned int i;
	int j;

	if (biarch) {
		nr_to_scan = max_nr_64bit_syscalls;
		is32bit = false;
	} else {
		nr_to_scan = max_nr_syscalls;
		is32bit = false;
	}
	if (nr_to_scan > MAX_NR_SYSCALL)
		nr_to_scan = MAX_NR_SYSCALL;

	for (i = 0; i < nr_to_scan; i++) {
		unsigned long c = __atomic_load_n(
			&shm->stats.syscall_wedge_count[i],
			__ATOMIC_RELAXED);
		unsigned long long u = __atomic_load_n(
			&shm->stats.syscall_wedge_total_us[i],
			__ATOMIC_RELAXED);

		if (c == 0 && u == 0)
			continue;

		count_total += c;
		us_total += u;

		/* Insertion sort, descending by total_us, capped at WEDGE_TOPN.
		 * Ties on total_us are broken by event count so a hot syscall
		 * with many quick wedges ranks above a single still-pending
		 * wedge whose duration matches by accident. */
		for (j = (int)top_count;
		     j > 0 && (u > top[j - 1].total_us ||
			       (u == top[j - 1].total_us &&
				c > top[j - 1].count));
		     j--) {
			if (j < WEDGE_TOPN)
				top[j] = top[j - 1];
		}
		if (j < WEDGE_TOPN) {
			top[j].nr = i;
			top[j].count = c;
			top[j].total_us = u;
			if (top_count < WEDGE_TOPN)
				top_count++;
		}
	}

	if (count_total == 0 && us_total == 0)
		return;

	output(0, "Top %u most-wedging syscalls (cumulative; %lu events, "
		"%llu.%03llu s wedged total):\n",
		top_count, count_total,
		us_total / 1000000ULL, (us_total / 1000ULL) % 1000ULL);

	for (j = 0; j < (int)top_count; j++) {
		const char *name = print_syscall_name(top[j].nr, is32bit);
		unsigned long long s = top[j].total_us / 1000000ULL;
		unsigned long long ms = (top[j].total_us / 1000ULL) % 1000ULL;
		unsigned long long avg_us = top[j].count > 0 ?
			(top[j].total_us / top[j].count) : 0;
		unsigned long long avg_s = avg_us / 1000000ULL;
		unsigned long long avg_ms = (avg_us / 1000ULL) % 1000ULL;

		output(0, "    %-24s events=%lu wedged=%llu.%03llus avg=%llu.%03llus\n",
			name, top[j].count, s, ms, avg_s, avg_ms);
	}
}

/*
 * Sister of dump_stats_top_wedging_syscalls() above, keyed by enum
 * child_op_type instead of syscall nr.  Wedging on this fleet is
 * dominated by long-lived non-syscall childops (flock_thrash,
 * futex_storm, memory_pressure, ...) whose inner sites cycle through
 * many syscalls; the per-syscall top-N attributes the wedge cost to
 * whichever syscall happened to be in flight at detection, which
 * mis-names the dominant wedgers.  This block surfaces them by the
 * childop that was running when the stall began.
 *
 * Shares the same duration definition as the per-syscall block --
 * full unreusable-slot time (watchdog grace included), CLOCK_MONOTONIC,
 * clamped >= 0 at the accumulator site (see reap_child() in main.c) --
 * so the per-syscall total and the per-childop total over the run are
 * the same number; the two top-N rows just slice it differently.
 *
 * Empty-block gate: skipped entirely if no wedge has ever been
 * accounted on this axis, so a clean run emits nothing.
 */
static void dump_stats_top_wedging_childops(void)
{
	struct childop_wedge_top_entry {
		unsigned int op;
		unsigned long count;
		unsigned long long total_us;
	} top[WEDGE_TOPN];
	unsigned int top_count = 0;
	unsigned long count_total = 0;
	unsigned long long us_total = 0;
	unsigned int i;
	int j;

	for (i = 0; i < NR_CHILD_OP_TYPES; i++) {
		unsigned long c = __atomic_load_n(
			&shm->stats.childop_wedge_count[i],
			__ATOMIC_RELAXED);
		unsigned long long u = __atomic_load_n(
			&shm->stats.childop_wedge_total_us[i],
			__ATOMIC_RELAXED);

		if (c == 0 && u == 0)
			continue;

		count_total += c;
		us_total += u;

		/* Insertion sort, descending by total_us, capped at
		 * WEDGE_TOPN.  Ties on total_us broken by event count so a
		 * hot childop with many quick wedges ranks above a single
		 * still-pending wedge whose duration matches by accident. */
		for (j = (int)top_count;
		     j > 0 && (u > top[j - 1].total_us ||
			       (u == top[j - 1].total_us &&
				c > top[j - 1].count));
		     j--) {
			if (j < WEDGE_TOPN)
				top[j] = top[j - 1];
		}
		if (j < WEDGE_TOPN) {
			top[j].op = i;
			top[j].count = c;
			top[j].total_us = u;
			if (top_count < WEDGE_TOPN)
				top_count++;
		}
	}

	if (count_total == 0 && us_total == 0)
		return;

	output(0, "Top %u most-wedging childops (cumulative; %lu events, "
		"%llu.%03llu s wedged total):\n",
		top_count, count_total,
		us_total / 1000000ULL, (us_total / 1000ULL) % 1000ULL);

	for (j = 0; j < (int)top_count; j++) {
		const char *name = alt_op_name(
			(enum child_op_type) top[j].op);
		unsigned long long s = top[j].total_us / 1000000ULL;
		unsigned long long ms = (top[j].total_us / 1000ULL) % 1000ULL;
		unsigned long long avg_us = top[j].count > 0 ?
			(top[j].total_us / top[j].count) : 0;
		unsigned long long avg_s = avg_us / 1000000ULL;
		unsigned long long avg_ms = (avg_us / 1000ULL) % 1000ULL;

		output(0, "    %-32s events=%lu wedged=%llu.%03llus avg=%llu.%03llus\n",
			name ? name : "?", top[j].count, s, ms, avg_s, avg_ms);
	}
}

static void dump_stats_fd_tracking(void)
{
	if (parent_stats.fault_injected) {
		stat_row("fault_injection", "armed_fail_nth",  parent_stats.fault_injected);
		stat_row("fault_injection", "returned_enomem", parent_stats.fault_consumed);
	}

	if (shm->stats.fd_stale_detected || shm->stats.fd_closed_tracked ||
	    shm->stats.fd_stale_by_generation ||
	    shm->stats.fd_duped || shm->stats.fd_events_processed ||
	    shm->stats.fd_hash_reinsert_dropped ||
	    shm->stats.local_fd_hash_insert_dropped ||
	    shm->stats.epoll_lazy_armed ||
	    shm->stats.epoll_blocking_poll_skipped ||
	    shm->stats.fd_random_exhausted ||
	    shm->stats.fd_provider_invalid) {
		stat_row("fd_lifecycle", "stale_detected",      shm->stats.fd_stale_detected);
		stat_row("fd_lifecycle", "stale_by_generation", shm->stats.fd_stale_by_generation);
		stat_row("fd_lifecycle", "closed_tracked",      shm->stats.fd_closed_tracked);
		stat_row("fd_lifecycle", "duped",               shm->stats.fd_duped);
		stat_row("fd_lifecycle", "events_processed",    shm->stats.fd_events_processed);
		stat_row("fd_lifecycle", "events_dropped",      shm->stats.fd_events_dropped);
		stat_row("fd_lifecycle", "event_close_count",   shm->stats.fd_event_close_count);
		stat_row("fd_lifecycle", "event_evict_count",   shm->stats.fd_event_evict_count);
		stat_row("fd_lifecycle", "hash_reinsert_dropped", shm->stats.fd_hash_reinsert_dropped);
		stat_row("fd_lifecycle", "local_hash_insert_dropped",
			 shm->stats.local_fd_hash_insert_dropped);
		stat_row("fd_lifecycle", "epoll_lazy_armed",    shm->stats.epoll_lazy_armed);
		stat_row("fd_lifecycle", "epoll_blocking_poll_skipped",
			 shm->stats.epoll_blocking_poll_skipped);
		stat_row("fd_lifecycle", "random_exhausted",    shm->stats.fd_random_exhausted);
		stat_row("fd_lifecycle", "provider_invalid",    shm->stats.fd_provider_invalid);
	}

	/*
	 * Per-provider outstanding-fd gauge.  Only providers whose live
	 * count is non-zero get a row -- a clean run with no leaks emits
	 * nothing; a non-empty block at shutdown surfaces a per-provider
	 * fd leak (CLOSE events lost in the fd_event ring, an OBJ_GLOBAL
	 * registration whose subsequent close() bypassed remove_object_by_fd,
	 * etc.).  The label comes from the registered fd_provider name so
	 * the row matches --enable-fds/--disable-fds syntax; an entry whose
	 * objtype has no matching provider is skipped (defensive: should
	 * not happen, since the bump site fires only on a successful
	 * fd_hash_insert for an is_fd_type() objtype).
	 */
	{
		unsigned int t;

		for (t = 0; t < MAX_OBJECT_TYPES; t++) {
			unsigned long outstanding =
				shm->stats.fd_provider_outstanding[t];
			const char *name;

			if (outstanding == 0)
				continue;

			name = fd_provider_name((enum objecttype) t);
			if (name == NULL)
				continue;

			stat_row("fd_provider_outstanding", name, outstanding);
		}
	}

	/* Producer-side capture count for the typed-scalar bypass push.
	 * Sibling to kcov_shm->propagation_injected (consumer-side); see
	 * the field comment in include/stats.h.  Lives next to the
	 * fd_runtime_* family because its capture site is the same
	 * register_returned_fd dispatch -- the OBJ_KEY_SERIAL branch
	 * mirrors the value into prop_ring after handing it to the typed
	 * registrar. */
	if (shm->stats.propagation_injected_key_scalar) {
		stat_row("propagation", "injected_key_scalar",
			 shm->stats.propagation_injected_key_scalar);
	}
}


static void dump_stats_shared_buffer_misc(void)
{
	if (parent_stats.shared_buffer_redirected)
		stat_row("shared_buffer", "args_redirected",     parent_stats.shared_buffer_redirected);
	if (parent_stats.libc_heap_redirected)
		stat_row("shared_buffer", "libc_heap_redirected", parent_stats.libc_heap_redirected);
	if (parent_stats.libc_heap_embedded_redirected)
		stat_row("shared_buffer", "libc_heap_embedded_redirected",
			 parent_stats.libc_heap_embedded_redirected);
	if (parent_stats.asb_relocate_readable_skip)
		stat_row("shared_buffer", "asb_relocate_readable_skip",
			 parent_stats.asb_relocate_readable_skip);
	if (parent_stats.asb_relocate_copy_fault)
		stat_row("shared_buffer", "asb_relocate_copy_fault",
			 parent_stats.asb_relocate_copy_fault);
	if (parent_stats.heap_pointer_outside_cache)
		stat_row("shared_buffer", "heap_pointer_outside_cache",
			 parent_stats.heap_pointer_outside_cache);
	if (parent_stats.heap_brk_stale_window_hit)
		stat_row("shared_buffer", "heap_brk_stale_window_hit",
			 parent_stats.heap_brk_stale_window_hit);
	if (parent_stats.range_overlaps_shared_rejects) {
		stat_row("shared_buffer", "range_overlaps_shared_rejects",
			 parent_stats.range_overlaps_shared_rejects);
		if (verbosity > 1)
			dump_range_overlaps_shared_top_offenders();
	}
	if (shm->stats.shared_region_overflow)
		stat_row("shared_buffer", "shared_region_overflow",
			 shm->stats.shared_region_overflow);
	if (parent_stats.mm_gate_post_slip)
		stat_row("shared_buffer", "mm_gate_post_slip",
			 parent_stats.mm_gate_post_slip);
	if (parent_stats.children_recycled_on_storm)
		stat_row("corruption", "children_recycled_on_storm",
			 parent_stats.children_recycled_on_storm);
	if (parent_stats.watchdog_fd_evict)
		stat_row("watchdog", "watchdog_fd_evict",
			 parent_stats.watchdog_fd_evict);

	if (verbosity > 1)
		dump_syscall_category_histogram();
}


static void dump_stats_childop_runs_local(void)
{
	stat_category_emit_text(&refcount_audit_category);

	if (shm->stats.fs_lifecycle_tmpfs   || shm->stats.fs_lifecycle_ramfs   ||
	    shm->stats.fs_lifecycle_rdonly  || shm->stats.fs_lifecycle_overlay ||
	    shm->stats.fs_lifecycle_quota   || shm->stats.fs_lifecycle_bind    ||
	    shm->stats.fs_lifecycle_unsupported) {
		stat_row("fs_lifecycle", "tmpfs",       shm->stats.fs_lifecycle_tmpfs);
		stat_row("fs_lifecycle", "ramfs",       shm->stats.fs_lifecycle_ramfs);
		stat_row("fs_lifecycle", "rdonly",      shm->stats.fs_lifecycle_rdonly);
		stat_row("fs_lifecycle", "overlay",     shm->stats.fs_lifecycle_overlay);
		stat_row("fs_lifecycle", "quota",       shm->stats.fs_lifecycle_quota);
		stat_row("fs_lifecycle", "bind",        shm->stats.fs_lifecycle_bind);
		stat_row("fs_lifecycle", "unsupported", shm->stats.fs_lifecycle_unsupported);
	}

	stat_category_emit_text(&signal_storm_category);

	if (shm->stats.futex_storm_runs)
		output(0, "\nfutex storm: runs:%lu inner_crashed:%lu iters:%lu\n",
			shm->stats.futex_storm_runs,
			shm->stats.futex_storm_inner_crashed,
			shm->stats.futex_storm_iters);

	stat_category_emit_text(&pipe_thrash_category);

	stat_category_emit_text(&fork_storm_category);

	stat_category_emit_text(&cpu_hotplug_rider_category);

	stat_category_emit_text(&pidfd_storm_category);

	stat_category_emit_text(&madvise_cycler_category);

	stat_category_emit_text(&keyring_spam_category);

	stat_category_emit_text(&vdso_mremap_race_category);

	stat_category_emit_text(&flock_thrash_category);

	stat_category_emit_text(&xattr_thrash_category);

	stat_category_emit_text(&epoll_volatility_category);

	stat_category_emit_text(&cgroup_churn_category);

	stat_category_emit_text(&mount_churn_category);

	stat_category_emit_text(&umount_race_category);

	stat_category_emit_text(&statmount_idmap_category);

	stat_category_emit_text(&uffd_churn_category);

	stat_category_emit_text(&iouring_flood_category);

	stat_category_emit_text(&close_racer_category);
}


static void dump_stats_corpus_and_taint_tail(void)
{
	unsigned int i;

	if (minicorpus_shm != NULL) {
		unsigned long tot_trials = 0;
		unsigned long r_count, r_wins, s_hits, s_wins, pct10;
		unsigned long histo_total;
		char hbuf[80];
		int hpos;

		for (i = 0; i < MUT_NUM_OPS; i++)
			tot_trials += __atomic_load_n(&minicorpus_shm->mut_trials[i],
						      __ATOMIC_RELAXED);

		if (tot_trials > 0) {
			output(0, "\nMutator productivity (wins/trials  [structured wins/trials]):\n");
			for (i = 0; i < MUT_NUM_OPS; i++) {
				unsigned long t  = __atomic_load_n(&minicorpus_shm->mut_trials[i],
								   __ATOMIC_RELAXED);
				unsigned long w  = __atomic_load_n(&minicorpus_shm->mut_wins[i],
								   __ATOMIC_RELAXED);
				unsigned long st = __atomic_load_n(
					&minicorpus_shm->mut_structured_trials[i],
					__ATOMIC_RELAXED);
				unsigned long sw = __atomic_load_n(
					&minicorpus_shm->mut_structured_wins[i],
					__ATOMIC_RELAXED);
				unsigned long spct10 = st ? (sw * 1000UL / st) : 0UL;

				pct10 = t ? (w * 1000UL / t) : 0UL;
				output(0, "  %-10s %lu/%lu (%lu.%lu%%)  [%lu/%lu (%lu.%lu%%)]\n",
				       op_names[i], w, t, pct10 / 10, pct10 % 10,
				       sw, st, spct10 / 10, spct10 % 10);
			}
		}

		s_hits = __atomic_load_n(&minicorpus_shm->splice_hits, __ATOMIC_RELAXED);
		s_wins = __atomic_load_n(&minicorpus_shm->splice_wins, __ATOMIC_RELAXED);
		if (s_hits > 0) {
			pct10 = s_wins * 1000UL / s_hits;
			output(0, "Splice: %lu hits  %lu wins (%lu.%lu%%)\n",
			       s_hits, s_wins, pct10 / 10, pct10 % 10);
		}

		{
			unsigned long xp_hits = __atomic_load_n(
				&minicorpus_shm->xprop_hits, __ATOMIC_RELAXED);
			unsigned long xp_wins = __atomic_load_n(
				&minicorpus_shm->xprop_wins, __ATOMIC_RELAXED);

			if (xp_hits > 0) {
				pct10 = xp_wins * 1000UL / xp_hits;
				output(0, "Xprop: %lu hits  %lu wins (%lu.%lu%%)\n",
				       xp_hits, xp_wins, pct10 / 10, pct10 % 10);
			}
		}

		/* Lockless-reader torn-read validator firings (aggregate over
		 * xprop pick, replay common, replay burst).  Gated on non-zero
		 * because the expected steady-state value is 0 -- the writer's
		 * release-store publish pattern makes mid-publish reads rare.
		 * A non-zero rate here means the validator is doing real work
		 * and torn reads ARE happening at the printed rate. */
		{
			unsigned long torn = __atomic_load_n(
				&minicorpus_shm->replay_torn_rejects,
				__ATOMIC_RELAXED);

			if (torn > 0)
				output(0, "Corpus torn-read rejects: %lu\n", torn);
		}

		histo_total = 0;
		for (i = 1; i <= STACK_MAX; i++)
			histo_total += __atomic_load_n(&minicorpus_shm->stack_depth_histogram[i],
						       __ATOMIC_RELAXED);
		if (histo_total > 0) {
			int written;

			hpos = 0;
			for (i = 1; i <= STACK_MAX; i++) {
				unsigned long d = __atomic_load_n(
					&minicorpus_shm->stack_depth_histogram[i],
					__ATOMIC_RELAXED);
				/* Bound BEFORE snprintf — sizeof(hbuf)-hpos goes to
				 * zero when full, but snprintf still returns the
				 * would-have-written length and the next iteration's
				 * hbuf+hpos lands past the buffer.  Stop here. */
				if (hpos >= (int)sizeof(hbuf) - 1)
					break;
				written = snprintf(hbuf + hpos, sizeof(hbuf) - hpos,
						   " [%u]:%lu", i, d);
				if (written < 0)
					break;
				hpos += written;
			}
			output(0, "Stack depth:%s\n", hbuf);
		}

		r_count = __atomic_load_n(&minicorpus_shm->replay_count, __ATOMIC_RELAXED);
		r_wins  = __atomic_load_n(&minicorpus_shm->replay_wins,  __ATOMIC_RELAXED);
		if (r_count > 0) {
			pct10 = r_wins * 1000UL / r_count;
			output(0, "Corpus replay: %lu replays  %lu wins (%lu.%lu%%)\n",
			       r_count, r_wins, pct10 / 10, pct10 % 10);
		}

		/* CMP-source save / win telemetry.  Always emit when the
		 * minicorpus block is being dumped -- a zero on saves_cmp is
		 * itself a signal worth seeing ("the gate widening is in but
		 * the path isn't firing"), per the falsification criteria in
		 * the investigations/ analysis. */
		{
			unsigned long saves_pc = __atomic_load_n(
				&minicorpus_shm->saves_by_reason[CORPUS_SAVE_REASON_PC],
				__ATOMIC_RELAXED);
			unsigned long saves_cmp = __atomic_load_n(
				&minicorpus_shm->saves_by_reason[CORPUS_SAVE_REASON_CMP],
				__ATOMIC_RELAXED);
			unsigned long saves_errno = __atomic_load_n(
				&minicorpus_shm->saves_by_reason[CORPUS_SAVE_REASON_ERRNO],
				__ATOMIC_RELAXED);
			unsigned long cmp_wins = __atomic_load_n(
				&minicorpus_shm->mut_attrib_cmp_wins,
				__ATOMIC_RELAXED);
			unsigned long errno_would = __atomic_load_n(
				&shm->stats.errno_grad_save_would_save,
				__ATOMIC_RELAXED);
			unsigned long errno_did = __atomic_load_n(
				&shm->stats.errno_grad_save_did_save,
				__ATOMIC_RELAXED);

			output(0, "Corpus saves: pc=%lu cmp=%lu errno=%lu  mut wins (cmp-source): %lu\n",
			       saves_pc, saves_cmp, saves_errno, cmp_wins);
			output(0, "Errno-gradient save: would=%lu did=%lu (gate=%s)\n",
			       errno_would, errno_did,
			       corpus_save_errno_grad_live ? "live" : "shadow");
		}

		/*
		 * Per-tag productivity for the C.2b post-fill struct-field
		 * mutator.  Independent from the per-op MUT_NUM_OPS counters
		 * dumped above -- different injection point, different
		 * histogram axis.  Suppressed when the aggregate trial count
		 * is zero so a build / fleet that never invoked the path
		 * stays clean; a single non-zero slot brings the whole
		 * histogram into view so per-tag relative productivity
		 * (FT_FLAGS bit-flips vs FT_RAW noise) is greppable.
		 * Skip-listed tags (FT_PTR_*, FT_LEN_*, FT_FD, FT_ADDRESS,
		 * FT_BPF_PROGRAM, FT_TAGGED_UNION) stay zero by design and
		 * are silently skipped to keep the output compact.
		 */
		{
			static const char *const tag_names[FT_NUM_TAGS] = {
				[FT_RAW]		= "raw",
				[FT_ENUM]		= "enum",
				[FT_RANGE]		= "range",
				[FT_FLAGS]		= "flags",
				[FT_PTR_BYTES]		= "ptr_bytes",
				[FT_PTR_ARRAY]		= "ptr_array",
				[FT_PTR_STRUCT]		= "ptr_struct",
				[FT_LEN_BYTES]		= "len_bytes",
				[FT_LEN_COUNT]		= "len_count",
				[FT_FD]			= "fd",
				[FT_MAGIC]		= "magic",
				[FT_VERSION_MAGIC]	= "vermagic",
				[FT_ADDRESS]		= "address",
				[FT_TAGGED_UNION]	= "tagged_union",
				[FT_BPF_PROGRAM]	= "bpf_program",
				[FT_VOCAB]		= "vocab",
				[FT_PICKER]		= "picker",
			};
			unsigned long sf_total = 0;
			unsigned int t;

			for (t = 0; t < FT_NUM_TAGS; t++)
				sf_total += __atomic_load_n(
					&minicorpus_shm->mut_struct_field_trials[t],
					__ATOMIC_RELAXED);

			if (sf_total > 0) {
				output(0, "\nStruct-field mutator wins/trials (per tag):\n");
				for (t = 0; t < FT_NUM_TAGS; t++) {
					unsigned long tr = __atomic_load_n(
						&minicorpus_shm->mut_struct_field_trials[t],
						__ATOMIC_RELAXED);
					unsigned long wn = __atomic_load_n(
						&minicorpus_shm->mut_struct_field_wins[t],
						__ATOMIC_RELAXED);
					unsigned long tag_pct10;

					if (tr == 0 || tag_names[t] == NULL)
						continue;
					tag_pct10 = wn * 1000UL / tr;
					output(0, "  %-12s %lu/%lu (%lu.%lu%%)\n",
					       tag_names[t], wn, tr,
					       tag_pct10 / 10, tag_pct10 % 10);
				}
			}
		}

		{
			unsigned long c_iter = __atomic_load_n(
				&minicorpus_shm->chain_iter_count,
				__ATOMIC_RELAXED);
			unsigned long c_subst = __atomic_load_n(
				&minicorpus_shm->chain_substitution_count,
				__ATOMIC_RELAXED);
			unsigned long c_save = chain_corpus_shm ? __atomic_load_n(
				&chain_corpus_shm->save_count,
				__ATOMIC_RELAXED) : 0UL;
			unsigned long c_replay = chain_corpus_shm ? __atomic_load_n(
				&chain_corpus_shm->replay_count,
				__ATOMIC_RELAXED) : 0UL;

			if (c_iter > 0)
				output(0, "Sequence chains: %lu iters  %lu substitutions  %lu corpus saves  %lu replays\n",
				       c_iter, c_subst, c_save, c_replay);
		}
	}

	if (cmp_hints_shm != NULL) {
		unsigned int total_hints = 0, syscalls_with_hints = 0;
		unsigned int a;

		/* Per-arch slots count individually -- same rationale as the
		 * JSON emitter above. */
		for (i = 0; i < MAX_NR_SYSCALL; i++) {
			for (a = 0; a < 2; a++) {
				unsigned int n = cmp_hints_pool_safe_count(&cmp_hints_shm->pools[i][a]);

				if (n > 0) {
					total_hints += n;
					syscalls_with_hints++;
				}
			}
		}
		stat_row("cmp_hints", "values_total",        total_hints);
		stat_row("cmp_hints", "syscalls_with_hints", syscalls_with_hints);
	}

	/*
	 * Periodic snapshot of /proc/sys/kernel/tainted so successive
	 * stats dumps record when the kernel became tainted and which
	 * flags were set, without waiting for is_tainted()'s mask-gated
	 * "became tainted" trip.  Skipped on a clean kernel to match
	 * the "suppress when zero" convention of the surrounding blocks.
	 * mask row carries the raw bitmask; one row per recognised flag
	 * makes the decoded set greppable.
	 */
	{
		static const struct {
			const char *name;
			int bit;
		} taint_flags[] = {
			{ "PROPRIETARY_MODULE",    TAINT_PROPRIETARY_MODULE },
			{ "FORCED_MODULE",         TAINT_FORCED_MODULE },
			{ "UNSAFE_SMP",            TAINT_UNSAFE_SMP },
			{ "FORCED_RMMOD",          TAINT_FORCED_RMMOD },
			{ "MACHINE_CHECK",         TAINT_MACHINE_CHECK },
			{ "BAD_PAGE",              TAINT_BAD_PAGE },
			{ "USER",                  TAINT_USER },
			{ "DIE",                   TAINT_DIE },
			{ "OVERRIDDEN_ACPI_TABLE", TAINT_OVERRIDDEN_ACPI_TABLE },
			{ "WARN",                  TAINT_WARN },
			{ "CRAP",                  TAINT_CRAP },
			{ "FIRMWARE_WORKAROUND",   TAINT_FIRMWARE_WORKAROUND },
			{ "OOT_MODULE",            TAINT_OOT_MODULE },
		};
		int current_taint = get_taint();
		unsigned int t;

		if (current_taint != 0) {
			stat_row("taint", "mask", (unsigned long)current_taint);
			for (t = 0; t < ARRAY_SIZE(taint_flags); t++)
				if (current_taint & (1U << taint_flags[t].bit))
					stat_row("taint", taint_flags[t].name, 1);
		}
	}
}

/*
 * SHADOW reader for the per-childop decaying edge+wall recency ring.
 * Emits one "childop_decay:" line per op that has been invoked at least
 * once this run, carrying the cached recent-edge and recent-wall totals
 * across the last CHILDOP_DECAY_WINDOWS rotations alongside the
 * cumulative childop_edges_clean[] / childop_wall_ns[] denominators so
 * the operator can read recent vs lifetime yield in the same row.  No
 * scheduler / picker / canary path reads either ring -- the dump is the
 * only consumer today; the C2 spec's future util-table extension is the
 * next consumer.  Skips CHILD_OP_SYSCALL (the syscall path attributes
 * its work through the per-strategy counters, matching the surrounding
 * per-childop dumps) and skips never-invoked ops (skip-zero convention).
 */
void __cold dump_stats_childop_decay_recency(void)
{
	enum child_op_type op;
	unsigned int slot;
	bool any = false;

	slot = __atomic_load_n(&shm->stats.childop_decay_slot,
			       __ATOMIC_RELAXED);

	for (op = CHILD_OP_SYSCALL + 1; op < NR_CHILD_OP_TYPES; op++) {
		unsigned long invocations, recent_edges, recent_wall;
		unsigned long cum_edges, cum_wall;

		invocations = __atomic_load_n(
				&shm->stats.childop_invocations[op],
				__ATOMIC_RELAXED);
		if (invocations == 0)
			continue;

		recent_edges = __atomic_load_n(
				&shm->stats.childop_edge_recent_cached[op],
				__ATOMIC_RELAXED);
		recent_wall = __atomic_load_n(
				&shm->stats.childop_wall_recent_cached[op],
				__ATOMIC_RELAXED);
		cum_edges = __atomic_load_n(
				&shm->stats.childop_edges_clean[op],
				__ATOMIC_RELAXED);
		cum_wall = __atomic_load_n(
				&shm->stats.childop_wall_ns[op],
				__ATOMIC_RELAXED);

		if (!any) {
			output(1,
			       "childop_decay: per-op recent edges+wall over "
			       "last %u windows (slot=%u)\n",
			       (unsigned int)CHILDOP_DECAY_WINDOWS,
			       slot & (CHILDOP_DECAY_WINDOWS - 1));
			any = true;
		}

		output(1,
		       "childop_decay %s: invocations=%lu recent_edges=%lu recent_wall_ns=%lu cum_edges=%lu cum_wall_ns=%lu\n",
		       alt_op_name(op), invocations,
		       recent_edges, recent_wall, cum_edges, cum_wall);
	}
}

void __cold dump_stats_topo_pair_shadow(void)
{
	/* Per-setup_op aggregates from the surviving ring entries.  Sized
	 * by NR_CHILD_OP_TYPES so a corrupted setup_op byte that masks to
	 * the sentinel value is still in-bounds; the loop skips
	 * NR_CHILD_OP_TYPES at render time so the sentinel slot stays
	 * inert.  Local-stack to avoid touching shm for the aggregate. */
	unsigned long per_op_pc[NR_CHILD_OP_TYPES] = { 0 };
	unsigned long per_op_trans[NR_CHILD_OP_TYPES] = { 0 };
	unsigned long per_op_age_sum[NR_CHILD_OP_TYPES] = { 0 };
	unsigned long total_records, no_setup, head, total_valid = 0;
	unsigned int i;

	total_records = __atomic_load_n(&shm->stats.topo_pair_records,
					__ATOMIC_RELAXED);
	no_setup = __atomic_load_n(&shm->stats.topo_pair_no_setup_observed,
				   __ATOMIC_RELAXED);

	/* Self-skip when no productive event has fired through the ring
	 * AND no event has been dropped to the no-setup denominator -- in
	 * that state the row would carry no signal at all, and emitting a
	 * blank "shadow active, ring empty" line just adds noise to the
	 * shutdown dump.  Matches the dump_stats_top_wedging_childops()
	 * self-skip pattern. */
	if (total_records == 0 && no_setup == 0)
		return;

	head = __atomic_load_n(&shm->stats.topo_pair_ring_head,
			       __ATOMIC_RELAXED);

	for (i = 0; i < TOPO_PAIR_RING_SIZE; i++) {
		uint64_t packed;
		unsigned int setup_op, reason, syscall_nr, age;

		packed = __atomic_load_n(&shm->stats.topo_pair_ring[i],
					 __ATOMIC_RELAXED);
		if (!topo_pair_unpack(packed, &setup_op, &reason,
				      &syscall_nr, &age))
			continue;
		/* Defensive bounds check: the producer's topo_pair_pack()
		 * AND-masks setup_op to 8 bits, so a sentinel-or-corrupt
		 * value cast from NR_CHILD_OP_TYPES would not be filtered
		 * by the producer's branch alone.  Skip rather than scribble
		 * past the per_op_* arrays. */
		if (setup_op >= NR_CHILD_OP_TYPES)
			continue;
		if (reason == TOPO_PAIR_REASON_PC)
			per_op_pc[setup_op]++;
		else if (reason == TOPO_PAIR_REASON_TRANSITION)
			per_op_trans[setup_op]++;
		else
			continue;
		per_op_age_sum[setup_op] += age;
		total_valid++;
	}

	output(0,
	       "topo_pair_shadow: events_total=%lu sample_window=%u "
	       "valid_in_ring=%lu no_setup_observed=%lu head=%lu wrapped=%s\n",
	       total_records, (unsigned int)TOPO_PAIR_RING_SIZE,
	       total_valid, no_setup, head,
	       total_records >= (unsigned long)TOPO_PAIR_RING_SIZE
	       ? "yes" : "no");

	if (total_valid == 0)
		return;

	for (i = 0; i < NR_CHILD_OP_TYPES; i++) {
		unsigned long n;
		unsigned long mean_age;
		const char *name;

		n = per_op_pc[i] + per_op_trans[i];
		if (n == 0)
			continue;

		mean_age = per_op_age_sum[i] / n;
		name = alt_op_name((enum child_op_type)i);
		output(0,
		       "topo_pair_shadow %s: samples=%lu pc=%lu transition=%lu mean_age=%lu\n",
		       name ? name : "?", n,
		       per_op_pc[i], per_op_trans[i], mean_age);
	}
}

void __cold dump_stats(void)
{
	if (stats_json) {
		dump_stats_json();
		return;
	}

	/* Lead the shutdown report with the run-identity block so the
	 * provenance triple + cold/warm carrier state + own-start deltas
	 * are the first thing an operator sees -- the post-mortem hook a
	 * "did this run actually advance coverage" check needs before
	 * any of the downstream tables can be interpreted. */
	stats_runid_render();

	dump_stats_runtime_header();

	dump_stats_per_syscall_tables();

	dump_stats_top_wedging_syscalls();

	dump_stats_top_wedging_childops();

	dump_stats_fd_tracking();

	dump_stats_oracle_anomalies();

	dump_stats_fuzzer_subsystems();

	dump_stats_corruption_and_pool();

	dump_stats_childop_ranked_tables();

	childop_score_dump();

	childop_outcome_window_dump();

	dump_stats_childop_decay_recency();

	dump_stats_topo_pair_shadow();

	dump_stats_shared_buffer_misc();

	dump_stats_strategy_summary();

	dump_stats_childop_runs_local();

	dump_stats_childop_runs_network();

	dump_stats_kcov_block();

	dump_stats_corpus_and_taint_tail();

	/* Cumulative childop vs random-syscall effort split.  Also emitted
	 * mid-run from defense_counters_periodic_dump on the 600 s cadence
	 * for long-fuzz visibility, but a short --dry-run (or any run that
	 * exits before the first periodic dump fires) still needs to see
	 * the block, so emit it unconditionally from the shutdown dump too.
	 * Self-skips silently if no dispatch has happened yet. */
	childop_split_dump();
}
