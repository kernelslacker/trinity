#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/utsname.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "arch.h"
#include "arg-len-semantics.h"
#include "breadcrumb_ring.h"
#include "child-api.h"
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
#include "shadow_promote.h"
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "stats_ring.h"
#include "strategy.h"		/* frontier_spare_lane_decide, enum frontier_spare_reason */
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "utils.h"
#include "utils-proc.h"
#include "version.h"

static void dump_stats_render_vfs_writes(void)
{
	if (shm->stats.procfs_writer.procfs_open_fail || shm->stats.procfs_writer.procfs_write_fail ||
	    shm->stats.procfs_writer.procfs_write_ok ||
	    shm->stats.procfs_writer.sysfs_open_fail || shm->stats.procfs_writer.sysfs_write_fail ||
	    shm->stats.procfs_writer.sysfs_write_ok ||
	    shm->stats.procfs_writer.debugfs_open_fail || shm->stats.procfs_writer.debugfs_write_fail ||
	    shm->stats.procfs_writer.debugfs_write_ok) {
		stat_row("vfs_writes", "procfs_open_fail",   shm->stats.procfs_writer.procfs_open_fail);
		stat_row("vfs_writes", "procfs_write_fail",  shm->stats.procfs_writer.procfs_write_fail);
		stat_row("vfs_writes", "procfs_write_ok",    shm->stats.procfs_writer.procfs_write_ok);
		stat_row("vfs_writes", "sysfs_open_fail",    shm->stats.procfs_writer.sysfs_open_fail);
		stat_row("vfs_writes", "sysfs_write_fail",   shm->stats.procfs_writer.sysfs_write_fail);
		stat_row("vfs_writes", "sysfs_write_ok",     shm->stats.procfs_writer.sysfs_write_ok);
		stat_row("vfs_writes", "debugfs_open_fail",  shm->stats.procfs_writer.debugfs_open_fail);
		stat_row("vfs_writes", "debugfs_write_fail", shm->stats.procfs_writer.debugfs_write_fail);
		stat_row("vfs_writes", "debugfs_write_ok",   shm->stats.procfs_writer.debugfs_write_ok);
	}
}

static void dump_stats_render_memory_pressure(void)
{
	if (shm->stats.memory_pressure.runs)
		stat_row("memory_pressure", "runs_madv_pageout", shm->stats.memory_pressure.runs);
}

static void dump_stats_render_genetlink(void)
{
	if (shm->stats.genetlink_fuzzer.families_discovered ||
	    shm->stats.genetlink_fuzzer.discovery_cycles       ||
	    shm->stats.genetlink_fuzzer.msgs_sent              ||
	    shm->stats.genetlink_fuzzer.missing_producer       ||
	    shm->stats.genetlink_fuzzer.discovery_io_err       ||
	    shm->stats.genetlink_fuzzer.discovery_nlerr        ||
	    shm->stats.genetlink_fuzzer.userns_run_fail        ||
	    shm->stats.genetlink_fuzzer.in_ns_open_fail        ||
	    shm->stats.genetlink_fuzzer.send_drain_fail) {
		stat_row("genetlink_fuzzer", "families_discovered", shm->stats.genetlink_fuzzer.families_discovered);
		stat_row("genetlink_fuzzer", "discovery_cycles",    shm->stats.genetlink_fuzzer.discovery_cycles);
		stat_row("genetlink_fuzzer", "msgs_sent",           shm->stats.genetlink_fuzzer.msgs_sent);
		stat_row("genetlink_fuzzer", "eperm",               shm->stats.genetlink_fuzzer.eperm);
		stat_row("genetlink_fuzzer", "stale_seq_drops",     shm->stats.genetlink_fuzzer.stale_seq_drops);
		stat_row("genetlink_fuzzer", "missing_producer",    shm->stats.genetlink_fuzzer.missing_producer);
		stat_row("genetlink_fuzzer", "discovery_io_err",    shm->stats.genetlink_fuzzer.discovery_io_err);
		stat_row("genetlink_fuzzer", "discovery_nlerr",     shm->stats.genetlink_fuzzer.discovery_nlerr);
		stat_row("genetlink_fuzzer", "userns_run_fail",     shm->stats.genetlink_fuzzer.userns_run_fail);
		stat_row("genetlink_fuzzer", "in_ns_open_fail",     shm->stats.genetlink_fuzzer.in_ns_open_fail);
		stat_row("genetlink_fuzzer", "send_drain_fail",     shm->stats.genetlink_fuzzer.send_drain_fail);
	}
}

static void dump_stats_render_genl_family_calls(void)
{
	if (shm->stats.genl_family_calls_devlink   ||
	    shm->stats.genl_family_calls_nl80211   ||
	    shm->stats.genl_family_calls_taskstats ||
	    shm->stats.genl_family_calls_ethtool   ||
	    shm->stats.genl_family_calls_mptcp_pm  ||
	    shm->stats.genl_family_calls_tipc      ||
	    shm->stats.genl_family_calls_wireguard ||
	    shm->stats.genl_family_calls_netlabel  ||
	    shm->stats.genl_family_calls_team      ||
	    shm->stats.genl_family_calls_hsr       ||
	    shm->stats.genl_family_calls_fou       ||
	    shm->stats.genl_family_calls_psample   ||
	    shm->stats.genl_family_calls_nfsd      ||
	    shm->stats.genl_family_calls_ila       ||
	    shm->stats.genl_family_calls_ioam6     ||
	    shm->stats.genl_family_calls_seg6      ||
	    shm->stats.genl_family_calls_thermal   ||
	    shm->stats.genl_family_calls_ipvs) {
		stat_row("genl_family_calls", "devlink",   shm->stats.genl_family_calls_devlink);
		stat_row("genl_family_calls", "nl80211",   shm->stats.genl_family_calls_nl80211);
		stat_row("genl_family_calls", "taskstats", shm->stats.genl_family_calls_taskstats);
		stat_row("genl_family_calls", "ethtool",   shm->stats.genl_family_calls_ethtool);
		stat_row("genl_family_calls", "mptcp_pm",  shm->stats.genl_family_calls_mptcp_pm);
		stat_row("genl_family_calls", "tipc",      shm->stats.genl_family_calls_tipc);
		stat_row("genl_family_calls", "wireguard", shm->stats.genl_family_calls_wireguard);
		stat_row("genl_family_calls", "netlabel",  shm->stats.genl_family_calls_netlabel);
		stat_row("genl_family_calls", "team",      shm->stats.genl_family_calls_team);
		stat_row("genl_family_calls", "hsr",       shm->stats.genl_family_calls_hsr);
		stat_row("genl_family_calls", "fou",       shm->stats.genl_family_calls_fou);
		stat_row("genl_family_calls", "psample",   shm->stats.genl_family_calls_psample);
		stat_row("genl_family_calls", "nfsd",      shm->stats.genl_family_calls_nfsd);
		stat_row("genl_family_calls", "ila",       shm->stats.genl_family_calls_ila);
		stat_row("genl_family_calls", "ioam6",     shm->stats.genl_family_calls_ioam6);
		stat_row("genl_family_calls", "seg6",      shm->stats.genl_family_calls_seg6);
		stat_row("genl_family_calls", "thermal",   shm->stats.genl_family_calls_thermal);
		stat_row("genl_family_calls", "ipvs",      shm->stats.genl_family_calls_ipvs);
	}
}

static void dump_stats_render_nfnl_subsys(void)
{
	if (shm->stats.nfnl_subsys_calls_ctnetlink     ||
	    shm->stats.nfnl_subsys_calls_ctnetlink_exp ||
	    shm->stats.nfnl_subsys_calls_nftables      ||
	    shm->stats.nfnl_subsys_calls_ipset) {
		stat_row("nfnl_subsys_calls", "ctnetlink",     shm->stats.nfnl_subsys_calls_ctnetlink);
		stat_row("nfnl_subsys_calls", "ctnetlink_exp", shm->stats.nfnl_subsys_calls_ctnetlink_exp);
		stat_row("nfnl_subsys_calls", "nftables",      shm->stats.nfnl_subsys_calls_nftables);
		stat_row("nfnl_subsys_calls", "ipset",         shm->stats.nfnl_subsys_calls_ipset);
	}
}

static void dump_stats_render_netlink_generator(void)
{
	if (shm->stats.netlink_nested_attrs_emitted)
		stat_row("netlink_generator", "nested_attrs_emitted",
			 shm->stats.netlink_nested_attrs_emitted);
	if (shm->stats.netlink_nested_attrs_accepted)
		stat_row("netlink_generator", "nested_attrs_accepted",
			 shm->stats.netlink_nested_attrs_accepted);
	if (shm->stats.netlink_nested_attr_skipped_width)
		stat_row("netlink_generator", "nested_attr_skipped_width",
			 shm->stats.netlink_nested_attr_skipped_width);
	if (shm->stats.netlink_nested_attr_built_width)
		stat_row("netlink_generator", "nested_attr_built_width",
			 shm->stats.netlink_nested_attr_built_width);
	if (shm->stats.netlink_nested_attr_build_calls)
		stat_row("netlink_generator", "nested_attr_build_calls",
			 shm->stats.netlink_nested_attr_build_calls);
	if (shm->stats.netlink_nested_attr_lost_align)
		stat_row("netlink_generator", "nested_attr_lost_align",
			 shm->stats.netlink_nested_attr_lost_align);
}

static void dump_stats_render_rtnl_ack_oracle(void)
{
	const struct rtnl_ack_oracle_stats *o = &shm->stats.rtnl_ack_oracle;
	unsigned int i;

	if (!o->accepted && !o->einval && !o->erange &&
	    !o->eopnotsupp && !o->eperm && !o->other &&
	    !o->send_fail && !o->no_reply_exhausted && !o->no_reply_clean &&
	    !o->bad_framing &&
	    !o->stale_done && !o->stale_other &&
	    !o->stale_foreign_ack && !o->stale_undersized &&
	    !o->stale_truncated && !o->stale_unparsed &&
	    !o->dump_skipped &&
	    !o->recv_enobufs && !o->recv_eintr && !o->recv_error)
		return;

	stat_row("rtnl_ack_oracle", "accepted",      o->accepted);
	stat_row("rtnl_ack_oracle", "einval",        o->einval);
	stat_row("rtnl_ack_oracle", "erange",        o->erange);
	stat_row("rtnl_ack_oracle", "eopnotsupp",    o->eopnotsupp);
	stat_row("rtnl_ack_oracle", "eperm",         o->eperm);
	stat_row("rtnl_ack_oracle", "other",         o->other);
	stat_row("rtnl_ack_oracle", "send_fail",          o->send_fail);
	stat_row("rtnl_ack_oracle", "no_reply_exhausted", o->no_reply_exhausted);
	stat_row("rtnl_ack_oracle", "no_reply_clean",     o->no_reply_clean);
	stat_row("rtnl_ack_oracle", "bad_framing",        o->bad_framing);
	stat_row("rtnl_ack_oracle", "stale_done",         o->stale_done);
	stat_row("rtnl_ack_oracle", "stale_other",        o->stale_other);
	stat_row("rtnl_ack_oracle", "stale_foreign_ack",  o->stale_foreign_ack);
	stat_row("rtnl_ack_oracle", "stale_undersized",   o->stale_undersized);
	stat_row("rtnl_ack_oracle", "stale_truncated",    o->stale_truncated);
	stat_row("rtnl_ack_oracle", "stale_unparsed",     o->stale_unparsed);
	stat_row("rtnl_ack_oracle", "dump_skipped",       o->dump_skipped);
	stat_row("rtnl_ack_oracle", "recv_enobufs",       o->recv_enobufs);
	stat_row("rtnl_ack_oracle", "recv_eintr",         o->recv_eintr);
	stat_row("rtnl_ack_oracle", "recv_error",         o->recv_error);

	/* Per-RTM-group accepted counts: emit only non-zero entries.
	 * group 0 = RTM_NEW/DEL/GET/SETLINK, group 1 = *ADDR, etc. */
	{
		char key[32];

		for (i = 0; i < RTNL_ACK_ORACLE_MAX_GROUPS; i++) {
			if (!o->type_accepted_per_group[i])
				continue;
			(void)snprintf(key, sizeof(key),
				       "accepted_rtm_grp%u", i);
			stat_row("rtnl_ack_oracle", key,
				 o->type_accepted_per_group[i]);
		}
	}
}

static void dump_stats_render_kvm(void)
{
	if (shm->stats.kvm.vcpu_ioctls_dispatched)
		stat_row("kvm", "vcpu_ioctls_dispatched", shm->stats.kvm.vcpu_ioctls_dispatched);

	if (shm->stats.kvm.vm_ioctls_dispatched)
		stat_row("kvm", "vm_ioctls_dispatched", shm->stats.kvm.vm_ioctls_dispatched);

	if (shm->stats.kvm.reclaim_prefault_ok ||
	    shm->stats.kvm.reclaim_prefault_eopnotsupp ||
	    shm->stats.kvm.reclaim_prefault_err) {
		stat_row("kvm_reclaim_race", "reclaim_prefault_ok",
			 shm->stats.kvm.reclaim_prefault_ok);
		stat_row("kvm_reclaim_race", "reclaim_prefault_eopnotsupp",
			 shm->stats.kvm.reclaim_prefault_eopnotsupp);
		stat_row("kvm_reclaim_race", "reclaim_prefault_err",
			 shm->stats.kvm.reclaim_prefault_err);
	}

	if (shm->stats.kvm.reclaim_set_nr_mmu_ok ||
	    shm->stats.kvm.reclaim_set_nr_mmu_err) {
		stat_row("kvm_reclaim_race", "reclaim_set_nr_mmu_ok",
			 shm->stats.kvm.reclaim_set_nr_mmu_ok);
		stat_row("kvm_reclaim_race", "reclaim_set_nr_mmu_err",
			 shm->stats.kvm.reclaim_set_nr_mmu_err);
	}

	if (shm->stats.kvm.reclaim_memslot_ok)
		stat_row("kvm_reclaim_race", "reclaim_memslot_ok",
			 shm->stats.kvm.reclaim_memslot_ok);
}

static void dump_stats_render_tracefs(void)
{
	if (shm->stats.tracefs_fuzzer.kprobe_open_fail || shm->stats.tracefs_fuzzer.kprobe_write_fail ||
	    shm->stats.tracefs_fuzzer.kprobe_write_ok ||
	    shm->stats.tracefs_fuzzer.uprobe_open_fail || shm->stats.tracefs_fuzzer.uprobe_write_fail ||
	    shm->stats.tracefs_fuzzer.uprobe_write_ok ||
	    shm->stats.tracefs_fuzzer.filter_open_fail || shm->stats.tracefs_fuzzer.filter_write_fail ||
	    shm->stats.tracefs_fuzzer.filter_write_ok ||
	    shm->stats.tracefs_fuzzer.event_enable_open_fail || shm->stats.tracefs_fuzzer.event_enable_write_fail ||
	    shm->stats.tracefs_fuzzer.event_enable_write_ok ||
	    shm->stats.tracefs_fuzzer.misc_open_fail || shm->stats.tracefs_fuzzer.misc_write_fail ||
	    shm->stats.tracefs_fuzzer.misc_write_ok ||
	    shm->stats.tracefs_fuzzer.dynevent_open_fail || shm->stats.tracefs_fuzzer.dynevent_write_fail ||
	    shm->stats.tracefs_fuzzer.dynevent_write_ok ||
	    shm->stats.tracefs_fuzzer.set_event_open_fail || shm->stats.tracefs_fuzzer.set_event_write_fail ||
	    shm->stats.tracefs_fuzzer.set_event_write_ok) {
		stat_row("tracefs_fuzzer", "kprobe_open_fail",         shm->stats.tracefs_fuzzer.kprobe_open_fail);
		stat_row("tracefs_fuzzer", "kprobe_write_fail",        shm->stats.tracefs_fuzzer.kprobe_write_fail);
		stat_row("tracefs_fuzzer", "kprobe_write_ok",          shm->stats.tracefs_fuzzer.kprobe_write_ok);
		stat_row("tracefs_fuzzer", "uprobe_open_fail",         shm->stats.tracefs_fuzzer.uprobe_open_fail);
		stat_row("tracefs_fuzzer", "uprobe_write_fail",        shm->stats.tracefs_fuzzer.uprobe_write_fail);
		stat_row("tracefs_fuzzer", "uprobe_write_ok",          shm->stats.tracefs_fuzzer.uprobe_write_ok);
		stat_row("tracefs_fuzzer", "filter_open_fail",         shm->stats.tracefs_fuzzer.filter_open_fail);
		stat_row("tracefs_fuzzer", "filter_write_fail",        shm->stats.tracefs_fuzzer.filter_write_fail);
		stat_row("tracefs_fuzzer", "filter_write_ok",          shm->stats.tracefs_fuzzer.filter_write_ok);
		stat_row("tracefs_fuzzer", "event_enable_open_fail",   shm->stats.tracefs_fuzzer.event_enable_open_fail);
		stat_row("tracefs_fuzzer", "event_enable_write_fail",  shm->stats.tracefs_fuzzer.event_enable_write_fail);
		stat_row("tracefs_fuzzer", "event_enable_write_ok",    shm->stats.tracefs_fuzzer.event_enable_write_ok);
		stat_row("tracefs_fuzzer", "misc_open_fail",           shm->stats.tracefs_fuzzer.misc_open_fail);
		stat_row("tracefs_fuzzer", "misc_write_fail",          shm->stats.tracefs_fuzzer.misc_write_fail);
		stat_row("tracefs_fuzzer", "misc_write_ok",            shm->stats.tracefs_fuzzer.misc_write_ok);
		stat_row("tracefs_fuzzer", "dynevent_open_fail",       shm->stats.tracefs_fuzzer.dynevent_open_fail);
		stat_row("tracefs_fuzzer", "dynevent_write_fail",      shm->stats.tracefs_fuzzer.dynevent_write_fail);
		stat_row("tracefs_fuzzer", "dynevent_write_ok",        shm->stats.tracefs_fuzzer.dynevent_write_ok);
		stat_row("tracefs_fuzzer", "set_event_open_fail",     shm->stats.tracefs_fuzzer.set_event_open_fail);
		stat_row("tracefs_fuzzer", "set_event_write_fail",   shm->stats.tracefs_fuzzer.set_event_write_fail);
		stat_row("tracefs_fuzzer", "set_event_write_ok",     shm->stats.tracefs_fuzzer.set_event_write_ok);
	}
}

static void dump_stats_render_bpf_fd_provider(void)
{
	if (shm->stats.ebpf_gen.maps_provided || shm->stats.ebpf_gen.progs_provided) {
		stat_row("bpf_fd_provider", "maps_provided",  shm->stats.ebpf_gen.maps_provided);
		stat_row("bpf_fd_provider", "progs_provided", shm->stats.ebpf_gen.progs_provided);
	}
}

static void dump_stats_render_ebpf_gen(void)
{
	if (shm->stats.ebpf_gen.map_fd_substituted) {
		stat_row("ebpf_gen", "map_fd_substituted",
			 shm->stats.ebpf_gen.map_fd_substituted);
	}

	if (shm->stats.ebpf_gen.helper_call_emitted) {
		stat_row("ebpf_gen", "helper_call_emitted",
			 shm->stats.ebpf_gen.helper_call_emitted);
	}

	if (shm->stats.ebpf_gen.map_value_deref_emitted) {
		stat_row("ebpf_gen", "map_value_deref_emitted",
			 shm->stats.ebpf_gen.map_value_deref_emitted);
		stat_row("ebpf_gen", "map_value_deref_read",
			 shm->stats.ebpf_gen.map_value_deref_read);
		stat_row("ebpf_gen", "map_value_deref_write",
			 shm->stats.ebpf_gen.map_value_deref_write);
	}
}

static void dump_stats_render_recipe_runner(void)
{
	if (shm->stats.recipe.runs) {
		stat_row("recipe_runner", "runs",        shm->stats.recipe.runs);
		stat_row("recipe_runner", "completed",   shm->stats.recipe.completed);
		stat_row("recipe_runner", "partial",     shm->stats.recipe.partial);
		stat_row("recipe_runner", "unsupported", shm->stats.recipe.unsupported);
		recipe_runner_dump_stats();
	}
}

static void dump_stats_render_iouring(void)
{
	if (shm->stats.iouring_recipes.runs) {
		stat_row("iouring_recipes", "runs",      shm->stats.iouring_recipes.runs);
		stat_row("iouring_recipes", "completed", shm->stats.iouring_recipes.completed);
		stat_row("iouring_recipes", "partial",   shm->stats.iouring_recipes.partial);
		stat_row("iouring_recipes", "enosys",    shm->stats.iouring_recipes.enosys);
		iouring_recipes_dump_stats();
	}

	if (shm->stats.iouring_eventfd.register_ok ||
	    shm->stats.iouring_eventfd.register_fail) {
		stat_row("iouring_eventfd", "register_ok",
			 shm->stats.iouring_eventfd.register_ok);
		stat_row("iouring_eventfd", "register_fail",
			 shm->stats.iouring_eventfd.register_fail);
		stat_row("iouring_eventfd", "recursive_runs",
			 shm->stats.iouring_eventfd.recursive_runs);
		stat_row("iouring_eventfd", "recursive_cqes",
			 shm->stats.iouring_eventfd.recursive_cqes);
	}
}

static void dump_stats_render_zombie_slots(void)
{
	if (shm->stats.zombie_reaper.reaped || shm->stats.zombie_reaper.timed_out ||
	    shm->stats.zombie_reaper.slots_pending ||
	    shm->stats.zombie_reaper.quarantined) {
		stat_row("zombie_slots", "pending",     shm->stats.zombie_reaper.slots_pending);
		stat_row("zombie_slots", "reaped",      shm->stats.zombie_reaper.reaped);
		stat_row("zombie_slots", "timed_out",   shm->stats.zombie_reaper.timed_out);
		stat_row("zombie_slots", "quarantined", shm->stats.zombie_reaper.quarantined);
	}
}

/*
 * Dead-arm detection: for each childop arm that books an arm_entered
 * tally at its top, report any arm whose counter is still 0 over a
 * full run while its parent childop ran at least once.  An arm with
 * arm_entered == 0 is either structurally unreachable on this kernel
 * (config-dead), permanently gate-rejected (cap-gate latched before
 * the arm), or unreachable from the dispatch path (modulo-routing bug
 * like igmp RACE E before the iter_idx-bias fix).  The value rendered is the
 * parent's runs count so the operator can see how many invocations
 * the dead arm survived undetected.
 *
 * Sample floor: before emitting DEAD_ARM for a group, require
 * sum(arm_entered_*) >= 5 * nr_arms for that group.  Short runs (smoke,
 * -C 4, N~200) cannot accumulate enough draws across a multi-way
 * selector to guarantee every arm fires, so checking without this
 * floor produces spurious DEAD_ARM on every smoke invocation.  When
 * the floor is not met, emit one DEAD_ARM_SKIP line so absence is
 * explicit and grep-able.
 *
 * For single-arm groups the floor must gate on the group's opportunity
 * count (runs), NOT on the arm's own entry count.  arm_entered==0 IS the
 * dead state for a single-arm group; gating on it makes the floor a
 * tautology that always fires, permanently masking the dead verdict.
 *
 * Model: stat_row("DEAD_ARM", "<childop>/<arm>", <parent_runs>).
 *        output "DEAD_ARM_SKIP <group> insufficient_samples" when below floor.
 * Pairs with dump_stats_render_childop_missing_producer() which catches
 * ops that never set up a setup_accepted producer.
 */
static void dump_stats_dead_arm_check(void)
{
	/* igmp-mld-source-churn: five v4 race arms (A-E, rnd_modulo_u32(5))
	 * and four v6 race arms (A-D, iter_idx-derived 4-way modulo).
	 * Floor: v4 requires 5*5=25 total draws; v6 requires 5*4=20. */
	if (shm->stats.igmp_mld_source_churn.runs > 0) {
		const unsigned long pr = shm->stats.igmp_mld_source_churn.runs;
		unsigned long v4_draws, v6_draws;

		v4_draws =
			shm->stats.igmp_mld_source_churn.arm_entered_race_v4_a +
			shm->stats.igmp_mld_source_churn.arm_entered_race_v4_b +
			shm->stats.igmp_mld_source_churn.arm_entered_race_v4_c +
			shm->stats.igmp_mld_source_churn.arm_entered_race_v4_d +
			shm->stats.igmp_mld_source_churn.arm_entered_race_v4_e;
		if (v4_draws >= 5 * 5) {
			if (!shm->stats.igmp_mld_source_churn.arm_entered_race_v4_a)
				stat_row("DEAD_ARM", "igmp-mld-source-churn/race_v4_a", pr);
			if (!shm->stats.igmp_mld_source_churn.arm_entered_race_v4_b)
				stat_row("DEAD_ARM", "igmp-mld-source-churn/race_v4_b", pr);
			if (!shm->stats.igmp_mld_source_churn.arm_entered_race_v4_c)
				stat_row("DEAD_ARM", "igmp-mld-source-churn/race_v4_c", pr);
			if (!shm->stats.igmp_mld_source_churn.arm_entered_race_v4_d)
				stat_row("DEAD_ARM", "igmp-mld-source-churn/race_v4_d", pr);
			if (!shm->stats.igmp_mld_source_churn.arm_entered_race_v4_e)
				stat_row("DEAD_ARM", "igmp-mld-source-churn/race_v4_e", pr);
		} else {
			output(0, "%-22s  %-32s  %s\n", "DEAD_ARM_SKIP",
			       "igmp-mld-source-churn/v4", "insufficient_samples");
		}

		v6_draws =
			shm->stats.igmp_mld_source_churn.arm_entered_race_v6_a +
			shm->stats.igmp_mld_source_churn.arm_entered_race_v6_b +
			shm->stats.igmp_mld_source_churn.arm_entered_race_v6_c +
			shm->stats.igmp_mld_source_churn.arm_entered_race_v6_d;
		if (v6_draws >= 5 * 4) {
			if (!shm->stats.igmp_mld_source_churn.arm_entered_race_v6_a)
				stat_row("DEAD_ARM", "igmp-mld-source-churn/race_v6_a", pr);
			if (!shm->stats.igmp_mld_source_churn.arm_entered_race_v6_b)
				stat_row("DEAD_ARM", "igmp-mld-source-churn/race_v6_b", pr);
			if (!shm->stats.igmp_mld_source_churn.arm_entered_race_v6_c)
				stat_row("DEAD_ARM", "igmp-mld-source-churn/race_v6_c", pr);
			if (!shm->stats.igmp_mld_source_churn.arm_entered_race_v6_d)
				stat_row("DEAD_ARM", "igmp-mld-source-churn/race_v6_d", pr);
		} else {
			output(0, "%-22s  %-32s  %s\n", "DEAD_ARM_SKIP",
			       "igmp-mld-source-churn/v6", "insufficient_samples");
		}
	}

	/* afxdp-churn: XDP_COPY bind arm -- bumped before bind() so a zero
	 * here means setup always bailed before reaching the bind block.
	 * Floor: 5 * 1 = 5 draws required (runs is the opportunity count).
	 * For this single-arm group the floor gates on runs, not arm_entered_bind
	 * -- arm_entered_bind==0 IS the dead state, not an ambiguous sample.
	 *
	 * RAN_NO_EFFECT: arm_entered_bind > 0 but arm_effective_bind == 0
	 * means the bind arm was reached on every draw but never produced
	 * detectable output (bind() always failed, or the follow-on I/O was
	 * silently dropped).  This is the 510-H class: config-dead past the
	 * entry point, or uapi-value-wrong on the bind flags/ifindex. */
	if (shm->stats.afxdp_churn.runs > 0) {
		if (shm->stats.afxdp_churn.runs < 5 * 1)
			output(0, "%-22s  %-32s  %s\n", "DEAD_ARM_SKIP",
			       "afxdp-churn", "insufficient_samples");
		else if (!shm->stats.afxdp_churn.arm_entered_bind)
			stat_row("DEAD_ARM", "afxdp-churn/bind",
				 shm->stats.afxdp_churn.runs);
		else if (!shm->stats.afxdp_churn.arm_effective_bind)
			stat_row("RAN_NO_EFFECT", "afxdp-churn/bind",
				 shm->stats.afxdp_churn.arm_entered_bind);
		/* else: arm_entered_bind >= 1, arm_effective_bind >= 1: fully live */
	}

	/* xfrm-churn: XFRM_MSG_MIGRATE_STATE arm in dispatch_msg_kind() --
	 * bumped before xfrm_emit_migrate_state() so a zero here means the
	 * probabilistic picker never landed on XMK_MIGRATE_STATE.
	 * Floor: gate on msg_kind_draws (grammar pick_msg_kind() calls), not
	 * on xfrm_churn.runs (childop invocations) -- the two counters come
	 * from entirely separate execution paths.  Using runs as the floor
	 * caused two failure modes: runs reaches >= 5 immediately (childop
	 * bumps it before any early-return), producing false DEAD_ARM when
	 * the grammar has not yet drawn XMK_MIGRATE_STATE; and when the
	 * childop is absent from the op rotation runs == 0, skipping the
	 * check entirely even if the grammar ran thousands of times and the
	 * arm is genuinely dead.
	 * With XMK_MIGRATE_STATE weight 2/120 (empty ring) to 4/138 (full
	 * ring), p ≈ 1/60-1/34; 300 draws gives ~5-9 expected hits before
	 * the dead-arm verdict fires. */
	{
		unsigned long draws = shm->stats.xfrm_churn.msg_kind_draws;

		if (draws < 300)
			output(0, "%-22s  %-32s  %s\n", "DEAD_ARM_SKIP",
			       "xfrm-churn", "insufficient_samples");
		else if (!shm->stats.xfrm_churn.arm_entered_migrate_state)
			stat_row("DEAD_ARM", "xfrm-churn/migrate_state",
				 draws);
		/* else: arm_entered_migrate_state >= 1, arm is live */
	}
}

void dump_stats_fuzzer_subsystems(void)
{
	dump_stats_render_vfs_writes();

	dump_stats_render_memory_pressure();

	stat_category_emit_text(&sched_cycler_category);

	stat_category_emit_text(&userns_fuzzer_category);

	stat_category_emit_text(&ipcns_ucount_exhaustion_category);

	stat_category_emit_text(&userns_bootstrap_category);

	stat_category_emit_text(&barrier_racer_category);

	dump_stats_render_genetlink();

	dump_stats_render_genl_family_calls();

	dump_stats_render_nfnl_subsys();

	dump_stats_render_netlink_generator();

	dump_stats_render_rtnl_ack_oracle();

	dump_stats_render_kvm();

	stat_category_emit_text(&perf_event_chains_category);

	dump_stats_render_tracefs();

	stat_category_emit_text(&bpf_lifecycle_category);

	dump_stats_render_bpf_fd_provider();

	dump_stats_render_ebpf_gen();

	dump_stats_render_recipe_runner();

	dump_stats_render_iouring();

	stat_category_emit_text(&aio_category);

	stat_category_emit_text(&errno_gradient_category);

	stat_category_emit_text(&cold_overflow_category);

	stat_category_emit_text(&inplace_crypto_category);

	stat_category_emit_text(&rpl_clone_fidelity_category);

	stat_category_emit_text(&memfd_secret_lifecycle_category);

	stat_category_emit_text(&mremap_merge_matrix_category);

	stat_category_emit_text(&thp_split_ref_race_category);

	stat_category_emit_text(&uffd_fault_move_category);

	stat_category_emit_text(&fd_runtime_skipped_category);

	stat_category_emit_text(&child_category);

	stat_category_emit_text(&parent_category);

	stat_category_emit_text(&uid_change_category);

	stat_category_emit_text(&no_domains_category);

	dump_stats_render_zombie_slots();

	if (shm->stats.arg.wrong_fd_type_substitutions)
		stat_row("arggen", "wrong_fd_type_substitutions",
			 shm->stats.arg.wrong_fd_type_substitutions);
	if (shm->stats.arg.wrong_fd_type_subst_generic)
		stat_row("arggen", "wrong_fd_type_subst_generic",
			 shm->stats.arg.wrong_fd_type_subst_generic);

	if (shm->stats.btrfs_ioctls_dispatched)
		stat_row("ioctl", "btrfs_ioctls_dispatched",
			 shm->stats.btrfs_ioctls_dispatched);

	if (shm->stats.ioctl_group_match)
		stat_row("ioctl", "group_match",
			 shm->stats.ioctl_group_match);
	if (shm->stats.ioctl_group_miss)
		stat_row("ioctl", "group_miss",
			 shm->stats.ioctl_group_miss);
	if (shm->stats.ioctl_group_random)
		stat_row("ioctl", "group_random",
			 shm->stats.ioctl_group_random);

	if (shm->stats.diag.mmap_size_clamped)
		stat_row("mmap", "mmap_size_clamped",
			 shm->stats.diag.mmap_size_clamped);

	if (shm->stats.diag.heap_extra_regions_overflow)
		stat_row("heap", "heap_extra_regions_overflow",
			 shm->stats.diag.heap_extra_regions_overflow);

	dump_stats_dead_arm_check();
}
