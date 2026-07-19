/*
 * nftables_churn - nftables table/chain/set/rule churn racing live traffic.
 *
 * Targets the transaction-commit teardown in net/netfilter/nf_tables_api.c
 * (nf_tables_commit / nft_chain_commit_drop_policy / nft_rule_destroy /
 * nft_set_destroy) against an in-flight skb traversing the hook -- the
 * commit-vs-softirq-walk window behind the recent nftables CVE lineage
 * (nft_verdict UAF, anonymous-set double-free, nft_setelem/rbtree/chain
 * reference races).  Flat per-syscall fuzz never assembles a coherent
 * table -> chain -> rule tree plus traffic into the registered hook, so
 * the commit machinery never engages.
 *
 * Sequence per invocation inside a userns_run_in_ns grandchild (identity
 * userns + CLONE_NEWNET, _exit reaps): NEWTABLE with family rotated across
 * {NFPROTO_INET, NFPROTO_BRIDGE, NFPROTO_NETDEV} per iter so each per-family
 * afinfo registration commits; NEWSET anonymous (NFT_SET_ANONYMOUS,
 * key_len=4, ipv4_addr); NEWCHAIN "chain_aux" (regular, no hook) before
 * NEWCHAIN "chain_in" (NF_INET_LOCAL_IN, prio 0, "filter") so the base
 * chain's NFT_JUMP/NFT_GOTO to chain_aux binds on first commit; NEWRULE on
 * chain_in with an immediate verdict (NFT_JUMP or NFT_GOTO) arming the
 * verdict-UAF window; AF_INET SOCK_DGRAM burst to 127.0.0.1 walks
 * nf_hook_slow across the fresh chain; mid-traffic NEWRULE at
 * NFTA_RULE_POSITION=1 (position-insert has its own commit codepath); then
 * DELRULE (no handle -> flush all rules) and DELSET/DELTABLE racing the
 * still-draining skbs.
 *
 * Brick-safety: private netns only, loopback only, no host ruleset ever
 * touched; burst BUDGETED+JITTER around base 3 with STORM_BUDGET_NS 200 ms
 * wall cap and 64-frame ceiling; all I/O MSG_DONTWAIT with SO_RCVTIMEO=1s
 * on the nfnetlink socket.
 *
 * Latches: userns -EPERM latches the op off for the child's life.  Inside
 * the grandchild: ns_unsupported_nfnetlink on NETLINK_NETFILTER socket
 * EPROTONOSUPPORT (CONFIG_NF_NETLINK=n); ns_unsupported_nf_tables on
 * NEWTABLE EOPNOTSUPP/EAFNOSUPPORT/EPROTONOSUPPORT.
 */

#include "internal.h"

#include "kernel/socket.h"
#define NFNL_RECV_TIMEO_S		1

/* Per-iteration packet burst base.  BUDGETED+JITTER scales it: a
 * productive run grows toward the cap, an unproductive one shrinks
 * to floor.  Sends are MSG_DONTWAIT; the inner loop also clamps to
 * STORM_BUDGET_NS wall-clock so even an unbounded burst can't stall
 * the iteration past the SIGALRM(1s) cap. */
#define NFT_PACKET_BASE			3U
#define NFT_PACKET_FLOOR		8U	/* always send at least this many */
#define NFT_PACKET_CAP			64U	/* upper clamp on per-iter burst */
#define STORM_BUDGET_NS			200000000L	/* 200 ms */

/* UDP destination port for the loopback drive packet.  Loopback-only
 * inside a private netns — the value doesn't matter functionally; a
 * fixed non-privileged port keeps any escaped packet trivially
 * identifiable in a tcpdump trace during triage. */
#define NFT_INNER_PORT			34568

/* Per-grandchild latched gates.  Inherited as false at grandchild
 * fork time (the persistent child never writes them -- the in-ns
 * callback runs exclusively in transient grandchildren) and flipped
 * on the first config-absent rejection from the corresponding
 * subsystem.  Die with the grandchild on _exit(); each subsequent
 * grandchild re-discovers the latch in its own fresh netns.  The
 * EPROTONOSUPPORT / EAFNOSUPPORT / EOPNOTSUPP detection arms are
 * preserved because a fresh user namespace cannot manufacture an
 * absent kernel CONFIG -- the gate still short-circuits the rest of
 * the grandchild's iteration once it fires. */
static bool ns_unsupported_nfnetlink;
static bool ns_unsupported_nf_tables;
static bool ns_unsupported_inet;

static bool lo_brought_up;

/* Master gate: persistent across iterations in the persistent child.
 * Set when userns_run_in_ns returns -EPERM (hardened userns policy
 * refused CLONE_NEWUSER -- typically user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0).  The per-grandchild gates
 * above die with the grandchild; helper-EPERM is the only signal
 * that survives long enough to short-circuit subsequent invocations. */
static bool ns_unsupported_nftables;

static void warn_once_unsupported_nftables(const char *reason, int err)
{
	if (ns_unsupported_nftables)
		return;
	ns_unsupported_nftables = true;
	outputerr("nftables_churn: %s failed (errno=%d), latching unsupported_nftables\n",
		  reason, err);
}

/* Per-invocation state shared across the extracted phase helpers.  Fd
 * fields default to -1 via the orchestrator's designated initialiser
 * so the teardown helper can close them unconditionally regardless of
 * which earlier phase bailed.  base_chain / aux_chain carry the
 * compile-time defaults the rule-build phases reference every
 * iteration; table_name / anon_set / family / set_id / verdict are
 * filled in by build_table; table_created flips true once NEWTABLE
 * commits so the teardown helper knows to DELTABLE on the way out. */
struct nftables_churn_iter_ctx {
	struct nl_ctx		rtnl;
	struct nfnl_ctx		nfnl;
	int			udp;
	char			table_name[32];
	char			base_chain[32];
	char			aux_chain[32];
	char			anon_set[32];
	__u8			family;
	__u32			set_id;
	__u32			verdict;
	bool			table_created;
	struct childdata	*child;
};

/*
 * Phase: NETLINK_NETFILTER socket open inside the grandchild's
 * private netns.  The netns itself is set up by userns_run_in_ns()
 * before the in-ns callback runs, so this helper only has to bring
 * up the nfnetlink fd that every later phase batches commits over
 * (latched off via ns_unsupported_nfnetlink on the EPROTONOSUPPORT /
 * EAFNOSUPPORT CONFIG_NF_NETLINK-absent shape).  Returns 0 on
 * success; -1 means caller should return immediately -- no other fd
 * was opened so the out: cleanup path has nothing useful to run.
 */
static int nftables_churn_iter_setup_netns(struct nftables_churn_iter_ctx *ctx)
{
	struct nfnl_open_opts nfnl_opts = {
		.recv_timeo_s  = NFNL_RECV_TIMEO_S,
	};
	/* Snapshot ctx->child->op_type once and bounds-check before
	 * indexing the per-op stats arrays.  The field lives in shared
	 * memory and can be scribbled by a poisoned-arena write from a
	 * sibling; the child.c dispatch loop already gates its dispatch
	 * + alt-op accounting on the same valid_op snapshot.  Skip the
	 * latch-reason writes entirely when the snapshot is out of
	 * range. */
	const enum child_op_type op = ctx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (nfnl_open(&ctx->nfnl, &nfnl_opts) < 0) {
		/* EPROTONOSUPPORT here means CONFIG_NF_NETLINK is off
		 * — latch and stop trying.  Other errors (ENOMEM,
		 * EMFILE) are transient; fall through and re-try next
		 * invocation. */
		if (errno == EPROTONOSUPPORT || errno == EAFNOSUPPORT) {
			ns_unsupported_nfnetlink = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.nftables_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	return 0;
}

/*
 * Phase: NETLINK_ROUTE socket open + one-time lo bring-up inside the
 * fresh netns.  Splits out from setup_netns because the nfnl fd is
 * already live by the time we get here, so a failure must funnel
 * through the out: cleanup path to close it (whereas
 * setup_netns failures had nothing yet to clean).  The lo bring-up is
 * gated by the process-wide lo_brought_up latch so subsequent
 * invocations skip the RTM_NEWLINK round trip.  Returns 0 on success;
 * -1 means caller should goto out -- nfnl needs closing.
 */
static int nftables_churn_iter_open_rtnl(struct nftables_churn_iter_ctx *ctx)
{
	struct nl_open_opts rtnl_opts = {
		.proto         = NETLINK_ROUTE,
		.recv_timeo_s  = NFNL_RECV_TIMEO_S,
	};

	if (nl_open(&ctx->rtnl, &rtnl_opts) < 0) {
		__atomic_add_fetch(&shm->stats.nftables_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	if (!lo_brought_up) {
		rtnl_bring_lo_up(&ctx->rtnl);
		lo_brought_up = true;
	}

	return 0;
}

/*
 * Phase: rare-gate dispatch into the five sub-mode sweeps.  Each gate
 * is independent and short-circuits the dominant expression-fuzz path
 * for the rest of this invocation, so the helper just rolls each in
 * turn and bails as soon as one fires.  Latches
 * The helper-local unsupported latches gate sub-modes whose
 * upstream commits don't share ns_unsupported_nf_tables.  Returns 0
 * if no sub-mode fired (caller continues into the main flow); 1 if
 * one fired and caller should goto out -- nfnl/rtnl are already open
 * and need teardown.
 */
static int nftables_churn_iter_submode_dispatch(struct nftables_churn_iter_ctx *ctx)
{
	/* Dormant-table abort sub-mode (upstream 63bac02786030) -- rare gate
	 * so the expression-fuzz path below stays the dominant workload.
	 * Reuses ns_unsupported_nf_tables as the latch on EPERM/EOPNOTSUPP. */
	if (ONE_IN(8)) {
		nft_dormant_abort_sweep(&ctx->nfnl);
		return 1;
	}

	/* xt_CT v1+v2 usersize sub-mode (upstream 8bedb6c46945) -- rare gate
	 * so the expression-fuzz path below stays the dominant workload.
	 * Independent latch (ns_unsupported_xt_ct) so a missing xt_CT module
	 * doesn't cascade into nf_tables disablement. */
	if (ONE_IN(8) && !nft_xt_ct_usersize_unsupported()) {
		nft_xt_ct_usersize_sweep();
		return 1;
	}

	/* xt_IDLETIMER grammar sub-mode.  Rare gate so the dominant
	 * expression-fuzz path stays the primary workload.  Independent
	 * latch (ns_unsupported_xt_idletimer) so a kernel without
	 * CONFIG_NETFILTER_XT_TARGET_IDLETIMER pays the EFAIL once and the
	 * rest of the child's iterations skip the socket() + setsockopt
	 * roundtrip. */
	if (ONE_IN(8) && !nft_xt_idletimer_unsupported()) {
		nft_xt_idletimer_sweep();
		return 1;
	}

	/* Per-hook .validate sweep on xt-compat targets, gated separately
	 * so the legacy expression-fuzz path above is undisturbed. */
	if (ONE_IN(2) && !nft_compat_validate_unsupported()) {
		nft_compat_validate_sweep(&ctx->nfnl);
		return 1;
	}

	/* nft_fwd_netdev neigh-forward loop sub-mode (upstream 1d47b55b36d2,
	 * 0a0b35f0bf10, 1049970d7583).  Rare gate so the dominant
	 * expression-fuzz path above stays the primary workload.  Independent
	 * latch (ns_unsupported_nft_fwd_netdev_loop) so a kernel without
	 * CONFIG_VETH or CONFIG_NFT_FWD_NETDEV pays the EFAIL once. */
	if (ONE_IN(8) && !nft_fwd_netdev_loop_unsupported()) {
		nft_fwd_netdev_loop_sweep(&ctx->nfnl, &ctx->rtnl);
		return 1;
	}

	/* L4-aware-on-fragment sub-mode (upstream 952e121c9613, 009d203e56db,
	 * 0bf00859d7a5).  Rare gate so the dominant expression-fuzz path
	 * above stays the primary workload.  No dedicated latch -- a kernel
	 * without CONFIG_NF_TABLES is already gated by ns_unsupported_nf_tables
	 * upstream; per-expression validators that EOPNOTSUPP just skip the
	 * rule install and the cleanup still drains. */
	if (ONE_IN(8)) {
		nft_l4_aware_frag_sweep(&ctx->nfnl);
		return 1;
	}

	return 0;
}

/*
 * Phase: roll the per-iteration family / table / set / verdict
 * identifiers, commit NEWTABLE, and stack the dependent NEWSET, two
 * NEWCHAIN, and the append-only NEWRULE on top.  aux_chain is created
 * before base_chain so the base-chain rule's NFT_JUMP/NFT_GOTO has a
 * resolvable target on first commit.  Latches ns_unsupported_nf_tables
 * on the EAFNOSUPPORT / EOPNOTSUPP / EPROTONOSUPPORT family-not-
 * registered shape of NEWTABLE failure so siblings stop probing.
 * Returns 0 on success (ctx.table_created flipped, ready for traffic
 * + teardown phases); -1 means NEWTABLE failed and caller should goto
 * out -- there is nothing for the set/chain/rule phases to anchor on.
 */
static int nftables_churn_iter_build_table(struct nftables_churn_iter_ctx *ctx)
{
	struct nft_expr_plan plan;
	int rc;

	ctx->family = nft_pick_family();
	nft_fill_table_name(ctx->table_name, sizeof(ctx->table_name), "trnft");
	snprintf(ctx->anon_set, sizeof(ctx->anon_set), "__set%u",
		 (unsigned int)(rand32() & 0xffffu));
	ctx->set_id = rand32();
	ctx->verdict = (rand32() & 1) ? NFT_JUMP : NFT_GOTO;

	rc = nft_build_newtable(&ctx->nfnl, ctx->family, ctx->table_name);
	if (rc != 0) {
		/* EAFNOSUPPORT / EOPNOTSUPP / EPROTONOSUPPORT all mean
		 * "this nf_tables family isn't registered" — most
		 * commonly because the nf_tables module itself is
		 * absent.  Latch the whole op off; nothing else here
		 * will work either. */
		if (rc == -EOPNOTSUPP || rc == -EPROTONOSUPPORT ||
		    rc == -EAFNOSUPPORT) {
			ns_unsupported_nf_tables = true;
			/* ctx->child->op_type lives in shared memory and
			 * can be scribbled by a poisoned-arena write from
			 * a sibling; bounds-check the snapshot before
			 * indexing the NR_CHILD_OP_TYPES-sized stats
			 * array, same pattern the child.c dispatch loop
			 * uses for the unguarded write that motivated
			 * this guard. */
			{
				const enum child_op_type op = ctx->child->op_type;
				if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
					__atomic_store_n(&shm->stats.childop.latch_reason[op],
							 CHILDOP_LATCH_UNSUPPORTED,
							 __ATOMIC_RELAXED);
			}
		}
		return -1;
	}
	ctx->table_created = true;
	__atomic_add_fetch(&shm->stats.nftables_churn.table_create_ok,
			   1, __ATOMIC_RELAXED);

	if (nft_build_newset(&ctx->nfnl, ctx->family, ctx->table_name,
			 ctx->anon_set, ctx->set_id) == 0)
		__atomic_add_fetch(&shm->stats.nftables_churn.set_create_ok,
				   1, __ATOMIC_RELAXED);

	/* aux first so the base-chain rule's NFT_JUMP/NFT_GOTO has a
	 * resolvable target on first commit. */
	if (nft_build_newchain(&ctx->nfnl, ctx->family, ctx->table_name,
			   ctx->aux_chain, false) == 0)
		__atomic_add_fetch(&shm->stats.nftables_churn.chain_create_ok,
				   1, __ATOMIC_RELAXED);

	if (nft_build_newchain(&ctx->nfnl, ctx->family, ctx->table_name,
			   ctx->base_chain, true) == 0)
		__atomic_add_fetch(&shm->stats.nftables_churn.chain_create_ok,
				   1, __ATOMIC_RELAXED);

	nft_expr_plan_randomize(&plan);
	if (nft_build_newrule(&ctx->nfnl, ctx->family, ctx->table_name,
			  ctx->base_chain, ctx->aux_chain, ctx->verdict,
			  0, &plan, ctx->anon_set, ctx->set_id) == 0) {
		__atomic_add_fetch(&shm->stats.nftables_churn.rule_create_ok,
				   1, __ATOMIC_RELAXED);
		nft_expr_plan_record_stats(&plan);
	}

	return 0;
}

/*
 * Phase: open the loopback UDP socket and drive a bounded sendto
 * burst at 127.0.0.1:NFT_INNER_PORT.  Each send ingresses on lo,
 * walks the freshly-installed chain_in -> chain_aux jump via
 * nf_hook_slow, and exercises the verdict path the CVE-2024-1086
 * lineage hangs off.  The local STORM_BUDGET_NS wall-cap kept the
 * loop inline in the original; it stays self-contained here so the
 * caller doesn't have to thread a timespec into the helper.  Latches
 * ns_unsupported_inet on EAFNOSUPPORT / EPROTONOSUPPORT so the rest
 * of the child's lifetime skips the socket() syscall.
 */
static void nftables_churn_iter_drive_traffic(struct nftables_churn_iter_ctx *ctx)
{
	struct sockaddr_in dst;
	struct timespec t0;
	unsigned int iters;
	unsigned int i;

	if (!ns_unsupported_inet) {
		ctx->udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (ctx->udp < 0) {
			if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
				ns_unsupported_inet = true;
		}
	}

	if (ctx->udp < 0)
		return;

	memset(&dst, 0, sizeof(dst));
	dst.sin_family      = AF_INET;
	dst.sin_port        = htons(NFT_INNER_PORT);
	dst.sin_addr.s_addr = htonl(0x7f000001U);	/* 127.0.0.1 */

	(void)clock_gettime(CLOCK_MONOTONIC, &t0);
	iters = BUDGETED(CHILD_OP_NFTABLES_CHURN,
			 JITTER_RANGE(NFT_PACKET_BASE));
	if (iters < NFT_PACKET_FLOOR)
		iters = NFT_PACKET_FLOOR;
	if (iters > NFT_PACKET_CAP)
		iters = NFT_PACKET_CAP;

	for (i = 0; i < iters; i++) {
		unsigned char payload[64];
		ssize_t n;

		if (ns_since(&t0) >= STORM_BUDGET_NS)
			break;

		generate_rand_bytes(payload, sizeof(payload));
		n = sendto(ctx->udp, payload, sizeof(payload),
			   MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst));
		if (n > 0)
			__atomic_add_fetch(&shm->stats.nftables_churn.packet_sent_ok,
					   1, __ATOMIC_RELAXED);
	}
}

/*
 * Phase: mid-flow position-1 insert + bulk DELRULE + DELSET racing
 * the still-draining UDP burst.  The position-based NEWRULE walks a
 * different commit-time codepath from the append-only path in
 * build_table; if no rule with handle 1 exists the kernel rejects it
 * cheaply, which is fine -- the commit-time validation still ran.
 * The bulk DELRULE (no NFTA_RULE_HANDLE) is the targeted
 * commit-vs-traffic teardown window -- the same one CVE-2024-1086
 * exploited.  DELSET retires the anonymous set the rule above bound
 * to before the orchestrator's DELTABLE cascades the rest at out:.
 */
static void nftables_churn_iter_mid_churn(struct nftables_churn_iter_ctx *ctx)
{
	struct nft_expr_plan plan;

	nft_expr_plan_randomize(&plan);
	if (nft_build_newrule(&ctx->nfnl, ctx->family, ctx->table_name,
			  ctx->base_chain, ctx->aux_chain, ctx->verdict,
			  1, &plan, ctx->anon_set, ctx->set_id) == 0) {
		__atomic_add_fetch(&shm->stats.nftables_churn.rule_insert_ok,
				   1, __ATOMIC_RELAXED);
		nft_expr_plan_record_stats(&plan);
	}

	if (nft_build_delrule(&ctx->nfnl, ctx->family, ctx->table_name,
			  ctx->base_chain) == 0)
		__atomic_add_fetch(&shm->stats.nftables_churn.rule_del_ok,
				   1, __ATOMIC_RELAXED);

	(void)nft_build_delset(&ctx->nfnl, ctx->family, ctx->table_name,
			   ctx->anon_set);
}

/*
 * Phase: close whichever resources we managed to open.  Runs on
 * every exit path -- both the success path after mid_churn returns
 * and any early-bail goto out from an earlier phase.  Order matches
 * the original out: cleanup: close udp first, then DELTABLE (gated
 * on table_created so an aborted build_table doesn't issue a NEWTABLE
 * we never sent), then nfnl close so the DELTABLE batch has somewhere
 * to land, then rtnl.  All fd fields default to -1 via the
 * orchestrator's designated initialiser so the guards skip work that
 * was never set up.
 */
static void nftables_churn_iter_teardown(struct nftables_churn_iter_ctx *ctx)
{
	if (ctx->udp >= 0)
		close(ctx->udp);

	if (ctx->nfnl.nl.fd >= 0) {
		/* DELTABLE cascades cleanup of any chain/rule/set
		 * survivors via nf_tables_table_destroy, racing the
		 * same in-flight skbs as the explicit DELRULE above. */
		if (ctx->table_created) {
			if (nft_build_deltable(&ctx->nfnl, ctx->family,
					   ctx->table_name) == 0)
				__atomic_add_fetch(&shm->stats.nftables_churn.table_del_ok,
						   1, __ATOMIC_RELAXED);
		}
		nfnl_close(&ctx->nfnl);
	}

	nl_close(&ctx->rtnl);
}

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so any table,
 * chain, rule, set, dummy / veth link and socket left behind is reaped
 * along with the namespace.  Explicit DELTABLE / close() calls are
 * still issued so the in-ns stats counters (table_del_ok etc.) move on
 * the success path; correctness does not depend on them.  Per-grand-
 * child latches set inside this callback die with the grandchild and
 * the per-grandchild gates above are re-discovered on the next
 * invocation -- helper-EPERM in the wrapper is the only signal that
 * survives across iterations.  Return value is ignored by the helper.
 */
static int nftables_churn_in_ns(void *arg)
{
	struct nftables_churn_iter_ctx *ctx = (struct nftables_churn_iter_ctx *)arg;
	struct childdata *child = ctx->child;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (ns_unsupported_nfnetlink || ns_unsupported_nf_tables)
		return 0;

	if (nftables_churn_iter_setup_netns(ctx) != 0)
		return 0;

	if (nftables_churn_iter_open_rtnl(ctx) != 0)
		goto out;

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}
	if (nftables_churn_iter_submode_dispatch(ctx) != 0)
		goto out;

	if (nftables_churn_iter_build_table(ctx) != 0)
		goto out;

	nftables_churn_iter_drive_traffic(ctx);
	nftables_churn_iter_mid_churn(ctx);

out:
	nftables_churn_iter_teardown(ctx);
	return 0;
}

bool nftables_churn(struct childdata *child)
{
	struct nftables_churn_iter_ctx ctx = {
		.rtnl       = { .fd = -1 },
		.nfnl       = { .nl = { .fd = -1 } },
		.udp        = -1,
		.base_chain = "chain_in",
		.aux_chain  = "chain_aux",
		.child      = child,
	};
	int rc;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op latch slot.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the latch
	 * store entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.nftables_churn.runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_nftables)
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET, nftables_churn_in_ns, &ctx);
	if (rc == -EPERM) {
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		warn_once_unsupported_nftables("userns_run_in_ns(CLONE_NEWNET)",
					       EPERM);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without
		 * latching -- the failure is not policy and may not
		 * recur. */
		__atomic_add_fetch(&shm->stats.nftables_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}
