/*
 * afxdp-churn-umem: setup-side helpers for afxdp_churn.
 *
 * Owns the first three phases of the per-iter setup chain:
 *   1. open the AF_XDP socket, mmap the UMEM region, register it via
 *      XDP_UMEM_REG with the per-iter feature knobs (multi-frag SG /
 *      TX metadata headroom);
 *   2. setsockopt the four rings (RX/TX/FILL/COMPLETION) and mmap each
 *      at its documented XDP_*_PGOFF using the sizes stamped by
 *      XDP_MMAP_OFFSETS;
 *   3. bring up the BPF side: create the single-entry XSKMAP, load the
 *      minimal redirect XDP program, and install the xsk fd at key 0
 *      so xdp_do_redirect() has something to walk.
 *
 * Also carries the module-local helpers that only the setup path needs
 * (setsockopt_retry, xdp_ring_mmap_size, xskmap_create,
 * xdp_prog_load, xskmap_install).
 */

#if __has_include(<linux/if_xdp.h>) && __has_include(<linux/bpf.h>)

#include "afxdp-churn-internal.h"

/* setsockopt with bounded EAGAIN/EBUSY retry. */
static int setsockopt_retry(int s, int level, int name,
			    const void *val, socklen_t len)
{
	unsigned int i;
	int r = -1;

	for (i = 0; i < AFXDP_RETRY_CAP; i++) {
		r = setsockopt(s, level, name, val, len);
		if (r == 0 || !afxdp_retryable(errno))
			return r;
	}
	return r;
}

/*
 * Compute mmap length for an XDP ring as desc_off + entries * entry_sz.
 * Returns false on wrap from the kernel-supplied desc_off or the
 * multiplication so a short/corrupt XDP_MMAP_OFFSETS reply can't drive
 * a bogus mmap (and matching bogus munmap) length.
 */
static bool xdp_ring_mmap_size(__u64 desc_off, size_t entries,
			       size_t entry_sz, size_t *out)
{
	size_t prod;

	if (__builtin_mul_overflow(entries, entry_sz, &prod))
		return false;
	if (__builtin_add_overflow((size_t)desc_off, prod, out))
		return false;
	return true;
}

static int xskmap_create(void)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_type    = BPF_MAP_TYPE_XSKMAP;
	attr.key_size    = sizeof(uint32_t);
	attr.value_size  = sizeof(uint32_t);
	attr.max_entries = 1;

	return sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

/*
 * Build the minimal XDP redirect program:
 *
 *     r1 = MAP_FD            ; LD_MAP_FD (two slots)
 *     r2 = 0                 ; key
 *     r3 = 0                 ; flags
 *     call bpf_redirect_map  ; r0 = XDP_REDIRECT or XDP_ABORTED
 *     r0 = XDP_REDIRECT (3)  ; force the action regardless of map state
 *     exit
 *
 * Forcing r0 = XDP_REDIRECT after the helper means the verifier blesses
 * the program even if the map is empty at load time, and at runtime the
 * kernel's xdp_do_redirect() picks up the bpf_redirect_info the helper
 * stamped into the per-CPU slot -- which is exactly the path that walks
 * the XSKMAP and is the surface for CVE-2024-50115.
 */
static int xdp_prog_load(int xskmap_fd)
{
	struct bpf_insn insns[] = {
		/* r1 = MAP_FD (two-slot LD_IMM64 with src=BPF_PSEUDO_MAP_FD). */
		{ .code = BPF_LD | BPF_DW | BPF_IMM,
		  .dst_reg = BPF_REG_1, .src_reg = BPF_PSEUDO_MAP_FD,
		  .off = 0, .imm = 0 },		/* imm patched below */
		{ .code = 0,
		  .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 },
		/* r2 = 0 */
		EBPF_MOV64_IMM(BPF_REG_2, 0),
		/* r3 = 0 */
		EBPF_MOV64_IMM(BPF_REG_3, 0),
		/* call bpf_redirect_map */
		EBPF_CALL(BPF_FUNC_redirect_map),
		/* r0 = XDP_REDIRECT */
		EBPF_MOV64_IMM(BPF_REG_0, XDP_REDIRECT_RET),
		/* exit */
		EBPF_EXIT(),
	};
	union bpf_attr attr;
	char license[] = "GPL";

	insns[0].imm = xskmap_fd;

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_XDP;
	attr.insn_cnt  = ARRAY_SIZE(insns);
	attr.insns     = (uintptr_t)insns;
	attr.license   = (uintptr_t)license;

	return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int xskmap_install(int map_fd, uint32_t key, int xsk_fd)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = map_fd;
	attr.key    = (uintptr_t)&key;
	attr.value  = (uintptr_t)&xsk_fd;
	attr.flags  = 0;

	return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

/*
 * Phase 1: open the AF_XDP socket, mmap the UMEM region, pick the per-
 * iteration feature knobs, and run XDP_UMEM_REG.  On EINVAL with a new
 * feature bit set, latch that feature off and retry once with the
 * baseline layout — the rest of the iteration is still useful coverage.
 * Outputs want_sg / want_tx_md / want_tun for the downstream phases.
 */
int afxdp_iter_setup_umem(struct childdata *child,
			  struct xsk_state *st,
			  bool *want_sg_out,
			  bool *want_tx_md_out,
			  bool *want_tun_out)
{
	struct afxdp_umem_reg_compat umem_reg;
	bool want_sg, want_tx_md, want_tun;
	int rc;

	/* Publish a single per-iter direct-syscall bump for the umem TU
	 * under the shared CHILD_OP_AFXDP_CHURN op.  afxdp_iter_setup_umem
	 * is the first entrypoint iter_one calls after xsk_init(), so
	 * bumping at the top marks "the umem phase was entered" — mirrors
	 * xsk_teardown()'s unconditional-per-iter bump.  Same op-snapshot +
	 * bounds check pattern as teardown: child->op_type lives in shared
	 * memory and can be scribbled by a poisoned-arena write from a
	 * sibling, so refuse to index the per-op stats array on an out-of-
	 * range snapshot.  The three afxdp-churn TUs (umem / io / teardown)
	 * all attribute to the same op via child->op_type / this_child(),
	 * so all bumps accumulate atomically into the single op's total. */
	{
		const enum child_op_type op = child->op_type;
		const bool valid_op = ((int) op >= 0 &&
				       op < NR_CHILD_OP_TYPES);

		if (valid_op)
			childop_direct_syscalls_add(op, 1);
	}

	st->xsk_fd = socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
	if (st->xsk_fd < 0) {
		if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT ||
		    errno == EPERM || errno == EACCES) {
			ns_unsupported_afxdp = true;
			/* child->op_type lives in shared memory and can be
			 * scribbled by a poisoned-arena write from a sibling;
			 * bounds-check the snapshot before indexing the
			 * NR_CHILD_OP_TYPES-sized stats arrays, same pattern
			 * the child.c dispatch loop uses for the unguarded
			 * write that motivated this guard. */
			{
				const enum child_op_type op = child->op_type;
				if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
					__atomic_store_n(&shm->stats.childop.latch_reason[op],
							 CHILDOP_LATCH_UNSUPPORTED,
							 __ATOMIC_RELAXED);
			}
		}
		__atomic_add_fetch(&shm->stats.afxdp_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	st->umem = mmap(NULL, AFXDP_UMEM_BYTES, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (st->umem == MAP_FAILED) {
		__atomic_add_fetch(&shm->stats.afxdp_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	/* Per-iteration knobs.  Two latches gate the new feature flags off
	 * the moment the kernel rejects them with EINVAL — but we never
	 * disable the whole childop on either, the existing UMEM/ring/bind
	 * path is the baseline coverage and must keep running. */
	want_sg    = !ns_unsupported_xdp_sg     && (rnd_u32() & 1);
	want_tx_md = !ns_unsupported_tx_metadata && (rnd_u32() & 1);
	want_tun   = (rnd_u32() & 3) == 0;

	memset(&umem_reg, 0, sizeof(umem_reg));
	umem_reg.addr            = (uint64_t)(uintptr_t)st->umem;
	umem_reg.len             = AFXDP_UMEM_BYTES;
	umem_reg.chunk_size      = want_sg ? AFXDP_SG_CHUNK_SIZE : AFXDP_CHUNK_SIZE;
	umem_reg.headroom        = want_tx_md ? AFXDP_TX_META_BYTES : 0;
	umem_reg.flags           = want_sg ? XDP_UMEM_FLAGS_USE_SG : 0;
	umem_reg.tx_metadata_len = want_tx_md ? AFXDP_TX_META_BYTES : 0;
	rc = setsockopt_retry(st->xsk_fd, SOL_XDP, XDP_UMEM_REG,
			      &umem_reg, sizeof(umem_reg));
	if (rc < 0 && errno == EINVAL && (want_sg || want_tx_md)) {
		/* Latch unsupported features off and retry once with the
		 * baseline (single-buf, no metadata) layout — the rest of
		 * the iteration is still useful coverage. */
		if (want_sg) {
			ns_unsupported_xdp_sg = true;
			__atomic_add_fetch(&shm->stats.afxdp_churn.xsg_bind_failed,
					   1, __ATOMIC_RELAXED);
		}
		if (want_tx_md) {
			ns_unsupported_tx_metadata = true;
			__atomic_add_fetch(&shm->stats.afxdp_churn.tx_md_bind_failed,
					   1, __ATOMIC_RELAXED);
		}
		want_sg = want_tx_md = false;
		umem_reg.chunk_size      = AFXDP_CHUNK_SIZE;
		umem_reg.headroom        = 0;
		umem_reg.flags           = 0;
		umem_reg.tx_metadata_len = 0;
		rc = setsockopt_retry(st->xsk_fd, SOL_XDP, XDP_UMEM_REG,
				      &umem_reg, sizeof(umem_reg));
	}
	if (rc < 0) {
		__atomic_add_fetch(&shm->stats.afxdp_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	__atomic_add_fetch(&shm->stats.afxdp_churn.umem_reg_ok,
			   1, __ATOMIC_RELAXED);
	if (want_sg)
		__atomic_add_fetch(&shm->stats.afxdp_churn.xsg_iters,
				   1, __ATOMIC_RELAXED);
	if (want_tx_md)
		__atomic_add_fetch(&shm->stats.afxdp_churn.tx_metadata_iters,
				   1, __ATOMIC_RELAXED);

	*want_sg_out    = want_sg;
	*want_tx_md_out = want_tx_md;
	*want_tun_out   = want_tun;
	return 0;
}

/*
 * Phase 2: setsockopt all four rings (RX / TX / FILL / COMPLETION), then
 * harvest XDP_MMAP_OFFSETS and mmap each ring at its documented pgoff.
 * Each ring's size + base is stamped into @st so the TX-inject and
 * munmap-race phases can poke them directly.
 */
int afxdp_iter_setup_rings(struct xsk_state *st)
{
	uint32_t ring_entries = AFXDP_RING_ENTRIES;
	socklen_t off_len = sizeof(st->off);

	/* All four rings, same size.  CVE-2022-3625 is in this exact
	 * setsockopt path -- the fix landed in xsk_setsockopt() to refuse
	 * a duplicate XDP_*_RING setsockopt that previously freed the old
	 * queue out from under the bound socket. */
	if (setsockopt_retry(st->xsk_fd, SOL_XDP, XDP_RX_RING,
			     &ring_entries, sizeof(ring_entries)) < 0 ||
	    setsockopt_retry(st->xsk_fd, SOL_XDP, XDP_TX_RING,
			     &ring_entries, sizeof(ring_entries)) < 0 ||
	    setsockopt_retry(st->xsk_fd, SOL_XDP, XDP_UMEM_FILL_RING,
			     &ring_entries, sizeof(ring_entries)) < 0 ||
	    setsockopt_retry(st->xsk_fd, SOL_XDP, XDP_UMEM_COMPLETION_RING,
			     &ring_entries, sizeof(ring_entries)) < 0) {
		__atomic_add_fetch(&shm->stats.afxdp_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	__atomic_add_fetch(&shm->stats.afxdp_churn.rings_setup_ok,
			   1, __ATOMIC_RELAXED);

	/* Zero before the getsockopt so a short reply leaves known state,
	 * then require the full struct came back before we trust any of
	 * its fields for downstream mmap sizing. */
	memset(&st->off, 0, sizeof(st->off));
	if (getsockopt(st->xsk_fd, SOL_XDP, XDP_MMAP_OFFSETS,
		       &st->off, &off_len) < 0 ||
	    off_len < sizeof(st->off)) {
		__atomic_add_fetch(&shm->stats.afxdp_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	if (!xdp_ring_mmap_size(st->off.rx.desc, AFXDP_RING_ENTRIES,
				sizeof(struct xdp_desc), &st->rx_ring_sz) ||
	    !xdp_ring_mmap_size(st->off.tx.desc, AFXDP_RING_ENTRIES,
				sizeof(struct xdp_desc), &st->tx_ring_sz) ||
	    !xdp_ring_mmap_size(st->off.fr.desc, AFXDP_RING_ENTRIES,
				sizeof(uint64_t), &st->fr_ring_sz) ||
	    !xdp_ring_mmap_size(st->off.cr.desc, AFXDP_RING_ENTRIES,
				sizeof(uint64_t), &st->cr_ring_sz)) {
		__atomic_add_fetch(&shm->stats.afxdp_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	st->rx_ring = mmap(NULL, st->rx_ring_sz, PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_POPULATE, st->xsk_fd,
			   XDP_PGOFF_RX_RING);
	st->tx_ring = mmap(NULL, st->tx_ring_sz, PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_POPULATE, st->xsk_fd,
			   XDP_PGOFF_TX_RING);
	st->fr_ring = mmap(NULL, st->fr_ring_sz, PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_POPULATE, st->xsk_fd,
			   XDP_UMEM_PGOFF_FILL_RING);
	st->cr_ring = mmap(NULL, st->cr_ring_sz, PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_POPULATE, st->xsk_fd,
			   XDP_UMEM_PGOFF_COMPLETION_RING);
	if (st->rx_ring == MAP_FAILED || st->tx_ring == MAP_FAILED ||
	    st->fr_ring == MAP_FAILED || st->cr_ring == MAP_FAILED) {
		__atomic_add_fetch(&shm->stats.afxdp_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	return 0;
}

/*
 * Phase 3: stand up the BPF side -- create the single-entry XSKMAP, load
 * the minimal redirect XDP program (best-effort: prog-load failures latch
 * but do not fail the iter; AF_XDP UMEM/ring/bind alone is still useful
 * coverage), and install the xsk fd at xskmap key 0.  Map-create failure
 * is the only fatal step.
 */
int afxdp_iter_setup_bpf(struct xsk_state *st)
{
	st->map_fd = xskmap_create();
	if (st->map_fd < 0) {
		if (errno == EPERM || errno == EACCES)
			ns_unsupported_bpf_xdp = true;
		__atomic_add_fetch(&shm->stats.afxdp_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	__atomic_add_fetch(&shm->stats.afxdp_churn.map_create_ok,
			   1, __ATOMIC_RELAXED);

	if (!ns_unsupported_bpf_xdp) {
		st->prog_fd = xdp_prog_load(st->map_fd);
		if (st->prog_fd < 0) {
			if (errno == EPERM || errno == EACCES ||
			    errno == EINVAL || errno == EOPNOTSUPP)
				ns_unsupported_bpf_xdp = true;
			/* AF_XDP setup still useful without the prog -- the
			 * UMEM/ring/bind path exercises xsk_buff_pool by
			 * itself.  Don't fail the iteration. */
		} else {
			__atomic_add_fetch(&shm->stats.afxdp_churn.prog_load_ok,
					   1, __ATOMIC_RELAXED);
		}
	}

	if (xskmap_install(st->map_fd, 0, st->xsk_fd) == 0)
		__atomic_add_fetch(&shm->stats.afxdp_churn.map_update_ok,
				   1, __ATOMIC_RELAXED);
	return 0;
}

#endif /* __has_include(<linux/if_xdp.h>) && __has_include(<linux/bpf.h>) */
