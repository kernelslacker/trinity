/*
 * afxdp-churn-io: TX descriptor kick + live-socket race window for
 * afxdp_churn.
 *
 * Owns the producer/consumer path that runs after bind:
 *   afxdp_iter_tx_burst  — stamp 1 (or 2 chained for want_sg)
 *                          xdp_desc entries into the TX ring, optionally
 *                          spawn the sw-csum metadata scribbler, then
 *                          sendto(MSG_DONTWAIT) to kick xsk_sendmsg.
 *   afxdp_iter_run_races — XDP_STATISTICS read against the live rings,
 *                          RACE A (xskmap delete on the bound key,
 *                          CVE-2024-50115), RACE B (munmap the FILL
 *                          ring while still bound, CVE-2023-39197).
 *
 * The metadata scribbler thread + args struct live here because they
 * only exist to feed the TX-metadata TOCTOU window; nothing outside
 * the TX kick calls them.  xskmap_delete is here for the same reason
 * — the only caller is the RACE A path.
 */

#if __has_include(<linux/if_xdp.h>) && __has_include(<linux/bpf.h>)

#include "afxdp-churn-internal.h"

static int xskmap_delete(int map_fd, uint32_t key)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = map_fd;
	attr.key    = (uintptr_t)&key;

	return sys_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

/*
 * Concurrent scribbler that tight-loops overwriting the 16-byte
 * xsk_tx_metadata header in the UMEM headroom while the kernel is
 * consuming the TX descriptor.  The kernel's sw-csum TX path reads
 * csum_start / csum_offset out of the user-writable UMEM region; a
 * concurrent overwrite between the kernel's two reads (a classic
 * double-fetch / TOCTOU window) can drive csum_start past the packet
 * end, exercising the bounds checks added in d73a9a63f9f7 and friends.
 *
 * Flips both the flags u64 at offset 0 and the (csum_start, csum_offset)
 * u16 pair at offsets 8/10 so any read order in the kernel sees a
 * moving target.  Bounded by an atomic stop flag (set by the main
 * thread after sendto() returns) AND a hard iteration cap as failsafe.
 */
struct afxdp_meta_scribbler_args {
	unsigned char	*meta;
	unsigned int	 stop;
};

static void *afxdp_meta_scribbler(void *p)
{
	struct afxdp_meta_scribbler_args *a = p;
	unsigned int i;
	__u64 mflags;
	__u16 cs;

	for (i = 0; i < AFXDP_TX_META_SCRIBBLE_CAP; i++) {
		if (__atomic_load_n(&a->stop, __ATOMIC_RELAXED))
			break;
		mflags = (i & 1U)
			? (XDP_TXMD_FLAGS_CHECKSUM | XDP_TXMD_FLAGS_TIMESTAMP)
			: XDP_TXMD_FLAGS_CHECKSUM;
		memcpy(a->meta, &mflags, sizeof(mflags));
		cs = (__u16)i;
		memcpy(a->meta + 8,  &cs, sizeof(cs));
		cs = (__u16)(i >> 1);
		memcpy(a->meta + 10, &cs, sizeof(cs));
	}
	return NULL;
}

/*
 * Phase 6: enqueue 1 (or 2 chained, for want_sg) TX descriptors into
 * the TX ring then sendto(MSG_DONTWAIT) to kick xsk_sendmsg.  This
 * drives descriptors through xsk_buff_pool — the live-pool path we
 * want to race against the deletes/munmaps below.  No-op when bind()
 * didn't take.  Touches the want_tx_md / want_sg per-iter knobs to
 * stamp xsk_tx_metadata in headroom and set XDP_PKT_CONTD/XDP_TX_METADATA
 * in desc->options where appropriate.
 *
 * When want_tx_md fires, a short-lived scribbler pthread is spawned
 * just before the sendto() kick to overwrite the metadata bytes WHILE
 * the kernel reads them, opening the TOCTOU window on the sw-csum
 * double-read.  The thread is hard-joined before this function returns
 * — trinity children keep fuzzing past here and a leaked thread would
 * corrupt subsequent ops.
 */
void afxdp_iter_tx_burst(struct xsk_state *st,
			 bool want_sg, bool want_tx_md)
{
	struct afxdp_meta_scribbler_args sa;
	pthread_t scribbler_tid;
	bool scribbler_spawned = false;
	uint32_t *prod;
	struct xdp_desc *desc;
	uint32_t p, chunk_sz, enq = 1U;
	uint64_t head_addr;
	uint16_t head_opts;

	if (!st->bound)
		return;

	/* Inject TX descriptor(s) into the TX ring, then sendto-kick.
	 * xsk_sendmsg walks the TX ring and pulls the descriptors
	 * through xsk_buff_pool — the live-pool path we want to race
	 * against the deletes/munmaps below.
	 *
	 * Multibuf path (want_sg): enqueue two chained descriptors,
	 * head with XDP_PKT_CONTD set in options.  Hits the chained-
	 * frag walker that 0f3776583d28 fixes (per-desc UAF when the
	 * chain crosses UMEM frag boundaries).
	 *
	 * TX-metadata path (want_tx_md): stamp xsk_tx_metadata into
	 * the headroom region just before the head desc->addr and set
	 * XDP_TX_METADATA in head->options.  The kernel reads csum
	 * fields from there; d73a9a63f9f7 mishandled this when the
	 * bound netdev advertises IFF_TX_SKB_NO_LINEAR. */
	prod = (uint32_t *)((char *)st->tx_ring + st->off.tx.producer);
	desc = (struct xdp_desc *)((char *)st->tx_ring + st->off.tx.desc);
	p         = __atomic_load_n(prod, __ATOMIC_RELAXED);
	chunk_sz  = want_sg ? AFXDP_SG_CHUNK_SIZE : AFXDP_CHUNK_SIZE;
	head_addr = want_tx_md ? AFXDP_TX_META_BYTES : 0;
	head_opts = (want_sg ? XDP_PKT_CONTD : 0) |
		    (want_tx_md ? XDP_TX_METADATA : 0);

	if (want_tx_md && (char *)st->umem != MAP_FAILED) {
		/* metadata header is 16 bytes immediately preceding
		 * head_addr in the UMEM region — relies on headroom
		 * being set to AFXDP_TX_META_BYTES at UMEM_REG. */
		unsigned char *meta = (unsigned char *)st->umem +
				      head_addr - AFXDP_TX_META_BYTES;
		__u64 mflags = XDP_TXMD_FLAGS_CHECKSUM |
			       ((rnd_u32() & 1) ? XDP_TXMD_FLAGS_TIMESTAMP : 0);

		memset(meta, 0, AFXDP_TX_META_BYTES);
		memcpy(meta, &mflags, sizeof(mflags));
		/* csum_start=0, csum_offset=0 — bytes 8..11 already zero. */

		/* Spawn the scribbler BEFORE the sendto() kick so the
		 * overwrite is already in flight when xsk_sendmsg reads
		 * the metadata.  pthread_create failure (EAGAIN under
		 * nproc/thread limits) is non-fatal — the TX path still
		 * runs, just without the race. */
		sa.meta = meta;
		sa.stop = 0;
		if (pthread_create(&scribbler_tid, NULL,
				   afxdp_meta_scribbler, &sa) == 0)
			scribbler_spawned = true;
	}

	desc[p % AFXDP_RING_ENTRIES].addr    = head_addr;
	desc[p % AFXDP_RING_ENTRIES].len     = 1;
	desc[p % AFXDP_RING_ENTRIES].options = head_opts;
	if (want_sg) {
		uint32_t q = (p + 1) % AFXDP_RING_ENTRIES;

		desc[q].addr    = (uint64_t)chunk_sz + head_addr;
		desc[q].len     = 1;
		desc[q].options = 0;	/* tail of chain */
		enq = 2U;
	}
	__atomic_store_n(prod, p + enq, __ATOMIC_RELEASE);

	if (sendto(st->xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0) >= 0 ||
	    errno == EAGAIN || errno == ENOBUFS || errno == EBUSY)
		__atomic_add_fetch(&shm->stats.afxdp_churn.send_ok,
				   1, __ATOMIC_RELAXED);

	/* HARD REQUIREMENT: stop + join the scribbler before returning.
	 * trinity children keep fuzzing after this op completes; a leaked
	 * thread would scribble UMEM that has already been munmap'd or
	 * scribble subsequent ops' shared state. */
	if (scribbler_spawned) {
		__atomic_store_n(&sa.stop, 1, __ATOMIC_RELAXED);
		(void)pthread_join(scribbler_tid, NULL);
	}
}

/*
 * Phase 7: the live-socket race window.  XDP_STATISTICS read while RX
 * is bound (stats walker concurrently reads ring counters the bound
 * rings are producing into), RACE A = XSKMAP delete on the bound key
 * (CVE-2024-50115: xdp_do_redirect's RCU-protected map pointer freed
 * under the walker), RACE B = munmap the FILL ring while still bound
 * (CVE-2023-39197: xsk_buff_pool refcount must outlive the user's
 * munmap of its own ring view).  All three are no-ops without bind.
 */
void afxdp_iter_run_races(struct xsk_state *st)
{
	struct xdp_statistics xstats;
	socklen_t xstats_len = sizeof(xstats);

	/* XDP_STATISTICS read while RX is bound -- the stats walker reads
	 * the per-ring ring_full / fill_ring_empty_descs counters which
	 * the bound rings are concurrently producing into. */
	if (getsockopt(st->xsk_fd, SOL_XDP, XDP_STATISTICS,
		       &xstats, &xstats_len) == 0)
		__atomic_add_fetch(&shm->stats.afxdp_churn.recv_ok,
				   1, __ATOMIC_RELAXED);

	/* RACE A: delete the bound XSKMAP entry.  CVE-2024-50115 surface --
	 * xdp_do_redirect()'s map walker holds an RCU-protected pointer
	 * that this delete frees from under it. */
	if (st->bound && xskmap_delete(st->map_fd, 0) == 0)
		__atomic_add_fetch(&shm->stats.afxdp_churn.map_delete_ok,
				   1, __ATOMIC_RELAXED);

	/* RACE B: munmap the FILL ring while still bound.  CVE-2023-39197
	 * surface -- the xsk_buff_pool refcount on the umem region must
	 * keep the kernel's mapping alive past the user's munmap of its
	 * own ring view. */
	if (st->bound && st->fr_ring != MAP_FAILED && st->fr_ring_sz) {
		if (munmap(st->fr_ring, st->fr_ring_sz) == 0)
			__atomic_add_fetch(&shm->stats.afxdp_churn.munmap_race_ok,
					   1, __ATOMIC_RELAXED);
		st->fr_ring = MAP_FAILED;
		st->fr_ring_sz = 0;
	}
}

#endif /* __has_include(<linux/if_xdp.h>) && __has_include(<linux/bpf.h>) */
