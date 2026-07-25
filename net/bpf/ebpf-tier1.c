/*
 * Tier 1 emitters and dispatch for the eBPF program generator.
 *
 * Tier 1 (valid): programs the verifier should accept — forward-only
 * jumps, register liveness, bounded stack access, valid helper calls,
 * proper exit.  Split out of net/bpf/ebpf.c as its own translation
 * unit; shared with the tier 2 sub-strategies via ebpf-internal.h.
 */
#include <stdint.h>
#include <linux/bpf.h>

#include "bpf.h"
#include "debug.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "rnd.h"

#include "ebpf-internal.h"

#ifdef USE_BPF

/*
 * Emit one ALU64 op with a sign-bounded immediate.  MOV always initializes
 * the destination; for other ops, dst must already be live or we emit a
 * priming MOV first (and bail if that priming insn hit body_len).
 */
static int emit_tier1_alu64_imm(struct bpf_insn *insns, int pos, int body_len,
				 struct reg_state *rs)
{
	int dst = reg_pick_dst();
	int op = RAND_ARRAY(alu_ops);
	int imm = (int)(rnd_modulo_u32(65536)) - 32768;

	if (op != BPF_MOV && !(rs->live & (1 << dst))) {
		insns[pos++] = EBPF_MOV64_IMM(dst, rnd_modulo_u32(100));
		reg_set(rs, dst);
		if (pos >= body_len)
			return pos;
	}
	/* Avoid shift by >= 64 */
	if (op == BPF_LSH || op == BPF_RSH || op == BPF_ARSH)
		imm = rnd_modulo_u32(64);
	insns[pos++] = EBPF_ALU64_IMM(op, dst, imm);
	reg_set(rs, dst);
	return pos;
}

/*
 * Emit one ALU64 reg-to-reg op, priming dst with a MOV first when
 * required for liveness (same pattern as the IMM variant).
 */
static int emit_tier1_alu64_reg(struct bpf_insn *insns, int pos, int body_len,
				 struct reg_state *rs)
{
	int dst = reg_pick_dst();
	int src = reg_pick_live(rs);
	int op = RAND_ARRAY(alu_ops);

	if (op != BPF_MOV && !(rs->live & (1 << dst))) {
		insns[pos++] = EBPF_MOV64_IMM(dst, 1);
		reg_set(rs, dst);
		if (pos >= body_len)
			return pos;
	}
	insns[pos++] = EBPF_ALU64_REG(op, dst, src);
	reg_set(rs, dst);
	return pos;
}

/* Emit a single ALU32 MOV-immediate.  Always initializes dst. */
static int emit_tier1_alu32_mov_imm(struct bpf_insn *insns, int pos,
				     struct reg_state *rs)
{
	int dst = reg_pick_dst();
	int imm = rnd_modulo_u32(256);

	insns[pos++] = EBPF_ALU32_IMM(BPF_MOV, dst, imm);
	reg_set(rs, dst);
	return pos;
}

/*
 * Emit a stack store of a live reg, then optionally a load from the
 * same slot into a fresh dst.  If the store alone lands on body_len,
 * return early without the follow-up load.
 */
static int emit_tier1_stack_roundtrip(struct bpf_insn *insns, int pos,
				       int body_len, struct reg_state *rs)
{
	int reg = reg_pick_live(rs);
	int off = rand_stack_offset();

	insns[pos++] = EBPF_STX_MEM(BPF_DW, BPF_REG_10, reg, off);
	if (pos >= body_len)
		return pos;

	if (ONE_IN(2)) {
		int dst = reg_pick_dst();

		insns[pos++] = EBPF_LDX_MEM(BPF_DW, dst, BPF_REG_10, off);
		reg_set(rs, dst);
	}
	return pos;
}

/* Emit one ST_MEM of a small immediate into a random stack slot. */
static int emit_tier1_st_imm(struct bpf_insn *insns, int pos)
{
	int off = rand_stack_offset();
	int sz = RAND_ARRAY(mem_sizes);
	int val = rnd_modulo_u32(256);

	insns[pos++] = EBPF_ST_MEM(sz, BPF_REG_10, off, val);
	return pos;
}

/*
 * Emit a forward conditional jump that skips 1-3 insns, then fill
 * the skipped slots with mov-self NOPs.  Caller must have ensured
 * body_len - pos >= 3 before dispatch so the skip range is non-zero.
 */
static int emit_tier1_jmp_fwd(struct bpf_insn *insns, int pos, int body_len,
			       struct reg_state *rs)
{
	int src = reg_pick_live(rs);
	int op = RAND_ARRAY(jmp_ops);
	int max_skip = (body_len - pos) - 2;
	int skip;

	if (max_skip > 3)
		max_skip = 3;

	skip = 1 + (rnd_modulo_u32(max_skip));
	insns[pos++] = EBPF_JMP_IMM(op, src, rnd_modulo_u32(100), skip);

	/* Fill skipped slots with safe NOPs (mov rX, rX) */
	for (int j = 0; j < skip && pos < body_len; j++) {
		int r = reg_pick_live(rs);

		insns[pos++] = EBPF_MOV64_REG(r, r);
	}
	return pos;
}

/* Emit one MOV64 reg-to-reg copy from a live src to a fresh dst. */
static int emit_tier1_mov64_reg(struct bpf_insn *insns, int pos,
				 struct reg_state *rs)
{
	int dst = reg_pick_dst();
	int src = reg_pick_live(rs);

	insns[pos++] = EBPF_MOV64_REG(dst, src);
	reg_set(rs, dst);
	return pos;
}

/*
 * Emit a helper call whose R1..R5 are populated per the descriptor's
 * per-arg kind, then BPF_CALL and a caller-saved clobber in the
 * liveness map.  Return value (R0) is left for the separate map-value
 * NULL-check + deref path to consume.
 *
 * Bails (returns pos unchanged) when no satisfiable helper exists in
 * the current reg state or the remaining buffer can't fit the setup
 * plus the EXIT epilogue.  The outer dispatch loop just re-rolls.
 */
int emit_tier1_helper_call(struct bpf_insn *insns, int pos,
			    int body_len, struct reg_state *rs,
			    struct helper_set hs)
{
	const struct helper_desc *h;
	bool need_init;
	int needed, i, reg;

	h = pick_helper_satisfiable(hs, rs);
	if (h == NULL)
		return pos;

	needed = helper_call_insns(h, &need_init);
	if (body_len - pos < needed + 1)	/* +1 reserves the EXIT slot */
		return pos;

	if (need_init) {
		insns[pos++] = EBPF_ST_MEM(BPF_DW, BPF_REG_10,
					   HELPER_ARG_STACK_OFF, 0);
	}

	for (i = 0; i < h->nargs; i++) {
		reg = BPF_REG_1 + i;
		switch (h->arg_kind[i]) {
		case ARG_SCALAR:
			insns[pos++] = EBPF_MOV64_IMM(reg,
						      rnd_modulo_u32(64));
			break;
		case ARG_STACK_SIZE:
			insns[pos++] = EBPF_MOV64_IMM(reg,
						      HELPER_ARG_STACK_BYTES);
			break;
		case ARG_MAP_PTR:
			insns[pos++] = EBPF_MOV64_REG(reg, rs->map_reg);
			break;
		case ARG_STACK_PTR:
			insns[pos++] = EBPF_MOV64_REG(reg, BPF_REG_10);
			insns[pos++] = EBPF_ALU64_IMM(BPF_ADD, reg,
						      HELPER_ARG_STACK_OFF);
			break;
		}
		reg_set(rs, reg);
	}

	insns[pos++] = EBPF_CALL(h->func);
	reg_clear_caller_saved(rs);
	/*
	 * Arm the deref gate when the helper returns a possibly-NULL
	 * pointer in R0.  Writable backings (map values,
	 * sk/inode/task storage, ringbuf reservation) also permit STXW;
	 * read-only returns (BTF task ptr) get LDXW only.  Helpers not
	 * yet in any prog-type table never reach here, so listing them
	 * is harmless until the descriptor table widens.  Cleanup-
	 * required helpers (sk_lookup_tcp/udp need bpf_sk_release) are
	 * deliberately omitted: emitting a deref without the paired
	 * release would leak ref-counted sock state.
	 */
	switch (h->func) {
	case BPF_FUNC_map_lookup_elem:
	case BPF_FUNC_map_lookup_percpu_elem:
	case BPF_FUNC_inode_storage_get:
	case BPF_FUNC_task_storage_get:
	case BPF_FUNC_sk_storage_get:
	case BPF_FUNC_ringbuf_reserve:
		rs->r0_or_null = true;
		rs->r0_writable = true;
		break;
	case BPF_FUNC_get_current_task_btf:
		rs->r0_or_null = true;
		rs->r0_writable = false;
		break;
	default:
		break;
	}
	__atomic_add_fetch(&shm->stats.ebpf_gen.helper_call_emitted, 1,
			   __ATOMIC_RELAXED);
	return pos;
}

/*
 * Emit the JEQ R0,0,+1 ; LDX/STX pair that actually touches the memory
 * pointed to by R0.  Caller has verified r0_or_null
 * and that body_len - pos >= 2.  Bounded to a 4-byte access at offset 0
 * -- the verifier's per-map bounds check accepts (0, 4) on every map
 * type trinity provisions, and the same shape is safe for ringbuf and
 * the *_storage_get returns; larger offsets fail per-map and would
 * need return-type-aware sizing the generator doesn't track.  Write
 * (STXW) is only legal when the helper returned a writable backing,
 * gated via r0_writable; read-only returns fall through to LDXW.
 * Either variant drops the or-null marker since the deref consumes it.
 */
int emit_tier1_map_val_deref(struct bpf_insn *insns, int pos,
			      struct reg_state *rs)
{
	/*
	 * +1 in the JEQ offset is the count of insns to skip past the
	 * JEQ itself.  We always emit exactly one insn after it, so the
	 * skip lands on whatever the dispatch picks next.
	 */
	insns[pos++] = EBPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1);

	if (rs->r0_writable && ONE_IN(2)) {
		int src = reg_pick_live(rs);

		insns[pos++] = EBPF_STX_MEM(BPF_W, BPF_REG_0, src, 0);
		__atomic_add_fetch(&shm->stats.ebpf_gen.map_value_deref_write,
				   1, __ATOMIC_RELAXED);
	} else {
		int dst = reg_pick_dst();

		insns[pos++] = EBPF_LDX_MEM(BPF_W, dst, BPF_REG_0, 0);
		reg_set(rs, dst);
		__atomic_add_fetch(&shm->stats.ebpf_gen.map_value_deref_read,
				   1, __ATOMIC_RELAXED);
	}

	rs->r0_or_null = false;
	rs->r0_writable = false;
	__atomic_add_fetch(&shm->stats.ebpf_gen.map_value_deref_emitted,
			   1, __ATOMIC_RELAXED);
	return pos;
}

/* Emit one endianness-conversion op on a live reg at 16/32/64 bits. */
static int emit_tier1_endian(struct bpf_insn *insns, int pos,
			      struct reg_state *rs)
{
	int dst = reg_pick_live(rs);
	int sizes[] = { 16, 32, 64 };

	insns[pos++] = EBPF_ENDIAN(BPF_K, dst, RAND_ARRAY(sizes));
	return pos;
}

/*
 * Tier 1: Generate a valid eBPF program.
 *
 * Strategy: emit a sequence of random operations that the verifier can
 * statically validate. All jumps are forward-only, all register reads
 * come from initialized registers, stack access is bounded.
 */
int gen_tier1(struct bpf_insn *insns, int max_insns,
	      struct helper_set hs, int prepend_map_reg)
{
	struct reg_state rs;
	int pos = 0;
	int body_len;

	reg_init(&rs, prepend_map_reg);

	/* Prologue: r0 = 0 (safe default return value) */
	insns[pos++] = EBPF_MOV64_IMM(BPF_REG_0, 0);
	reg_set(&rs, BPF_REG_0);

	/* Initialize a few registers with small constants for variety */
	if (ONE_IN(2)) {
		int reg = 2 + (rnd_modulo_u32(4));	/* r2-r5 */
		insns[pos++] = EBPF_MOV64_IMM(reg, rnd_modulo_u32(256));
		reg_set(&rs, reg);
	}

	/* Body: random operations */
	if (max_insns <= TIER1_MIN_INSNS + 2)
		body_len = pos + 1;
	else
		body_len = TIER1_MIN_INSNS + (rnd_modulo_u32(max_insns - TIER1_MIN_INSNS - 2));
	if (body_len > max_insns - 2)
		body_len = max_insns - 2;

	while (pos < body_len) {
		int remaining = body_len - pos;
		int choice;

		/*
		 * Opportunistic deref of a recent
		 * PTR_OR_NULL-returning helper result.  Rolled independently
		 * of the main lottery so the existing dispatch weights stay
		 * untouched.  The marker survives across iterations that
		 * don't touch R0, so a missed roll here still has a chance
		 * on subsequent iterations until something clobbers R0.
		 */
		if (rs.r0_or_null && remaining >= 2 &&
		    rnd_modulo_u32(100) < MAP_VAL_DEREF_WEIGHT_PCT) {
			pos = emit_tier1_map_val_deref(insns, pos, &rs);
			continue;
		}

		choice = rnd_modulo_u32(100);

		if (choice < 40) {
			pos = emit_tier1_alu64_imm(insns, pos, body_len, &rs);

		} else if (choice < 55) {
			pos = emit_tier1_alu64_reg(insns, pos, body_len, &rs);

		} else if (choice < 65) {
			pos = emit_tier1_alu32_mov_imm(insns, pos, &rs);

		} else if (choice < 75) {
			pos = emit_tier1_stack_roundtrip(insns, pos, body_len, &rs);

		} else if (choice < 82 && remaining >= 3) {
			pos = emit_tier1_jmp_fwd(insns, pos, body_len, &rs);

		} else if (choice < 87) {
			pos = emit_tier1_st_imm(insns, pos);

		} else if (choice < 90) {
			pos = emit_tier1_mov64_reg(insns, pos, &rs);

		} else if (choice < 100 - HELPER_CALL_WEIGHT_PCT) {
			pos = emit_tier1_endian(insns, pos, &rs);

		} else {
			/*
			 * Last HELPER_CALL_WEIGHT_PCT% of the lottery: a
			 * typed helper call.  May bail (returns pos
			 * unchanged) when no satisfiable helper exists in
			 * the current reg state or the buffer can't fit the
			 * arg-setup + CALL + EXIT; the next loop iteration
			 * re-rolls.
			 */
			pos = emit_tier1_helper_call(insns, pos, body_len,
						     &rs, hs);
		}
	}

	/* Epilogue: ensure r0 is set and exit */
	if (!(rs.live & (1 << BPF_REG_0)))
		insns[pos++] = EBPF_MOV64_IMM(BPF_REG_0, 0);
	insns[pos++] = EBPF_EXIT();

	return pos;
}

#endif /* USE_BPF */
