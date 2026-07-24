#pragma once

/*
 * Private declarations shared between the source-split
 * net/socket-family-grammar-*.c pieces (core, illegal, seq, alg).
 * Public API stays in include/socket-family-grammar.h.
 */

#include <stdbool.h>
#include <stdint.h>

#include "socket-family-grammar.h"

/*
 * FNV-1a step-ID hash.  Streamed per-step from the executor loop so
 * a walk that bails mid-sequence hashes only the steps that actually
 * ran — the truncated hash is a distinct sequence in its own right,
 * which is the right variety signal for the P1 metric.
 */
#define SFG_FNV1A_OFFSET	0x811c9dc5u
#define SFG_FNV1A_PRIME		0x01000193u

static inline uint32_t sfg_fnv1a_step(uint32_t h, unsigned char step)
{
	h ^= step;
	h *= SFG_FNV1A_PRIME;
	return h;
}

/* Returned by sfg_seq_record when the ring is full and the hash was
 * not already present -- the caller has no slot to attach per-sequence
 * data to and skips the attempt. */
#define SFG_SEQ_SLOT_NONE	((unsigned int)-1)

/*
 * P4 arm id: one grammar "arm" is a (family, order-index) pair.
 * Several executed sequence hashes can map to one arm (via needs_la
 * gating and mid-walk bails), so reward is stored per hash-slot and
 * rolled up to the arm at pick time.  Packing family in the high bits
 * and the order-index in the low byte lets the rollup side (core's
 * picker) and the credit side (seq's sfg_seq_credit) derive the
 * identical id.  order-index is < SFG_MAX_PHASES and family is a small
 * AF_* constant, so the low byte never overflows.
 */
static inline uint32_t sfg_arm_id(int family, unsigned int order_idx)
{
	return ((uint32_t)family << 8) | (order_idx & 0xffu);
}

unsigned int sfg_seq_record(uint32_t h);
void sfg_seq_credit(unsigned int slot, uint32_t arm_id, uint32_t reward);

#ifdef USE_IF_ALG
/*
 * AF_ALG lifecycle phase handlers (net/socket-family-grammar-alg.c).
 * bind/accept helpers return true on success; false signals bail to the
 * coordinator so late phases don't run against an unopened fd.  The
 * other handlers self-gate on ctx->conn_state / ctx->fam.alg.type and
 * degrade to no-ops on unmet preconditions.
 */
bool sfg_alg_do_bind(struct socket_ctx *ctx, unsigned int *err_burst);
void sfg_alg_do_setkey(struct socket_ctx *ctx);
void sfg_alg_do_set_aead(struct socket_ctx *ctx);
bool sfg_alg_do_accept(struct socket_ctx *ctx, unsigned int *err_burst);
void sfg_alg_do_cmsg(struct socket_ctx *ctx);
void sfg_alg_do_send_more(struct socket_ctx *ctx);
void sfg_alg_do_recv(struct socket_ctx *ctx);
#endif
