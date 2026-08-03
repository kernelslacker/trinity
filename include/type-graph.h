#pragma once

/*
 * Observation-only resource type-graph.
 *
 * Records the edges of a shallow producer -> consumer object-flow
 * graph inferred from the sequence-chain executor.  Every
 * publish_resource() successful call stamps (producer_nr, obj_type,
 * returned handle id) into a small direct-mapped ring.  When
 * apply_chain_substitution() splices a prior retval into a consumer
 * arg slot, it looks up that retval in the ring and -- on a hit --
 * bumps a per-edge triple of EMA-decayed counters:
 *
 *   total_ema   observations of the (producer_nr, obj_type,
 *               consumer_arg, consumer_nr) handoff
 *   success_ema observations whose consumer syscall returned
 *               a non-negative retval
 *   novel_ema   observations whose consumer syscall recorded new PC
 *               coverage
 *
 * The graph is a fixed-size open-addressed pool sized to keep the
 * shm footprint bounded; a full pool drops further inserts and
 * bumps edge_pool_exhausted so operator dumps can distinguish a
 * silent cap from a real signal absence.
 *
 * Slice A is observation-only: no consumer of these counters
 * influences the picker in random_syscall/ or the substitution
 * decision in chain-subst.c.  A byte-identical fuzzing run with
 * the observer wired remains the design contract.
 */

#include <stdbool.h>
#include <stdint.h>

#include "object-types.h"

/*
 * Direct-mapped ring the publish observer writes to and the
 * consume observer reads from.  Sizing target: fit publish + edge
 * pool together under ~200 KiB of shm to stay in the same order of
 * magnitude as the other observer subsystems (chain-corpus,
 * minicorpus).  Both dimensions are powers of two so slot lookup
 * is a mask.
 */
#define TYPE_GRAPH_PUBLISH_SLOTS	2048u
#define TYPE_GRAPH_EDGES_MAX		4096u

/*
 * Linear-probe budget for the edge pool.  A miss on all TYPE_GRAPH_
 * EDGE_PROBES neighbouring slots gives up and bumps edge_pool_
 * exhausted -- the graph is a Slice A observation surface and
 * eventual drop of a lost-race insert is acceptable.
 */
#define TYPE_GRAPH_EDGE_PROBES		8u

struct type_graph_publish_slot {
	unsigned long id;		/* value returned by producer */
	uint32_t gen;			/* monotonic; 0 == empty slot */
	uint16_t producer_nr;
	uint8_t obj_type;		/* enum objecttype fits in 8 bits */
	uint8_t producer_do32;
};

struct type_graph_edge {
	/*
	 * Packed (producer_nr << 16) | consumer_nr key.  Zero means
	 * the slot has never been claimed and is a candidate for the
	 * first inserter that lands here.  Both nrs use +1 encoding so
	 * a genuine producer_nr == 0 can be distinguished from empty.
	 */
	uint32_t key;
	/*
	 * Packed (obj_type << 8) | consumer_arg secondary key.  A slot
	 * with a matching primary key but a mismatched secondary key
	 * belongs to a different handoff -- the probe continues past
	 * it rather than merging distinct edges.
	 */
	uint32_t sub_key;

	uint32_t total_ema;
	uint32_t success_ema;
	uint32_t novel_ema;
	uint64_t observations;
	uint8_t producer_do32;
	uint8_t consumer_do32;
	uint8_t _pad[6];
};

struct type_graph_shm {
	struct type_graph_publish_slot publish[TYPE_GRAPH_PUBLISH_SLOTS];
	struct type_graph_edge edges[TYPE_GRAPH_EDGES_MAX];

	uint32_t next_gen;

	uint64_t publish_observations;
	uint64_t consume_observations;
	uint64_t consume_hits;
	uint64_t consume_misses;
	uint64_t edge_inserts;
	uint64_t edge_updates;
	uint64_t edge_pool_exhausted;
	uint64_t outcome_commits;
};

extern struct type_graph_shm *type_graph_shm;

void type_graph_init(void);

void type_graph_observe_publish(unsigned int producer_nr, bool do32bit,
				enum objecttype type, unsigned long id);

/*
 * Slot argument is 1-based (matches chain-subst's rec->aN indexing).
 * A zero slot is treated as "no substitution recorded" and the call
 * is a no-op.  Non-hit lookups still bump the miss counter so the
 * publish/consume dance is countable end-to-end.
 */
void type_graph_observe_consume(unsigned int consumer_nr, bool do32bit,
				unsigned int consumer_arg,
				unsigned long substitute_retval);

/*
 * Commit the outcome of the most recent consume observation on this
 * child.  Idempotent when no prior consume was recorded (the pending
 * slot is per-process file scope and clears itself on commit).
 * @success is set when the consumer syscall returned a non-negative
 * retval; @novel is set when the consumer step recorded new PC
 * coverage.  Callers that have neither signal can pass both false --
 * the observation still counts and its win-rate denominator advances.
 */
void type_graph_commit_outcome(bool success, bool novel);

/*
 * Render a top-N line-per-edge dump of the strongest observed
 * handoffs, ranked by total_ema.  N clamps at 20 for the shipping
 * observer surface.  Emits via output(0, ...) so the block folds
 * into the existing shutdown dump.
 */
void type_graph_dump_top_handoffs(void);

/*
 * Public iteration surface for external renderers (JSON emitter in
 * stats/json/, additional text dumps, offline snapshots).  Fills
 * @buf with up to TYPE_GRAPH_TOP_N entries ranked by total_ema
 * descending; returns the filled count.  @buf MUST have room for
 * TYPE_GRAPH_TOP_N entries.
 */
#define TYPE_GRAPH_TOP_N	20u

struct type_graph_top_entry {
	uint16_t producer_nr;
	uint16_t consumer_nr;
	uint8_t obj_type;
	uint8_t consumer_arg;
	uint8_t producer_do32;
	uint8_t consumer_do32;
	uint32_t total_ema;
	uint32_t success_ema;
	uint32_t novel_ema;
	uint64_t observations;
};

unsigned int type_graph_get_top_handoffs(struct type_graph_top_entry *buf);

/* Printable name for @type; NULL for types outside the enum. */
const char *type_graph_obj_type_name(uint8_t type);

/* Printable syscall name for (@nr, @do32bit); NULL when the entry
 * cannot be resolved. */
const char *type_graph_syscall_name(uint16_t nr, uint8_t do32bit);
