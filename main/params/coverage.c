/*
 * Coverage/CMP/frontier/strategy knobs.  parse_kcov_options() covers
 * the per-child KCOV buffer + attribution + transition rows;
 * parse_cmp_options() the redqueen/errno-gradient compatibility
 * rows; parse_strategy_options() the picker-mode + frontier + reach
 * + blob/cmsg + arg-length policy rows.  The canary and fork-pressure
 * childop knobs live in childop.c.
 */

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "arg-len-semantics.h"
#include "blob_mutator.h"
#include "cmp-frontier.h"
#include "cmp_hints.h"
#include "cmsg-richness.h"
#include "kcov.h"
#include "params.h"
#include "reach-band.h"
#include "strategy.h"
#include "trinity.h"	// outputerr
#include "utils.h"

#include "internal.h"

bool parse_kcov_options(int opt, const char *name, char *arg)
{
	if (opt != 0)
		return false;

	if (strcmp("childop-kcov-attribution", name) == 0) {
		if (strcmp(arg, "off") == 0) {
			childop_kcov_attr_mode = CHILDOP_KCOV_ATTR_OFF;
		} else if (strcmp(arg, "dual") == 0) {
			childop_kcov_attr_mode = CHILDOP_KCOV_ATTR_DUAL;
		} else if (strcmp(arg, "on") == 0) {
			childop_kcov_attr_mode = CHILDOP_KCOV_ATTR_ON;
		} else {
			outputerr("--childop-kcov-attribution: unknown mode '%s' (expected off, dual, or on)\n",
				arg);
			exit(EXIT_FAILURE);
		}
		return true;
	}

	if (strcmp("childop-cmp-harvest", name) == 0) {
		if (strcmp(arg, "off") == 0) {
			childop_cmp_harvest_mode = CHILDOP_CMP_HARVEST_OFF;
		} else if (strcmp(arg, "on") == 0) {
			childop_cmp_harvest_mode = CHILDOP_CMP_HARVEST_ON;
		} else {
			outputerr("--childop-cmp-harvest: unknown mode '%s' (expected off or on)\n",
				arg);
			exit(EXIT_FAILURE);
		}
		return true;
	}

	if (strcmp("childop-cmp-consume", name) == 0) {
		if (strcmp(arg, "off") == 0) {
			childop_cmp_consume_mode = CHILDOP_CMP_CONSUME_OFF;
		} else if (strcmp(arg, "on") == 0) {
			childop_cmp_consume_mode = CHILDOP_CMP_CONSUME_ON;
		} else {
			outputerr("--childop-cmp-consume: unknown mode '%s' (expected off or on)\n",
				arg);
			exit(EXIT_FAILURE);
		}
		return true;
	}

	if (strcmp("kcov-trace-size", name) == 0) {
		unsigned long val;

		if (!parse_unsigned(arg, "kcov-trace-size", false, &val))
			exit(EXIT_FAILURE);
		if (val < (unsigned long)KCOV_TRACE_SIZE) {
			outputerr("--kcov-trace-size=%lu below the lower bound %u (KCOV_TRACE_SIZE)\n",
				val, (unsigned int)KCOV_TRACE_SIZE);
			exit(EXIT_FAILURE);
		}
		if (val > KCOV_TRACE_SIZE_MAX) {
			outputerr("--kcov-trace-size=%lu exceeds upper bound %lu (KCOV_TRACE_SIZE_MAX)\n",
				val, (unsigned long)KCOV_TRACE_SIZE_MAX);
			exit(EXIT_FAILURE);
		}
		/* Power-of-2: matches the historical KCOV_TRACE_SIZE shape
		 * (and keeps the kernel's mmap-page alignment trivial). */
		if ((val & (val - 1)) != 0) {
			outputerr("--kcov-trace-size=%lu is not a power of 2\n",
				val);
			exit(EXIT_FAILURE);
		}
		kcov_trace_size = (unsigned int)val;
		return true;
	}

	if (strcmp("frontier-noise-sample", name) == 0) {
		unsigned long val;

		if (!parse_unsigned(arg, "frontier-noise-sample", false, &val))
			exit(EXIT_FAILURE);
		if (val > UINT_MAX) {
			outputerr("--frontier-noise-sample=%lu exceeds UINT_MAX\n",
				val);
			exit(EXIT_FAILURE);
		}
		frontier_noise_sample = (unsigned int)val;
		return true;
	}

	if (strcmp("kcov-transition-coverage", name) == 0) {
		if (strcmp(arg, "off") == 0) {
			kcov_transition_coverage_mode = KCOV_TRANSITION_COVERAGE_OFF;
		} else if (strcmp(arg, "shadow") == 0) {
			kcov_transition_coverage_mode = KCOV_TRANSITION_COVERAGE_SHADOW;
		} else {
			outputerr("--kcov-transition-coverage: unknown mode '%s' (expected off or shadow)\n",
				arg);
			exit(EXIT_FAILURE);
		}
		return true;
	}

	if (strcmp("kcov-transition-reward", name) == 0) {
		if (strcmp(arg, "off") == 0) {
			kcov_transition_reward_mode = KCOV_TRANSITION_REWARD_OFF;
		} else if (strcmp(arg, "shadow-only") == 0) {
			kcov_transition_reward_mode = KCOV_TRANSITION_REWARD_SHADOW_ONLY;
		} else if (strcmp(arg, "combined") == 0) {
			kcov_transition_reward_mode = KCOV_TRANSITION_REWARD_COMBINED;
		} else {
			outputerr("--kcov-transition-reward: unknown mode '%s' (expected off, shadow-only, or combined)\n",
				arg);
			exit(EXIT_FAILURE);
		}
		return true;
	}

	if (strcmp("bandit-reward-edge-count", name) == 0) {
		if (strcmp(arg, "off") == 0) {
			bandit_reward_edge_count_mode =
				BANDIT_REWARD_EDGE_COUNT_OFF;
		} else if (strcmp(arg, "shadow-only") == 0) {
			bandit_reward_edge_count_mode =
				BANDIT_REWARD_EDGE_COUNT_SHADOW_ONLY;
		} else if (strcmp(arg, "combined") == 0) {
			bandit_reward_edge_count_mode =
				BANDIT_REWARD_EDGE_COUNT_COMBINED;
		} else {
			outputerr("--bandit-reward-edge-count: unknown mode '%s' (expected off, shadow-only, or combined)\n",
				arg);
			exit(EXIT_FAILURE);
		}
		return true;
	}

	if (strcmp("expensive-adaptive", name) == 0) {
		if (strcmp(arg, "off") == 0) {
			expensive_adaptive_mode = EXPENSIVE_ADAPTIVE_MODE_OFF;
		} else if (strcmp(arg, "shadow-only") == 0) {
			expensive_adaptive_mode =
				EXPENSIVE_ADAPTIVE_MODE_SHADOW_ONLY;
		} else if (strcmp(arg, "combined") == 0) {
			expensive_adaptive_mode =
				EXPENSIVE_ADAPTIVE_MODE_COMBINED;
		} else {
			outputerr("--expensive-adaptive: unknown mode '%s' (expected off, shadow-only, or combined)\n",
				arg);
			exit(EXIT_FAILURE);
		}
		return true;
	}

	return false;
}

bool parse_cmp_options(int opt, const char *name, char *arg)
{
	if (opt != 0)
		return false;

	if (strcmp("redqueen-pending-pick", name) == 0) {
		if (!parse_redqueen_pending_pick(arg,
						 &redqueen_pending_pick_mode_arg)) {
			outputerr("--redqueen-pending-pick: unknown policy '%s' (try random or first)\n",
				  arg);
			exit(EXIT_FAILURE);
		}
		return true;
	}

	if (strcmp("corpus-save-errno-grad-live", name) == 0) {
		corpus_save_errno_grad_live = true;
		return true;
	}

	return false;
}

bool parse_strategy_options(int opt, const char *name, char *arg)
{
	if (opt != 0)
		return false;

	if (strcmp("strategy", name) == 0) {
		if (!parse_picker_mode(arg, &picker_mode_arg)) {
			outputerr("--strategy: unknown picker '%s' (try bandit or round-robin)\n",
				  arg);
			exit(EXIT_FAILURE);
		}
		return true;
	}

	if (strcmp("group-bias", name) == 0) {
		group_bias = true;
		return true;
	}

	if (strcmp("cred-throttle", name) == 0) {
		cred_throttle = true;
		return true;
	}

	if (strcmp("frontier-live-cooldown-mode", name) == 0) {
		if (strcmp(arg, "off") == 0) {
			frontier_live_cooldown_mode =
				FRONTIER_LIVE_COOLDOWN_MODE_OFF;
		} else if (strcmp(arg, "shadow-only") == 0) {
			frontier_live_cooldown_mode =
				FRONTIER_LIVE_COOLDOWN_MODE_SHADOW_ONLY;
		} else if (strcmp(arg, "combined") == 0) {
			frontier_live_cooldown_mode =
				FRONTIER_LIVE_COOLDOWN_MODE_COMBINED;
		} else {
			outputerr("--frontier-live-cooldown-mode: unknown mode '%s' (expected off, shadow-only, or combined)\n",
				arg);
			exit(EXIT_FAILURE);
		}
		return true;
	}

	if (strcmp("frontier-saturation-cooldown", name) == 0) {
		if (strcmp(arg, "off") == 0) {
			frontier_saturation_cooldown_mode =
				FRONTIER_SATURATION_COOLDOWN_MODE_OFF;
		} else if (strcmp(arg, "shadow-only") == 0) {
			frontier_saturation_cooldown_mode =
				FRONTIER_SATURATION_COOLDOWN_MODE_SHADOW_ONLY;
		} else if (strcmp(arg, "combined") == 0) {
			frontier_saturation_cooldown_mode =
				FRONTIER_SATURATION_COOLDOWN_MODE_COMBINED;
		} else {
			outputerr("--frontier-saturation-cooldown: unknown mode '%s' (expected off, shadow-only, or combined)\n",
				arg);
			exit(EXIT_FAILURE);
		}
		return true;
	}

	if (strcmp("frontier-barren-demote", name) == 0) {
		if (strcmp(arg, "off") == 0) {
			frontier_barren_demote_mode =
				FRONTIER_BARREN_DEMOTE_MODE_OFF;
		} else if (strcmp(arg, "shadow-only") == 0) {
			frontier_barren_demote_mode =
				FRONTIER_BARREN_DEMOTE_MODE_SHADOW_ONLY;
		} else if (strcmp(arg, "combined") == 0) {
			frontier_barren_demote_mode =
				FRONTIER_BARREN_DEMOTE_MODE_COMBINED;
		} else {
			outputerr("--frontier-barren-demote: unknown mode '%s' (expected off, shadow-only, or combined)\n",
				arg);
			exit(EXIT_FAILURE);
		}
		return true;
	}

	if (strcmp("cost-pool-selector", name) == 0) {
		if (strcmp(arg, "off") == 0) {
			cost_pool_selector_mode =
				COST_POOL_SELECTOR_MODE_OFF;
		} else if (strcmp(arg, "shadow-only") == 0) {
			cost_pool_selector_mode =
				COST_POOL_SELECTOR_MODE_SHADOW_ONLY;
		} else if (strcmp(arg, "combined") == 0) {
			cost_pool_selector_mode =
				COST_POOL_SELECTOR_MODE_COMBINED;
		} else {
			outputerr("--cost-pool-selector: unknown mode '%s' (expected off, shadow-only, or combined)\n",
				arg);
			exit(EXIT_FAILURE);
		}
		return true;
	}

	if (strcmp("context-pool", name) == 0) {
		if (strcmp(arg, "off") == 0) {
			context_pool_mode = CONTEXT_POOL_MODE_OFF;
		} else if (strcmp(arg, "shadow-only") == 0) {
			context_pool_mode = CONTEXT_POOL_MODE_SHADOW_ONLY;
		} else if (strcmp(arg, "combined") == 0) {
			context_pool_mode = CONTEXT_POOL_MODE_COMBINED;
		} else {
			outputerr("--context-pool: unknown mode '%s' (expected off, shadow-only, or combined)\n",
				arg);
			exit(EXIT_FAILURE);
		}
		return true;
	}

	if (strcmp("cmp-shared-tier", name) == 0) {
		if (strcmp(arg, "off") == 0) {
			cmp_shared_tier_mode = CMP_SHARED_TIER_MODE_OFF;
		} else if (strcmp(arg, "shadow") == 0) {
			cmp_shared_tier_mode = CMP_SHARED_TIER_MODE_SHADOW_ONLY;
		} else if (strcmp(arg, "combined") == 0) {
			cmp_shared_tier_mode = CMP_SHARED_TIER_MODE_COMBINED;
		} else {
			outputerr("--cmp-shared-tier: unknown mode '%s' (expected off, shadow, or combined)\n",
				arg);
			exit(EXIT_FAILURE);
		}
		return true;
	}

	if (strcmp("cmp-cfactual", name) == 0) {
		if (strcmp(arg, "off") == 0) {
			cmp_cfactual_mode = CMP_CFACTUAL_MODE_OFF;
		} else if (strcmp(arg, "shadow") == 0) {
			cmp_cfactual_mode = CMP_CFACTUAL_MODE_SHADOW;
		} else {
			outputerr("--cmp-cfactual: unknown mode '%s' (expected off or shadow)\n",
				arg);
			exit(EXIT_FAILURE);
		}
		return true;
	}

	if (strcmp("arg-len-semantics", name) == 0) {
		enum arg_len_semantics_mode mode;

		if (strcmp(arg, "off") == 0) {
			mode = ARG_LEN_SEMANTICS_OFF;
		} else if (strcmp(arg, "on") == 0) {
			mode = ARG_LEN_SEMANTICS_ON;
		} else {
			outputerr("--arg-len-semantics: unknown mode '%s' (expected off or on)\n",
				arg);
			exit(EXIT_FAILURE);
		}
		__atomic_store_n(&arg_len_semantics_mode, mode, __ATOMIC_RELAXED);
		return true;
	}

	if (strcmp("reach-band", name) == 0) {
		enum reach_band_mode mode;

		if (strcmp(arg, "off") == 0) {
			mode = REACH_BAND_OFF;
		} else if (strcmp(arg, "shadow-only") == 0) {
			mode = REACH_BAND_SHADOW_ONLY;
		} else if (strcmp(arg, "combined") == 0) {
			mode = REACH_BAND_COMBINED;
		} else {
			outputerr("--reach-band: unknown mode '%s' (expected off, shadow-only, or combined)\n",
				arg);
			exit(EXIT_FAILURE);
		}
		__atomic_store_n(&reach_band_mode, mode, __ATOMIC_RELAXED);
		return true;
	}

	if (strcmp("blob-mutator", name) == 0) {
		enum blob_mutator_mode mode;

		if (strcmp(arg, "off") == 0) {
			mode = BLOB_MUTATOR_OFF;
		} else if (strcmp(arg, "fill") == 0) {
			mode = BLOB_MUTATOR_FILL;
		} else if (strcmp(arg, "havoc") == 0) {
			mode = BLOB_MUTATOR_HAVOC;
		} else if (strcmp(arg, "cmpdict") == 0) {
			mode = BLOB_MUTATOR_CMPDICT;
		} else {
			outputerr("--blob-mutator: unknown mode '%s' (expected off, fill, havoc, or cmpdict)\n",
				arg);
			exit(EXIT_FAILURE);
		}
		__atomic_store_n(&blob_mutator_mode, mode, __ATOMIC_RELAXED);
		return true;
	}

	if (strcmp("cmp-frontier", name) == 0) {
		enum cmp_frontier_mode mode;

		if (strcmp(arg, "off") == 0) {
			mode = CMP_FRONTIER_OFF;
		} else if (strcmp(arg, "shadow-only") == 0) {
			mode = CMP_FRONTIER_SHADOW_ONLY;
		} else if (strcmp(arg, "combined") == 0) {
			mode = CMP_FRONTIER_COMBINED;
		} else {
			outputerr("--cmp-frontier: unknown mode '%s' (expected off, shadow-only, or combined)\n",
				arg);
			exit(EXIT_FAILURE);
		}
		__atomic_store_n(&cmp_frontier_mode, mode, __ATOMIC_RELAXED);
		return true;
	}

	if (strcmp("cmsg-richness", name) == 0) {
		enum cmsg_richness_mode mode;

		if (strcmp(arg, "off") == 0) {
			mode = CMSG_RICHNESS_OFF;
		} else if (strcmp(arg, "on") == 0) {
			mode = CMSG_RICHNESS_ON;
		} else {
			outputerr("--cmsg-richness: unknown mode '%s' (expected off or on)\n",
				arg);
			exit(EXIT_FAILURE);
		}
		__atomic_store_n(&cmsg_richness_mode, mode, __ATOMIC_RELAXED);
		return true;
	}

	if (strcmp("frontier-group-antilock", name) == 0) {
		if (strcmp(arg, "off") == 0) {
			frontier_group_antilock_mode =
				FRONTIER_GROUP_ANTILOCK_MODE_OFF;
		} else if (strcmp(arg, "shadow-only") == 0) {
			frontier_group_antilock_mode =
				FRONTIER_GROUP_ANTILOCK_MODE_SHADOW_ONLY;
		} else if (strcmp(arg, "combined") == 0) {
			frontier_group_antilock_mode =
				FRONTIER_GROUP_ANTILOCK_MODE_COMBINED;
		} else {
			outputerr("--frontier-group-antilock: unknown mode '%s' (expected off, shadow-only, or combined)\n",
				arg);
			exit(EXIT_FAILURE);
		}
		return true;
	}

	return false;
}
