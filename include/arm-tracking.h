#pragma once

/*
 * arm-tracking.h -- CHILDOP_ARM_ENTER macro for probabilistic-arm coverage.
 *
 * Include this header (directly or via child.h) in any translation unit
 * that dispatches via a switch-on-random-selector pattern so that every
 * switch-case arm calls CHILDOP_ARM_ENTER at its very top.
 *
 * --- Usage ---
 *
 *   switch (rnd_modulo_u32(N)) {
 *   case 0:
 *       CHILDOP_ARM_ENTER(my_subsys, arm_a);
 *       ...
 *   case 1:
 *       CHILDOP_ARM_ENTER(my_subsys, arm_b);
 *       ...
 *   }
 *
 * Prerequisites for a new childop:
 *
 *   1. Add `unsigned long arm_entered_<arm>;` fields to the subsystem
 *      stats struct in stats/subsys/<childop>.h.
 *   2. Expose them via the matching category array in stats/subsys/<childop>.c.
 *   3. Call CHILDOP_ARM_ENTER(subsys_field, arm_suffix) at the top of each
 *      switch-case arm, before any early-return or outcome counter.
 *   4. Add a drain-time check in dump_stats_dead_arm_check() (stats/dump/
 *      subsystems.c) so a zero tally over a full run is reported as
 *      DEAD_ARM: <childop>/<arm>.
 *
 * Detection: scripts/check-static/dead-arm-detect.sh warns (WARN, not FAIL)
 * about switch-on-rnd_modulo_u32 blocks that are missing this call.
 *
 * Caller must have shm.h in scope; child.h pulls it in transitively.
 * Files outside childops/ that use shm->stats directly should include
 * this header explicitly.
 */

/*
 * CHILDOP_ARM_ENTER(op, arm)
 *
 * Atomically increment shm->stats.op.arm_entered_##arm.  A zero count
 * at drain time means the arm received no traffic during the entire run
 * -- reported as DEAD_ARM by dump_stats_dead_arm_check().
 *
 * op:  stats subsystem field name  (e.g. igmp_mld_source_churn)
 * arm: arm_entered_* suffix        (e.g. race_v4_a, bind, migrate_state)
 */
#define CHILDOP_ARM_ENTER(op, arm) \
	__atomic_add_fetch(&shm->stats.op.arm_entered_##arm, 1, __ATOMIC_RELAXED)
