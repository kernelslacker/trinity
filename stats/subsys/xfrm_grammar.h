#ifndef _TRINITY_STATS_SUBSYS_XFRM_GRAMMAR_H
#define _TRINITY_STATS_SUBSYS_XFRM_GRAMMAR_H

struct xfrm_grammar_stats {
	/* XFRM netlink grammar accounting (net/proto/netlink-xfrm.c).
	 *
	 * msg_kind_draws counts every draw from the message-kind picker,
	 * so a dead-arm verdict can be gated on the opportunities the
	 * picker actually had rather than on a childop's run count.
	 *
	 * migrate_state_arm_entered counts entries into the
	 * XMK_MIGRATE_STATE arm.  Zero entries against a non-zero draw
	 * count means the arm is structurally unreachable; entries with
	 * no acks upstream means the emitter is broken.  The two are
	 * different bugs and only the pair distinguishes them. */
	unsigned long msg_kind_draws;
	unsigned long migrate_state_arm_entered;
};

#endif /* _TRINITY_STATS_SUBSYS_XFRM_GRAMMAR_H */
