#ifndef _TRINITY_STATS_SUBSYS_TC_STANDALONE_ACTION_H
#define _TRINITY_STATS_SUBSYS_TC_STANDALONE_ACTION_H

struct tc_standalone_action_stats {
	/* tc_standalone_action childop counters */
	unsigned long runs;			/* total tc_standalone_action invocations */
	unsigned long setup_failed;		/* userns / rtnl open / grandchild fork latched */
	unsigned long qdisc_ok;			/* clsact install on the A veth end accepted */
	unsigned long qdisc_fail;		/* clsact install on the A veth end rejected */
	unsigned long action_create_ok;		/* RTM_NEWACTION (create) shared gact accepted */
	unsigned long action_create_fail;	/* RTM_NEWACTION (create) shared gact rejected */
	unsigned long filter_ok;		/* matchall filter referencing shared action accepted */
	unsigned long filter_fail;		/* matchall filter referencing shared action rejected */
	unsigned long packet_sent_ok;		/* live UDP sendto returned >0 */
	unsigned long action_replace_ok;	/* RTM_NEWACTION + NLM_F_REPLACE accepted (tcf_action_set_ctrlact) */
	unsigned long tc_action_replace_concurrent; /* replace cycles completed concurrently with in-flight traffic */
	unsigned long action_del_ok;		/* RTM_DELACTION accepted at teardown */
	unsigned long link_del_ok;		/* RTM_DELLINK on the A veth end at teardown accepted */
};

#endif /* _TRINITY_STATS_SUBSYS_TC_STANDALONE_ACTION_H */
