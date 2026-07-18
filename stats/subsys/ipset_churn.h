#ifndef _TRINITY_STATS_SUBSYS_IPSET_CHURN_H
#define _TRINITY_STATS_SUBSYS_IPSET_CHURN_H

struct ipset_churn_stats {
	/* ipset_churn childop counters */
	unsigned long runs;			/* total ipset_churn invocations */
	unsigned long setup_failed;		/* nfnl socket open / IPSET_CMD_PROTOCOL probe failed */
	unsigned long create_ok;		/* IPSET_CMD_CREATE ack 0 or EEXIST (set tracked) */
	unsigned long create_fail;		/* IPSET_CMD_CREATE rejected (parse gate ran) */
	unsigned long add_ok;		/* IPSET_CMD_ADD ack 0 (entry inserted) */
	unsigned long test_ok;		/* IPSET_CMD_TEST ack 0 (lookup succeeded) */
	unsigned long del_ok;		/* IPSET_CMD_DEL ack 0 (entry removed) */
	unsigned long header_ok;		/* IPSET_CMD_HEADER ack 0 (header serializer ran) */
	unsigned long list_ok;		/* IPSET_CMD_LIST dump completed (element walker ran) */
	unsigned long swap_ok;		/* IPSET_CMD_SWAP ack 0 (partner rotation ran) */
	unsigned long flush_ok;		/* IPSET_CMD_FLUSH ack 0 (bulk erase ran) */
	unsigned long destroy_ok;		/* IPSET_CMD_DESTROY ack 0 or ENOENT (teardown reached kernel) */
};

#endif /* _TRINITY_STATS_SUBSYS_IPSET_CHURN_H */
