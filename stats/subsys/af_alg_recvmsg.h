#ifndef _TRINITY_STATS_SUBSYS_AF_ALG_RECVMSG_H
#define _TRINITY_STATS_SUBSYS_AF_ALG_RECVMSG_H

/*
 * af_alg_recvmsg_churn childop counters.  Drives the AF_ALG
 * setkey -> sendmsg(cmsg) -> recvmsg(rotating-iov) data-plane
 * path that the upstream aead_recvmsg memcpy_sglist GPF and
 * af_alg_pull_tsgl slab-OOB upstream CI reproducers hit; the
 * existing af_alg_template/af_alg_weak_cipher probes only walk
 * bind+accept and so don't reach the sg/tsgl rotation logic.
 * See childops/net/af-alg-recvmsg-churn.c.  The surrounding
 * struct stats_s composes an instance of struct
 * af_alg_recvmsg_stats as its "af_alg_recvmsg" member.
 */
struct af_alg_recvmsg_stats {
	unsigned long runs;			/* total invocations */
	unsigned long setkey_sent;		/* CMSG_ALG_SET_KEY emitted (alg_setkey_cmsg) */
	unsigned long iv_sent;			/* CMSG_ALG_SET_IV emitted (alg_setiv_cmsg) */
	unsigned long oob_iov;			/* slab-OOB-shaped sendmsg iov layout used */
	unsigned long zerolen;			/* recvmsg() with a 0-length output iov */
	unsigned long oversize;			/* recvmsg() with an oversize (64KB) output iov */
	unsigned long empty_cmsg_no_more;	/* sendmsg() cmsg-only, empty payload, no MSG_MORE */
	unsigned long unsupported;		/* socket(AF_ALG)/proc-crypto latched off */
};

#endif	/* _TRINITY_STATS_SUBSYS_AF_ALG_RECVMSG_H */
