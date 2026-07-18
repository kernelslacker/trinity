#ifndef _TRINITY_STATS_SUBSYS_AF_ALG_WEAK_CIPHER_PROBE_H
#define _TRINITY_STATS_SUBSYS_AF_ALG_WEAK_CIPHER_PROBE_H

struct af_alg_weak_cipher_probe_stats {
	/* af_alg_weak_cipher_probe childop counters.  Enumerates which
	 * crypto template names AF_ALG accepts via bind(); surfaces the
	 * deprecated/weak templates the kernel still accepts as a
	 * hardening signal, plus a small strong-template control set. */
	unsigned long runs;			/* total invocations */
	unsigned long socket_failed;		/* socket(AF_ALG) returned <0 */
	unsigned long total_bind_attempts;	/* bind() calls issued */
	unsigned long total_bind_accepted;	/* bind() returned 0 */
	unsigned long weak_accepted_total;	/* of those, hits on the weak-template set */
	unsigned long setkey_accepted_total;	/* skcipher/aead setsockopt(ALG_SET_KEY) returned 0 */
	unsigned long skcipher_weak_accepted;	/* per-kind weak-bucket: skcipher */
	unsigned long aead_weak_accepted;	/* per-kind weak-bucket: aead */
	unsigned long hash_weak_accepted;	/* per-kind weak-bucket: hash */
	unsigned long strong_rejected;		/* control template rejected -- structurally broken kernel */
};

#endif /* _TRINITY_STATS_SUBSYS_AF_ALG_WEAK_CIPHER_PROBE_H */
