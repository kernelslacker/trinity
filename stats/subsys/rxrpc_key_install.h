#ifndef _TRINITY_STATS_SUBSYS_RXRPC_KEY_INSTALL_H
#define _TRINITY_STATS_SUBSYS_RXRPC_KEY_INSTALL_H

struct rxrpc_key_install_stats {
	/* rxrpc_key_install childop counters.  Coverage of the
	 * net/rxrpc/key.c token parsers reached via add_key("rxrpc", ...)
	 * and add_key("rxrpc_s", ...): null-security fast path, v1 binary
	 * RXKAD, XDR envelope (with XDR-RXKAD / XDR-RXGK inners), and
	 * rxkad/rxgk preparse_server_key. */
	unsigned long runs;		/* total rxrpc_key_install invocations */
	unsigned long calls;		/* total add_key/keyctl ops attempted */
	unsigned long revokes;	/* KEYCTL_REVOKE / KEYCTL_UNLINK accepted */
	unsigned long quota_hits;	/* add_key returned -EDQUOT */
	unsigned long unsupported;	/* per-process latch fired (no rxrpc key type) */
	unsigned long xrxgk_accepted;	/* XDR-RXGK arm add_key returned a serial -- penetration into rxrpc_preparse_xdr_yfs_rxgk past the length/level/enctype/expiry gates and through the alloc + key install */
};

#endif /* _TRINITY_STATS_SUBSYS_RXRPC_KEY_INSTALL_H */
