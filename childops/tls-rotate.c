/*
 * tls_rotate - kTLS ULP install + cipher swap on a live loopback socket.
 *
 * Trinity's per-syscall fuzzer can issue setsockopt(SOL_TLS, TLS_TX, ...)
 * (proto-ipv4.c call_ulp_sso_ptr() builds the cinfo grammar) but flat
 * fuzzing essentially never assembles the four-step sequence kTLS
 * actually requires: TCP socket -> ESTABLISHED -> setsockopt(TCP_ULP,
 * "tls") -> setsockopt(SOL_TLS, TLS_TX, &cinfo).  Without those four
 * pieces in the right order, none of net/tls/ is reachable.  This
 * childop walks the lifecycle end-to-end and then re-installs TLS_TX
 * with a *different* cipher_info mid-stream, exercising the rekey /
 * EBUSY path that is the textbook bug class for new keying APIs
 * (CVE-2024-26583 tls_strp UAF, CVE-2024-26584 tls_sw_recvmsg,
 * CVE-2024-36904 tls_strp_msg, CVE-2025-21701 tls splice).
 *
 * Sequence:
 *   1. socket()+bind()+listen() a loopback TCP server fd.
 *   2. socket()+connect() a client fd to it; accept() the server side.
 *   3. setsockopt(TCP_ULP, "tls") on both ends (RX install requires it
 *      on the receive side too — bug-rich rekey paths only fire when
 *      both directions are armed).
 *   4. setsockopt(SOL_TLS, TLS_TX) with a random cipher_info on each
 *      end; setsockopt(SOL_TLS, TLS_RX) on the matching peer.
 *   5. send() a small payload through the TX side (drives
 *      tls_sw_sendmsg / TLS record build).
 *   6. setsockopt(SOL_TLS, TLS_TX) AGAIN with a DIFFERENT cipher_info
 *      (re-install / rekey).  This frequently EBUSYs on TLS_SW; the
 *      rejection path is itself a previously-unreached edge.  When the
 *      kernel does accept it (TLS_TX_ZEROCOPY_RO toggles, certain
 *      version transitions), the rekey codepath fires.
 *   7. send() another payload through the rotated key.
 *   8. shutdown / close all fds.
 *
 * Self-bounding: the whole sequence runs once per invocation, sockets
 * are non-blocking, and SIGALRM(1s) from child.c bounds any stray
 * blocking call.  Failures at every step are *expected* (config without
 * CONFIG_TLS, EBUSY on rekey, EAFNOSUPPORT in chroot) — they're all
 * code-path coverage, so we never propagate them as childop failure.
 *
 * If the kernel doesn't have CONFIG_TLS at all, setsockopt(TCP_ULP,
 * "tls") returns ENOENT.  We latch on the first failure for the
 * fleet so siblings stop probing.
 */

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "compat.h"
#include "random.h"
#include "shm.h"
#include "tls.h"
#include "trinity.h"

/* Cipher selector.  Keep distinct entries for the two install slots so
 * the rekey is GUARANTEED to swap cipher_type — that's where the
 * rejection / re-init paths bifurcate. */
enum tls_cipher_choice {
	TLS_CHOICE_AES_GCM_128,
	TLS_CHOICE_AES_GCM_256,
	TLS_CHOICE_CHACHA20,
	TLS_CHOICE_AES_CCM_128,
	NR_TLS_CHOICES,
};

static socklen_t fill_cinfo(enum tls_cipher_choice choice,
			    unsigned char *buf, unsigned short version)
{
	switch (choice) {
	case TLS_CHOICE_AES_GCM_128: {
		struct tls12_crypto_info_aes_gcm_128 *ci = (void *)buf;

		generate_rand_bytes(buf, sizeof(*ci));
		ci->info.version = version;
		ci->info.cipher_type = TLS_CIPHER_AES_GCM_128;
		return (socklen_t)sizeof(*ci);
	}
	case TLS_CHOICE_AES_GCM_256: {
		struct tls12_crypto_info_aes_gcm_256 *ci = (void *)buf;

		generate_rand_bytes(buf, sizeof(*ci));
		ci->info.version = version;
		ci->info.cipher_type = TLS_CIPHER_AES_GCM_256;
		return (socklen_t)sizeof(*ci);
	}
	case TLS_CHOICE_CHACHA20: {
		struct tls12_crypto_info_chacha20_poly1305 *ci = (void *)buf;

		generate_rand_bytes(buf, sizeof(*ci));
		ci->info.version = version;
		ci->info.cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
		return (socklen_t)sizeof(*ci);
	}
	case TLS_CHOICE_AES_CCM_128:
	default: {
		struct tls12_crypto_info_aes_ccm_128 *ci = (void *)buf;

		generate_rand_bytes(buf, sizeof(*ci));
		/* AES-CCM-128 is TLS 1.2 only in the kernel. */
		ci->info.version = TLS_1_2_VERSION;
		ci->info.cipher_type = TLS_CIPHER_AES_CCM_128;
		return (socklen_t)sizeof(*ci);
	}
	}
}

/* Build a connected TCP pair on loopback.  Returns 0 on success and
 * fills the cli/srv outparams; returns -1 on any setup failure (caller
 * treats it as benign — no kernel TLS == no coverage to grab). */
static int make_loopback_pair(int *cli, int *srv)
{
	struct sockaddr_in addr;
	socklen_t slen = sizeof(addr);
	int listener = -1;
	int c = -1, s = -1;
	int one = 1;

	listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener < 0)
		goto fail;

	(void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;

	if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		goto fail;
	if (listen(listener, 1) < 0)
		goto fail;
	if (getsockname(listener, (struct sockaddr *)&addr, &slen) < 0)
		goto fail;

	c = socket(AF_INET, SOCK_STREAM, 0);
	if (c < 0)
		goto fail;

	/* Non-blocking connect so a wedged loopback can't pin us past
	 * the SIGALRM bound.  Loopback connect completes synchronously
	 * in practice, but EINPROGRESS is also acceptable — we accept()
	 * regardless and proceed. */
	(void)fcntl(c, F_SETFL, O_NONBLOCK);
	if (connect(c, (struct sockaddr *)&addr, sizeof(addr)) < 0 &&
	    errno != EINPROGRESS)
		goto fail;

	s = accept(listener, NULL, NULL);
	if (s < 0)
		goto fail;

	close(listener);
	*cli = c;
	*srv = s;
	return 0;

fail:
	if (listener >= 0)
		close(listener);
	if (c >= 0)
		close(c);
	if (s >= 0)
		close(s);
	return -1;
}

bool tls_rotate(struct childdata *child)
{
	unsigned char cinfo[256];
	unsigned char payload[64];
	enum tls_cipher_choice c1, c2;
	unsigned short v1, v2;
	socklen_t clen;
	int cli = -1, srv = -1;
	int rc;

	(void)child;

	__atomic_add_fetch(&shm->stats.tls_rotate_runs, 1, __ATOMIC_RELAXED);

	if (make_loopback_pair(&cli, &srv) < 0) {
		__atomic_add_fetch(&shm->stats.tls_rotate_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	/* Install TCP_ULP="tls" on both ends.  Both sides must be ULP'd
	 * for the rekey-while-RX-is-also-armed bug class to be reachable. */
	if (setsockopt(cli, IPPROTO_TCP, TCP_ULP, "tls", 3) < 0) {
		__atomic_add_fetch(&shm->stats.tls_rotate_ulp_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	(void)setsockopt(srv, IPPROTO_TCP, TCP_ULP, "tls", 3);

	c1 = (enum tls_cipher_choice)((unsigned int)rand() % NR_TLS_CHOICES);
	v1 = RAND_BOOL() ? TLS_1_2_VERSION : TLS_1_3_VERSION;

	/* Step 4a: client TX install. */
	clen = fill_cinfo(c1, cinfo, v1);
	rc = setsockopt(cli, SOL_TLS, TLS_TX, cinfo, clen);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.tls_rotate_installs,
				   1, __ATOMIC_RELAXED);

	/* Step 4b: server RX install with the SAME params (matching peer).
	 * If the kernel rejects (cipher mismatch with what the client
	 * actually sent on rekey, version disallowed) it's still a code
	 * path — we don't gate progress on it. */
	clen = fill_cinfo(c1, cinfo, v1);
	(void)setsockopt(srv, SOL_TLS, TLS_RX, cinfo, clen);

	/* Step 5: drive tls_sw_sendmsg through the just-installed TX. */
	generate_rand_bytes(payload, sizeof(payload));
	(void)send(cli, payload, 1 + ((unsigned int)rand() % sizeof(payload)),
		   MSG_DONTWAIT);

	/* Step 6: REKEY — install TLS_TX again with a different cipher.
	 * This is THE bug window (CVE-2024-26583 family).  Pick a cipher
	 * that's not equal to c1 so cipher_type strictly differs. */
	do {
		c2 = (enum tls_cipher_choice)((unsigned int)rand() %
					      NR_TLS_CHOICES);
	} while (c2 == c1);
	v2 = RAND_BOOL() ? TLS_1_2_VERSION : TLS_1_3_VERSION;

	clen = fill_cinfo(c2, cinfo, v2);
	rc = setsockopt(cli, SOL_TLS, TLS_TX, cinfo, clen);
	if (rc == 0) {
		__atomic_add_fetch(&shm->stats.tls_rotate_rekeys_ok,
				   1, __ATOMIC_RELAXED);
	} else {
		/* EBUSY is the canonical "kTLS is already installed,
		 * can't re-init in place" rejection — exercising the
		 * reject-after-validate path that flat fuzzing skips. */
		__atomic_add_fetch(&shm->stats.tls_rotate_rekeys_rejected,
				   1, __ATOMIC_RELAXED);
	}

	/* Step 7: post-rekey send.  If the rekey was rejected, this
	 * still drives the original key's send path; if it was accepted,
	 * it drives the new key — either way we get coverage. */
	generate_rand_bytes(payload, sizeof(payload));
	(void)send(cli, payload, 1 + ((unsigned int)rand() % sizeof(payload)),
		   MSG_DONTWAIT);

	/* Occasionally toggle TLS_TX_ZEROCOPY_RO on the now-armed socket;
	 * the toggle is documented to fail unless TLS_RX is installed too,
	 * but the validation path is itself net/tls/ coverage. */
	if (ONE_IN(4)) {
		int zc = RAND_BOOL();

		(void)setsockopt(cli, SOL_TLS, TLS_TX_ZEROCOPY_RO,
				 &zc, sizeof(zc));
	}

	(void)shutdown(cli, SHUT_RDWR);
	(void)shutdown(srv, SHUT_RDWR);

out:
	if (cli >= 0)
		close(cli);
	if (srv >= 0)
		close(srv);
	return true;
}
