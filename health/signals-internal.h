/*
 * health/signals-internal.h — private cross-file interface for the
 * health/signals-*.c subsystem files.  Not for inclusion outside
 * health/signals-*.c.
 *
 * Provides:
 *  - struct sigsafe_buf + sigsafe_* byte-formatting primitives as
 *    static inline so every signals-*.c translation unit that needs
 *    them gets a private inlined copy (all callers are inside the
 *    health/ signals subsystem; no link-time exports required).
 *  - Forward declarations for the de-static'd helpers each .c file
 *    exports to its siblings.
 */
#pragma once

#include <signal.h>	/* siginfo_t */
#include <stddef.h>	/* size_t */
#include <stdint.h>	/* uintptr_t */

/*
 * Async-signal-safe formatting state.  Callers stack-allocate one of
 * these, pass it by pointer to sigsafe_put*(), then write() the
 * filled region to a fd.  No heap, no FILE, no lock.
 */
struct sigsafe_buf {
	char *p;
	size_t left;
};

static inline void sigsafe_putc(struct sigsafe_buf *b, char c)
{
	if (b->left > 0) {
		*b->p++ = c;
		b->left--;
	}
}

static inline void sigsafe_puts(struct sigsafe_buf *b, const char *s)
{
	while (*s != '\0')
		sigsafe_putc(b, *s++);
}

static inline void sigsafe_putu(struct sigsafe_buf *b, unsigned long v)
{
	char tmp[24];	/* 20 digits for u64 + slack */
	int i = 0;

	do {
		tmp[i++] = (char)('0' + (v % 10U));
		v /= 10U;
	} while (v != 0);
	while (i-- > 0)
		sigsafe_putc(b, tmp[i]);
}

static inline void sigsafe_puti(struct sigsafe_buf *b, long v)
{
	unsigned long u;

	if (v < 0) {
		sigsafe_putc(b, '-');
		/* Two-step negate so LONG_MIN does not overflow. */
		u = (unsigned long)(-(v + 1)) + 1UL;
	} else {
		u = (unsigned long)v;
	}
	sigsafe_putu(b, u);
}

static inline void sigsafe_putp(struct sigsafe_buf *b, const void *p)
{
	static const char hex[] = "0123456789abcdef";
	uintptr_t v = (uintptr_t)p;
	char tmp[2 * sizeof(uintptr_t)];
	int i = 0;

	sigsafe_putc(b, '0');
	sigsafe_putc(b, 'x');
	if (v == 0) {
		sigsafe_putc(b, '0');
		return;
	}
	while (v != 0) {
		tmp[i++] = hex[v & 0xfU];
		v >>= 4;
	}
	while (i-- > 0)
		sigsafe_putc(b, tmp[i]);
}

/* ------------------------------------------------------------------ */
/* signals-async-safe.c exports                                        */
/* ------------------------------------------------------------------ */

void write_siginfo_safely(int sig, const siginfo_t *info, const char *who);
#if defined(USE_BACKTRACE) && !defined(__SANITIZE_ADDRESS__)
void write_backtrace_raw_pcs(const char *who);
#endif
void *fault_beacon_extract_ip(const void *ctx);
void *fault_beacon_extract_sp(const void *ctx);

/* ------------------------------------------------------------------ */
/* signals-precrash.c exports                                          */
/* ------------------------------------------------------------------ */

void open_buglog_and_drain_stderr(int sig);

/* ------------------------------------------------------------------ */
/* signals-fault-handler.c exports (SA_SIGINFO handler signatures)    */
/* ------------------------------------------------------------------ */

void child_fault_handler(int sig, siginfo_t *info, void *ctx);
void writer_trap_handler(int sig, siginfo_t *info, void *ctx);
void main_fault_handler(int sig, siginfo_t *info, void *ctx);
