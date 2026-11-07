#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>
#include "pc_format.h"
#include "trinity.h"
#include "utils.h"

/*
 * Render a PROT_* mask as "READ|WRITE|EXEC" into the caller-provided
 * buffer.  Empties to "NONE" for prot==PROT_NONE so the diagnostic line
 * is never silently truncated to nothing between the brackets.  Unknown
 * upper bits (PROT_GROWSDOWN, pkey bits, ...) are left to the raw
 * 0x%x rendering at the call site.
 */
static void prot_to_string(int prot, char *buf, size_t buflen)
{
	int n = 0;
	int written;

	if (buf == NULL || buflen == 0)
		return;

	buf[0] = '\0';

	/* snprintf returns the would-have-written length even when truncated.
	 * Naive `n += snprintf(buf+n, buflen-n, ...)` advances n past buflen
	 * once the buffer fills, so the next call writes outside buf.  Currently
	 * safe at buflen=32 with the three short strings but identical cliff
	 * to the stats.c stack-depth histogram cumulator.  Bound n each step. */
	if ((prot & PROT_READ) && (size_t)n < buflen) {
		written = snprintf(buf + n, buflen - (size_t)n, "READ");
		if (written > 0)
			n += written;
	}
	if ((prot & PROT_WRITE) && (size_t)n < buflen) {
		written = snprintf(buf + n, buflen - (size_t)n,
				   "%sWRITE", n ? "|" : "");
		if (written > 0)
			n += written;
	}
	if ((prot & PROT_EXEC) && (size_t)n < buflen) {
		written = snprintf(buf + n, buflen - (size_t)n,
				   "%sEXEC", n ? "|" : "");
		if (written > 0)
			n += written;
	}

	if (n == 0)
		snprintf(buf, buflen, "NONE");
}

static const char *mprotect_errstr(int err)
{
	switch (err) {
	case ENOMEM:	return "ENOMEM";
	case EACCES:	return "EACCES";
	case EINVAL:	return "EINVAL";
	case EAGAIN:	return "EAGAIN";
	case EFAULT:	return "EFAULT";
	default:	return "unknown error";
	}
}

void log_mprotect_failure(void *addr, size_t len, int prot,
			  void *caller, int err)
{
	char protbuf[32];
	char pcbuf[128];

	prot_to_string(prot, protbuf, sizeof(protbuf));
	outputerr("mprotect(addr=%p, len=%zu, prot=0x%x [%s]) failed at %s: %s\n",
		  addr, len, prot, protbuf,
		  pc_to_string(caller, pcbuf, sizeof(pcbuf)),
		  mprotect_errstr(err));
}
