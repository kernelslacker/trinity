/*
 * Routines to take a syscallrecord and turn it into an ascii representation.
 */
#include <stdarg.h>
#include <stdio.h>
#include "arch.h"	//PAGE_MASK
#include "arg-decoder.h"
#include "params.h"	// verbosity
#include "pids.h"
#include "sanitise.h"	// get_argval
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "utils.h"

/*
 * Bounded sprintf for the sptr/end rendering pattern.
 * Advances sptr by the number of characters written, clamped to
 * available space so we never write past end.
 */
static char * bprintf(char *sptr, char *end, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

static char * bprintf(char *sptr, char *end, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (sptr >= end)
		return sptr;

	va_start(ap, fmt);
	n = vsnprintf(sptr, end - sptr, fmt, ap);
	va_end(ap);

	if (n > 0)
		sptr += (n < end - sptr) ? n : end - sptr - 1;

	return sptr;
}

static char * decode_argtype(char *sptr, char *end, unsigned long reg, enum argtype type)
{
	if (is_typed_fdarg(type)) {
		sptr = bprintf(sptr, end, "%ld", (long) reg);
		return sptr;
	}

	switch (type) {
	case ARG_PATHNAME:
		sptr = bprintf(sptr, end, "\"%s\"", (char *) reg);
		break;
	case ARG_PID:
	case ARG_FD:
	case ARG_SOCKETINFO:
		sptr = bprintf(sptr, end, "%ld", (long) reg);
		break;
	case ARG_MODE_T:
		sptr = bprintf(sptr, end, "%o", (mode_t) reg);
		break;

	case ARG_ADDRESS:
	case ARG_NON_NULL_ADDRESS:
	case ARG_IOVEC:
	case ARG_SOCKADDR:
		sptr = bprintf(sptr, end, "0x%lx", reg);
		break;

	case ARG_MMAP:
		/* Although generic sanitise has set this to a map struct,
		 * common_set_mmap_ptr_len() will subsequently set it to the ->ptr
		 * in the per syscall ->sanitise routine. */
		sptr = bprintf(sptr, end, "0x%lx", reg);
		break;

	case ARG_OP:
	case ARG_LIST:
		sptr = bprintf(sptr, end, "0x%lx", reg);
		break;

	case ARG_UNDEFINED:
	case ARG_LEN:
	case ARG_RANGE:
	case ARG_CPU:
	case ARG_IOVECLEN:
	case ARG_SOCKADDRLEN:
		if (((long) reg < -16384) || ((long) reg > 16384)) {
			/* Print everything outside -16384 and 16384 as hex. */
			sptr = bprintf(sptr, end, "0x%lx", reg);
		} else {
			/* Print everything else as signed decimal. */
			sptr = bprintf(sptr, end, "%ld", (long) reg);
		}
		break;
	default:
		break;
	}

	return sptr;
}

static char * render_arg(struct syscallrecord *rec, char *sptr, char *end, unsigned int argnum, struct syscallentry *entry)
{
	const char *name;
	unsigned long reg;
	enum argtype type;

	type = entry->argtype[argnum - 1];
	name = entry->argname[argnum - 1];
	reg = get_argval(rec, argnum);

	if (argnum != 1)
		sptr = bprintf(sptr, end, ", ");

	sptr = bprintf(sptr, end, "%s=", name);

	sptr = decode_argtype(sptr, end, reg, type);

	if (entry->decode != NULL) {
		char *str;

		str = entry->decode(rec, argnum);
		if (str != NULL) {
			sptr = bprintf(sptr, end, "%s", str);
			free(str);
		}
	}

	return sptr;
}

/*
 * Used from output_syscall_prefix, and also from postmortem dumper
 */
static unsigned int render_syscall_prefix(struct syscallrecord *rec, char *bufferstart)
{
	struct syscallentry *entry;
	struct childdata *child = this_child();
	char *sptr = bufferstart;
	char *end = bufferstart + PREBUFFER_LEN;
	unsigned int i;
	unsigned int syscallnr;

	syscallnr = rec->nr;
	entry = get_syscall_entry(syscallnr, rec->do32bit);
	if (entry == NULL)
		return 0;

	sptr = bprintf(sptr, end, "[child%u:%u] [%lu] %s",
			child->num, __atomic_load_n(&pids[child->num], __ATOMIC_RELAXED), child->op_nr,
			rec->do32bit == true ? "[32BIT] " : "");

	sptr = bprintf(sptr, end, "%s(", entry->name);

	for_each_arg(entry, i) {
		sptr = render_arg(rec, sptr, end, i, entry);
	}

	sptr = bprintf(sptr, end, ") ");

	return sptr - bufferstart;
}

static unsigned int render_syscall_postfix(struct syscallrecord *rec, char *bufferstart)
{
	char *sptr = bufferstart;
	char *end = bufferstart + POSTBUFFER_LEN;

	if (IS_ERR(rec->retval)) {
		sptr = bprintf(sptr, end, "= %ld (%s)",
			(long) rec->retval, strerror(rec->errno_post));
	} else {
		sptr = bprintf(sptr, end, "= ");
		if ((unsigned long) rec->retval > 10000)
			sptr = bprintf(sptr, end, "0x%lx", rec->retval);
		else
			sptr = bprintf(sptr, end, "%ld", (long) rec->retval);
	}
	sptr = bprintf(sptr, end, "\n");

	return sptr - bufferstart;
}

/* These next two functions are always called from child_random_syscalls() by a fuzzing child.
 * They render the buffer, and output it to stdout.
 * Other contexts (like post-mortem) directly use the buffers.
 */
void output_syscall_prefix(struct syscallrecord *rec)
{
	static char *buffer = NULL;
	unsigned int len;

	if (buffer == NULL)
		buffer = zmalloc(PREBUFFER_LEN);

	len = render_syscall_prefix(rec, buffer);

	/* copy child-local buffer to shm, NUL-terminate */
	memcpy(rec->prebuffer, buffer, len);
	rec->prebuffer[len] = '\0';

	output_rendered_buffer(rec->prebuffer);
}

void output_syscall_postfix(struct syscallrecord *rec)
{
	static char *buffer = NULL;
	unsigned int len;

	if (buffer == NULL)
		buffer = zmalloc(POSTBUFFER_LEN);

	len = render_syscall_postfix(rec, buffer);

	/* copy child-local buffer to shm, NUL-terminate */
	memcpy(rec->postbuffer, buffer, len);
	rec->postbuffer[len] = '\0';

	output_rendered_buffer(rec->postbuffer);
}
