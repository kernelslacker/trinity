/*
 * Routines to take a syscallrecord and turn it into an ascii representation.
 */
#include <stdio.h>
#include "arch.h"	//PAGE_MASK
#include "arg-decoder.h"
#include "params.h"	// logging, quiet_level
#include "pids.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "utils.h"

static char * decode_argtype(char *sptr, unsigned long reg, enum argtype type)
{
	switch (type) {
	case ARG_PATHNAME:
		sptr += sprintf(sptr, "\"%s\"", (char *) reg);
		break;
	case ARG_PID:
	case ARG_FD:
	case ARG_SOCKETINFO:
		sptr += sprintf(sptr, "%ld", (long) reg);
		break;
	case ARG_MODE_T:
		sptr += sprintf(sptr, "%o", (mode_t) reg);
		break;

	case ARG_ADDRESS:
	case ARG_NON_NULL_ADDRESS:
	case ARG_IOVEC:
	case ARG_SOCKADDR:
		sptr += sprintf(sptr, "0x%lx", reg);
		break;

	case ARG_MMAP:
		/* Although generic sanitise has set this to a map struct,
		 * common_set_mmap_ptr_len() will subsequently set it to the ->ptr
		 * in the per syscall ->sanitise routine. */
		sptr += sprintf(sptr, "%p", (void *) reg);
		break;

	case ARG_OP:
	case ARG_LIST:
		sptr += sprintf(sptr, "0x%lx", reg);
		break;

	case ARG_UNDEFINED:
	case ARG_LEN:
	case ARG_RANGE:
	case ARG_CPU:
	case ARG_IOVECLEN:
	case ARG_SOCKADDRLEN:
		if (((long) reg < -16384) || ((long) reg > 16384)) {
			/* Print everything outside -16384 and 16384 as hex. */
			sptr += sprintf(sptr, "0x%lx", reg);
		} else {
			/* Print everything else as signed decimal. */
			sptr += sprintf(sptr, "%ld", (long) reg);
		}
		break;
	}

	return sptr;
}

static char * render_arg(struct syscallrecord *rec, char *sptr, unsigned int argnum, struct syscallentry *entry)
{
	const char *name = NULL;
	unsigned long reg = 0;
	enum argtype type = 0;

	switch (argnum) {
	case 1:	type = entry->arg1type;
		name = entry->arg1name;
		reg = rec->a1;
		break;
	case 2:	type = entry->arg2type;
		name = entry->arg2name;
		reg = rec->a2;
		break;
	case 3:	type = entry->arg3type;
		name = entry->arg3name;
		reg = rec->a3;
		break;
	case 4:	type = entry->arg4type;
		name = entry->arg4name;
		reg = rec->a4;
		break;
	case 5:	type = entry->arg5type;
		name = entry->arg5name;
		reg = rec->a5;
		break;
	case 6:	type = entry->arg6type;
		name = entry->arg6name;
		reg = rec->a6;
		break;
	}

	if (argnum != 1)
		sptr += sprintf(sptr, ", ");

	sptr += sprintf(sptr, "%s=", name);

	sptr = decode_argtype(sptr, reg, type);

	if (entry->decode != NULL) {
		char *str;

		str = entry->decode(rec, argnum);
		if (str != NULL) {
			sptr += sprintf(sptr, "%s", str);
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
	unsigned int i;
	unsigned int syscallnr;

	syscallnr = rec->nr;
	entry = get_syscall_entry(syscallnr, rec->do32bit);

	sptr += sprintf(sptr, "[child%u:%u] [%lu] %s",
			child->num, pids[child->num], child->op_nr,
			rec->do32bit == TRUE ? "[32BIT] " : "");

	sptr += sprintf(sptr, "%s(", entry->name);

	for_each_arg(entry, i) {
		sptr = render_arg(rec, sptr, i, entry);
	}

	sptr += sprintf(sptr, ") ");

	return sptr - bufferstart;
}

static unsigned int render_syscall_postfix(struct syscallrecord *rec, char *bufferstart)
{
	char *sptr = bufferstart;

	if (IS_ERR(rec->retval)) {
		sptr += sprintf(sptr, "= %ld (%s)",
			(long) rec->retval, strerror(rec->errno_post));
	} else {
		sptr += sprintf(sptr, "= ");
		if ((unsigned long) rec->retval > 10000)
			sptr += sprintf(sptr, "0x%lx", rec->retval);
		else
			sptr += sprintf(sptr, "%ld", (long) rec->retval);
	}
	sptr += sprintf(sptr, "\n");

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

	/* copy child-local buffer to shm, and zero out trailing bytes */
	memcpy(rec->prebuffer, buffer, len);
	memset(rec->prebuffer + len, 0, PREBUFFER_LEN - len);

	output_rendered_buffer(rec->prebuffer);
}

void output_syscall_postfix(struct syscallrecord *rec)
{
	static char *buffer = NULL;
	unsigned int len;

	if (buffer == NULL)
		buffer = zmalloc(POSTBUFFER_LEN);

	len = render_syscall_postfix(rec, buffer);

	/* copy child-local buffer to shm, and zero out trailing bytes */
	memcpy(rec->postbuffer, buffer, len);
	memset(rec->postbuffer + len, 0, POSTBUFFER_LEN - len);

	output_rendered_buffer(rec->postbuffer);
}
