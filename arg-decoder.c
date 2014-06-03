/*
 * Routines to take a syscallrecord and turn it into an ascii representation.
 */
#include <stdio.h>
#include "arch.h"	//PAGE_MASK
#include "log.h"
#include "maps.h"	// page_rand
#include "params.h"	// logging, monochrome, quiet_level
#include "pids.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "utils.h"

static void output_arg(unsigned int argnum, struct syscallentry *entry, FILE *fd, bool mono, int childno)
{
	enum argtype type = 0;
	const char *name = NULL;
	unsigned long reg = 0;

	switch (argnum) {
	case 1:	type = entry->arg1type;
		name = entry->arg1name;
		reg = shm->syscall[childno].a1;
		break;
	case 2:	type = entry->arg2type;
		name = entry->arg2name;
		reg = shm->syscall[childno].a2;
		break;
	case 3:	type = entry->arg3type;
		name = entry->arg3name;
		reg = shm->syscall[childno].a3;
		break;
	case 4:	type = entry->arg4type;
		name = entry->arg4name;
		reg = shm->syscall[childno].a4;
		break;
	case 5:	type = entry->arg5type;
		name = entry->arg5name;
		reg = shm->syscall[childno].a5;
		break;
	case 6:	type = entry->arg6type;
		name = entry->arg6name;
		reg = shm->syscall[childno].a6;
		break;
	}

	if (argnum != 1) {
		CRESETFD
		fprintf(fd, ", ");
	}

	fprintf(fd, "%s=", name);

	switch (type) {
	case ARG_PATHNAME:
		fprintf(fd, "\"%s\"", (char *) reg);
		break;
	case ARG_PID:
	case ARG_FD:
		CRESETFD
		fprintf(fd, "%ld", (long) reg);
		break;
	case ARG_MODE_T:
		CRESETFD
		fprintf(fd, "%o", (mode_t) reg);
		break;

	case ARG_ADDRESS:
	case ARG_NON_NULL_ADDRESS:
	case ARG_IOVEC:
	case ARG_SOCKADDR:
		fprintf(fd, "0x%lx", reg);
		break;

	case ARG_MMAP:
		/* Although generic sanitise has set this to a map struct,
		 * common_set_mmap_ptr_len() will subsequently set it to the ->ptr
		 * in the per syscall ->sanitise routine. */
		fprintf(fd, "%p", (void *) reg);
		break;

	case ARG_RANDPAGE:
		fprintf(fd, "0x%lx [page_rand]", reg);
		break;

	case ARG_OP:
	case ARG_LIST:
		fprintf(fd, "0x%lx", reg);
		break;

	case ARG_UNDEFINED:
	case ARG_LEN:
	case ARG_RANGE:
	case ARG_CPU:
	case ARG_RANDOM_LONG:
	case ARG_IOVECLEN:
	case ARG_SOCKADDRLEN:
		if (((long) reg < -16384) || ((long) reg > 16384)) {
			/* Print everything outside -16384 and 16384 as hex. */
			fprintf(fd, "0x%lx", reg);
		} else {
			/* Print everything else as signed decimal. */
			fprintf(fd, "%ld", (long) reg);
		}
		CRESETFD
		break;
	}

	if ((reg & PAGE_MASK) == (unsigned long) page_rand)
		fprintf(fd, "[page_rand]");

	if (entry->decode != NULL) {
		char *str;

		str = entry->decode(childno, argnum);
		if (str != NULL) {
			fprintf(fd, "%s", str);
			free(str);
		}
	}
}

/*
 * Used from output_syscall_prefix, and also from postmortem dumper
 */
void output_syscall_prefix_to_fd(int childno, FILE *fd, bool mono)
{
	struct syscallentry *entry;
	struct syscallrecord *rec;
	unsigned int i;
	unsigned int syscallnr;

	rec = &shm->syscall[childno];
	syscallnr = rec->nr;
	entry = get_syscall_entry(syscallnr, rec->do32bit);

	fprintf(fd, "[child%u:%u] [%lu] %s", childno, shm->pids[childno],
			rec->op_nr,
			(rec->do32bit == TRUE) ? "[32BIT] " : "");

	fprintf(fd, "%s", entry->name);

	CRESETFD
	fprintf(fd, "(");

	for (i = 1; i < entry->num_args + 1; i++)
		output_arg(i, entry, fd, mono, childno);

	CRESETFD
	fprintf(fd, ") ");
	fflush(fd);
}

/* This function is always called from a fuzzing child. */
void output_syscall_prefix(int childno)
{
	FILE *log_handle;

	/* Exit if should not continue at all. */
	if (logging == FALSE && quiet_level < MAX_LOGLEVEL)
		return;

	/* Find the log file handle */
	log_handle = robust_find_logfile_handle();

	/* do not output any ascii control symbols to files */
	if ((logging == TRUE) && (log_handle != NULL))
		output_syscall_prefix_to_fd(childno, log_handle, TRUE);

	/* Output to stdout only if -q param is not specified */
	if (quiet_level == MAX_LOGLEVEL)
		output_syscall_prefix_to_fd(childno, stdout, monochrome);
}

void output_syscall_postfix_err(unsigned long ret, int errno_saved, FILE *fd, bool mono)
{
	REDFD
	fprintf(fd, "= %ld (%s)", (long) ret, strerror(errno_saved));
	CRESETFD
	fprintf(fd, "\n");
	fflush(fd);
}

void output_syscall_postfix_success(unsigned long ret, FILE *fd, bool mono)
{
	GREENFD
	if ((unsigned long)ret > 10000)
		fprintf(fd, "= 0x%lx", ret);
	else
		fprintf(fd, "= %ld", (long) ret);
	CRESETFD
	fprintf(fd, "\n");
	fflush(fd);
}

void output_syscall_postfix(int childno)
{
	struct syscallrecord *rec;
	FILE *log_handle;
	bool err;

	rec = &shm->syscall[childno];
	err = IS_ERR(rec->retval);

	/* Exit if should not continue at all. */
	if (logging == FALSE && quiet_level < MAX_LOGLEVEL)
		return;

	/* Find the log file handle */
	log_handle = robust_find_logfile_handle();

	if (err) {
		if ((logging == TRUE) && (log_handle != NULL))
			output_syscall_postfix_err(rec->retval, rec->errno_post, log_handle, TRUE);
		if (quiet_level == MAX_LOGLEVEL)
			output_syscall_postfix_err(rec->retval, rec->errno_post, stdout, monochrome);
	} else {
		if ((logging == TRUE) && (log_handle != NULL))
			output_syscall_postfix_success(rec->retval, log_handle, TRUE);
		if (quiet_level == MAX_LOGLEVEL)
			output_syscall_postfix_success(rec->retval, stdout, monochrome);
	}
}
