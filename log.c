#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "arch.h" //PAGE_MASK
#include "log.h"
#include "maps.h" //pages
#include "params.h"	// logging, monochrome, quiet_level
#include "pids.h"
#include "shm.h"
#include "syscall.h" //syscalls
#include "tables.h"
#include "trinity.h"
#include "utils.h"

#define BUFSIZE 1024

static FILE *mainlogfile;
static bool logfiles_opened = FALSE;

void open_logfiles(void)
{
	unsigned int i;
	char *logfilename;

	logfilename = zmalloc(64);
	sprintf(logfilename, "trinity.log");
	unlink(logfilename);
	mainlogfile = fopen(logfilename, "a");
	if (!mainlogfile) {
		outputerr("## couldn't open logfile %s\n", logfilename);
		exit(EXIT_FAILURE);
	}

	for_each_pidslot(i) {
		sprintf(logfilename, "trinity-child%u.log", i);
		unlink(logfilename);
		shm->logfiles[i] = fopen(logfilename, "a");
		if (!shm->logfiles[i]) {
			outputerr("## couldn't open logfile %s\n", logfilename);
			exit(EXIT_FAILURE);
		}
	}
	free(logfilename);
	logfiles_opened = TRUE;
}

void close_logfiles(void)
{
	unsigned int i;

	for_each_pidslot(i)
		if (shm->logfiles[i] != NULL)
			fclose(shm->logfiles[i]);
}

static FILE * find_logfile_handle(void)
{
	pid_t pid;
	int i;

	pid = getpid();
	if (pid == initpid)
		return mainlogfile;

	if (pid == shm->mainpid)
		return mainlogfile;

	if (pid == watchdog_pid)
		return mainlogfile;

	i = find_pid_slot(pid);
	if (i != PIDSLOT_NOT_FOUND)
		return shm->logfiles[i];
	else {
		/* try one more time. FIXME: This is awful. */
		unsigned int j;

		sleep(1);
		i = find_pid_slot(pid);
		if (i != PIDSLOT_NOT_FOUND)
			return shm->logfiles[i];

		outputerr("## Couldn't find logfile for pid %d\n", pid);
		dump_pid_slots();
		outputerr("## Logfiles for pids: ");
		for_each_pidslot(j)
			outputerr("%p ", shm->logfiles[j]);
		outputerr("\n");
	}
	return NULL;
}

unsigned int highest_logfile(void)
{
	FILE *file;
	int ret;

	if (logging == FALSE)
		return 0;

	file = shm->logfiles[max_children - 1];
	ret = fileno(file);

	return ret;
}

void synclogs(void)
{
	unsigned int i;
	int fd;

	if (logging == FALSE)
		return;

	for_each_pidslot(i) {
		int ret;

		ret = fflush(shm->logfiles[i]);
		if (ret == EOF) {
			outputerr("## logfile flushing failed! %s\n", strerror(errno));
			continue;
		}

		fd = fileno(shm->logfiles[i]);
		if (fd != -1) {
			ret = fsync(fd);
			if (ret != 0)
				outputerr("## fsyncing logfile %d failed. %s\n", i, strerror(errno));
		}
	}

	(void)fflush(mainlogfile);
	fsync(fileno(mainlogfile));
}

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

	if ((reg & PAGE_MASK) == (unsigned long) page_zeros)
		fprintf(fd, "[page_zeros]");
	if ((reg & PAGE_MASK) == (unsigned long) page_rand)
		fprintf(fd, "[page_rand]");
	if ((reg & PAGE_MASK) == (unsigned long) page_0xff)
		fprintf(fd, "[page_0xff]");
	if ((reg & PAGE_MASK) == (unsigned long) page_allocs)
		fprintf(fd, "[page_allocs]");

	if (entry->decode != NULL) {
		char *str;

		str = entry->decode(argnum, childno);
		if (str != NULL) {
			fprintf(fd, "%s", str);
			free(str);
		}
	}
}

static FILE *robust_find_logfile_handle(void)
{
	FILE *handle = NULL;

	if ((logging == TRUE) && (logfiles_opened)) {
		handle = find_logfile_handle();
		if (!handle) {
			unsigned int j;

			outputerr("## child logfile handle was null logging to main!\n");
			(void)fflush(stdout);
			for_each_pidslot(j)
				shm->logfiles[j] = mainlogfile;
			sleep(5);
			handle = find_logfile_handle();
		}
	}
	return handle;
}

/*
 * level defines whether it gets displayed to the screen with printf.
 * (it always logs).
 *   0 = everything, even all the registers
 *   1 = Watchdog prints syscall count
 *   2 = Just the reseed values
 *
 */
void output(unsigned char level, const char *fmt, ...)
{
	va_list args;
	int n;
	FILE *handle;
	pid_t pid;
	char outputbuf[BUFSIZE];
	char *prefix = NULL;
	char watchdog_prefix[]="[watchdog]";
	char init_prefix[]="[init]";
	char main_prefix[]="[main]";
	char child_prefix[32];

	if (logging == FALSE && level >= quiet_level)
		return;

	/* prefix preparation */
	pid = getpid();
	if (pid == watchdog_pid)
		prefix = watchdog_prefix;

	if (pid == initpid)
		prefix = init_prefix;

	if (pid == shm->mainpid)
		prefix = main_prefix;

	if (prefix == NULL) {
		unsigned int slot;

		slot = find_pid_slot(pid);
		snprintf(child_prefix, sizeof(child_prefix), "[child%u:%u]", slot, pid);
		prefix = child_prefix;
	}

	/* formatting output */
	va_start(args, fmt);
	n = vsnprintf(outputbuf, sizeof(outputbuf), fmt, args);
	va_end(args);
	if (n < 0) {
		outputerr("## Something went wrong in output() [%d]\n", n);
		if (getpid() == shm->mainpid)
			exit_main_fail();
		else
			exit(EXIT_FAILURE);
	}

	/* stdout output if needed */
	if (quiet_level > level) {
		printf("%s %s", prefix, outputbuf);
		(void)fflush(stdout);
	}

	/* go on with file logs only if enabled */
	if (logging == FALSE)
		return;

	handle = robust_find_logfile_handle();
	if (!handle)
		return;

	/* If we've specified monochrome, we can just dump the buffer into
	 * the logfile as is, because there shouldn't be any ANSI codes
	 * in the buffer to be stripped out. */
	if (monochrome == FALSE) {
		char monobuf[BUFSIZE];
		unsigned int len, i, j;

		/* copy buffer, sans ANSI codes */
		len = strlen(outputbuf);
		for (i = 0, j = 0; (i < len) && (i + 2 < BUFSIZE) && (j < BUFSIZE); i++) {
			if (outputbuf[i] == '') {
				if (outputbuf[i + 2] == '1')
					i += 6;	// ANSI_COLOUR
				else
					i += 3;	// ANSI_RESET
			} else {
				monobuf[j] = outputbuf[i];
				j++;
			}
		}
		monobuf[j] = '\0';
		fprintf(handle, "%s %s", prefix, monobuf);
	} else {
		fprintf(handle, "%s %s", prefix, outputbuf);
	}

	(void)fflush(handle);
}

/*
* Used as a way to consolidated all printf calls if someones one to redirect it to somewhere else.
* note: this function ignores quiet_level since it main purpose is error output.
*/
void outputerr(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}

void outputstd(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stdout, fmt, args);
	va_end(args);
}

static void output_syscall_prefix_to_fd(const unsigned int childno, const unsigned int syscallnr, FILE *fd, bool mono)
{
	struct syscallentry *entry;
	unsigned int i;
	pid_t pid;

	entry = syscalls[syscallnr].entry;

	pid = getpid();

	fprintf(fd, "[child%u:%u] [%lu] %s", childno, pid, shm->child_op_count[childno],
			(shm->syscall[childno].do32bit == TRUE) ? "[32BIT] " : "");

	if (syscallnr > max_nr_syscalls)
		fprintf(fd, "%u", syscallnr);
	else
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
void output_syscall_prefix(const unsigned int childno)
{
	FILE *log_handle;
	unsigned int syscallnr = shm->syscall[childno].nr;

	/* Exit if should not continue at all. */
	if (logging == FALSE && quiet_level < MAX_LOGLEVEL)
		return;

	/* Find the log file handle */
	log_handle = robust_find_logfile_handle();

	/* do not output any ascii control symbols to files */
	if ((logging == TRUE) && (log_handle != NULL))
		output_syscall_prefix_to_fd(childno, syscallnr, log_handle, TRUE);

	/* Output to stdout only if -q param is not specified */
	if (quiet_level == MAX_LOGLEVEL)
		output_syscall_prefix_to_fd(childno, syscallnr, stdout, monochrome);
}

static void output_syscall_postfix_err(unsigned long ret, int errno_saved, FILE *fd, bool mono)
{
	REDFD
	fprintf(fd, "= %ld (%s)", (long) ret, strerror(errno_saved));
	CRESETFD
	fprintf(fd, "\n");
	fflush(fd);
}

static void output_syscall_postfix_success(unsigned long ret, FILE *fd, bool mono)
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

void output_syscall_postfix(unsigned long ret, int errno_saved)
{
	FILE *log_handle;
	bool err = IS_ERR(ret);

	/* Exit if should not continue at all. */
	if (logging == FALSE && quiet_level < MAX_LOGLEVEL)
		return;

	/* Find the log file handle */
	log_handle = robust_find_logfile_handle();

	if (err) {
		if ((logging == TRUE) && (log_handle != NULL))
			output_syscall_postfix_err(ret, errno_saved, log_handle, TRUE);
		if (quiet_level == MAX_LOGLEVEL)
			output_syscall_postfix_err(ret, errno_saved, stdout, monochrome);
	} else {
		if ((logging == TRUE) && (log_handle != NULL))
			output_syscall_postfix_success(ret, log_handle, TRUE);
		if (quiet_level == MAX_LOGLEVEL)
			output_syscall_postfix_success(ret, stdout, monochrome);
	}
}

/*
 * debugging output.
 * This is just a convenience helper to avoid littering the code
 * with dozens of 'if debug == TRUE' comparisons causing unnecessary nesting.
 */
void debugf(const char *fmt, ...)
{
	char debugbuf[BUFSIZE];
	va_list args;

	if (debug == FALSE)
		return;

	va_start(args, fmt);
	vsprintf(debugbuf, fmt, args);
	va_end(args);
	output(0, debugbuf);
}
