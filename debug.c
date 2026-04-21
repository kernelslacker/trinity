/*
 * Various routines useful for debugging.
 */


#ifdef USE_BACKTRACE
#include <execinfo.h>
#endif
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>
#include "child.h"
#include "debug.h"
#include "params.h"
#include "pids.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "version.h"

#define BACKTRACE_SIZE 100

static void __show_backtrace(void)
{
#ifdef USE_BACKTRACE
	unsigned int j, nptrs;
	void *buffer[BACKTRACE_SIZE];
	char **strings;

	nptrs = backtrace(buffer, BACKTRACE_SIZE);

	strings = backtrace_symbols(buffer, nptrs);
	if (strings == NULL) {
		perror("backtrace_symbols");
		return;
	}

	for (j = 0; j < nptrs; j++)
		output(0, "%s\n", strings[j]);

	free(strings);
#endif
}

static void show_child_backtrace(void)
{
	struct childdata *child = this_child();

	set_dontkillme(child, true);
	__show_backtrace();
	set_dontkillme(child, false);
}

void show_backtrace(void)
{
	pid_t pid = getpid();

	if (pid == mainpid) {
		__show_backtrace();
		return;
	}

	show_child_backtrace();
}

void __BUG(const char *bugtxt, const char *filename, const char *funcname, unsigned int lineno)
{
	struct childdata *child = this_child();

	outputerr("BUG!: %s\n", bugtxt);
	outputerr("BUG!: %s\n", VERSION);
	outputerr("BUG!: [%d] %s:%s:%u\n", getpid(), filename, funcname, lineno);

	show_backtrace();

	/* Now spin indefinitely (but allow ctrl-c) */

	if (child != NULL)
		set_dontkillme(child, true);

	while (1) {
		if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) == EXIT_SIGINT) {
			if (child != NULL)
				set_dontkillme(child, false);
			exit(EXIT_FAILURE);
		}
		sleep(1);
	}
}

void dump_syscallrec(struct syscallrecord *rec)
{
	struct syscallentry *entry = get_syscall_entry(rec->nr, rec->do32bit);
	const char *name = entry ? entry->name : "?";

	output(0, " nr:%d (%s) a1:%lx a2:%lx a3:%lx a4:%lx a5:%lx a6:%lx retval:%ld errno_post:%d\n",
		rec->nr, name, rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6, rec->retval, rec->errno_post);
	output(0, " do32bit:%d\n", rec->do32bit);
	output(0, " lock:%d (owner:%d)\n", LOCK_STATE(rec->lock.state), LOCK_OWNER(rec->lock.state));
	output(0, " state:%d\n", rec->state);
	output(0, " prebuffer : %p (len:%zu)\n", rec->prebuffer, strnlen(rec->prebuffer, PREBUFFER_LEN));
	output(0, " -> %.*s\n", PREBUFFER_LEN, rec->prebuffer);
	output(0, " postbuffer : %p (len:%zu)\n", rec->postbuffer, strnlen(rec->postbuffer, POSTBUFFER_LEN));
	output(0, " -> %.*s\n", POSTBUFFER_LEN, rec->postbuffer);
}

/*
 * dump_childdata is only called from the shm-corruption path, so the
 * struct we're handed is by definition untrustworthy.  Refuse to call
 * head->dump (a function pointer) unless the surrounding counters
 * pass a basic sanity check; otherwise we crash dereferencing junk
 * while trying to *report* the corruption.
 */
#define OBJHEAD_SANE_LIMIT	(1U << 16)

static bool objhead_looks_sane(const struct objhead *head)
{
	if (head->num_entries > OBJHEAD_SANE_LIMIT)
		return false;
	if (head->max_entries > OBJHEAD_SANE_LIMIT)
		return false;
	if (head->array_capacity > OBJHEAD_SANE_LIMIT)
		return false;
	if (head->num_entries > head->array_capacity)
		return false;
	if (head->max_entries > head->array_capacity)
		return false;
	if (head->num_entries > 0 && head->array == NULL)
		return false;
	return true;
}

void dump_childdata(struct childdata *child)
{
	output(0, "child struct @%p\n", child);

	output(0, " op_nr:%lx\n", child->op_nr);

	output(0, "syscall: %p\n", &child->syscall);
	dump_syscallrec(&child->syscall);

	output(0, "objects: %p\n", child->objects);
	{
		unsigned int i;
		for (i = 0; i < MAX_OBJECT_TYPES; i++) {
			struct objhead *head = &child->objects[i];

			if (head->num_entries == 0)
				continue;

			if (!objhead_looks_sane(head)) {
				output(0, " objhead[%u]: <corrupt: entries=%u max=%u capacity=%u array=%p>\n",
					i, head->num_entries, head->max_entries,
					head->array_capacity, head->array);
				continue;
			}

			output(0, " objhead[%u]: %u entries (max %u, capacity %u)\n",
				i, head->num_entries, head->max_entries,
				head->array_capacity);

			if (head->dump != NULL) {
				unsigned int j;
				for (j = 0; j < head->num_entries; j++)
					head->dump(head->array[j], OBJ_LOCAL);
			}
		}
	}

	output(0, " tp.tv_sec=%ld tp.tv_nsec=%ld\n", child->tp.tv_sec, child->tp.tv_nsec);

	output(0, "seed: %u\n", child->seed);
	output(0, "childnum: %d\n", child->num);

	output(0, "killcount: %d\n", child->kill_count);
	output(0, "dontkillme: %d\n", child->dontkillme);
	output(0, "\n");
};

/*
 * debugging output.
 * This is just a convenience helper to avoid littering the code
 * with dozens of 'if debug == true' comparisons causing unnecessary nesting.
 */
#define BUFSIZE 1024

void debugf(const char *fmt, ...)
{
	char debugbuf[BUFSIZE];
	va_list args;

	if (shm->debug == false)
		return;

	va_start(args, fmt);
	vsnprintf(debugbuf, BUFSIZE, fmt, args);
	va_end(args);
	output(0, "%s", debugbuf);
}

/* This is a bit crappy, wrapping a varargs fn with another,
 * but this saves us having to do the openlog/closelog for every
 * case where we want to write a message.
 */
void syslogf(const char *fmt, ...)
{
	char debugbuf[BUFSIZE];
	va_list args;

	va_start(args, fmt);
	vsnprintf(debugbuf, BUFSIZE, fmt, args);
	va_end(args);

	openlog("trinity", LOG_CONS|LOG_PERROR, LOG_USER);
	syslog(LOG_CRIT, "%s", debugbuf);
	closelog();
}
