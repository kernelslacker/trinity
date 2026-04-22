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
#include "list.h"
#include "params.h"
#include "pids.h"
#include "pre_crash_ring.h"
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

	/* Drain the pre-crash syscall ring(s).  For a child-side BUG, dump
	 * just this child's ring — that is by far the most relevant trace.
	 * For a parent-side BUG (this_child() returns NULL), iterate every
	 * child: parent crashes are typically downstream fallout from a
	 * child's recent wild write, so the offending syscall is sitting
	 * in some child's ring even though the parent has no obvious
	 * pointer to which one. */
	if (child != NULL)
		pre_crash_ring_dump(child);
	else
		pre_crash_ring_dump_all();

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
				for (j = 0; j < head->num_entries; j++) {
					/*
					 * dump_childdata is called from the shm-corruption /
					 * sanity-check path against another process's per-
					 * child OBJ_LOCAL pool, so head->array[] may be in
					 * the middle of an add/destroy when we read it.  A
					 * NULL slot inside the [0..num_entries) window
					 * indicates an in-flight mutation (or earlier
					 * corruption); skip it rather than dereferencing
					 * NULL inside the type-specific dump function.
					 */
					if (head->array[j] == NULL) {
						output(0, "  array[%u]: NULL (in-flight or corrupt)\n", j);
						continue;
					}
					head->dump(head->array[j], OBJ_LOCAL);
				}
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
 * Mirror of the Linux kernel's CONFIG_DEBUG_LIST validators.
 *
 * On any failure we log the specific corruption class observed (NULL
 * pointer, poison, or broken back-link) along with the call site, then
 * route to __BUG so the existing backtrace+spin path lets gdb attach
 * before the process is reaped.
 */
void __list_add_valid_or_die(struct list_head *new,
                             struct list_head *prev,
                             struct list_head *next,
                             const char *file,
                             const char *func,
                             unsigned int line)
{
	if (prev == NULL || next == NULL) {
		outputerr("list_add corruption at %s:%s:%u: prev=%p next=%p new=%p (NULL insertion point — caller passed in a torn list head)\n",
			file, func, line, prev, next, new);
		__BUG("list_add: NULL prev or next", file, func, line);
	}
	if (new == prev || new == next) {
		outputerr("list_add corruption at %s:%s:%u: new=%p coincides with prev=%p or next=%p (double-add or self-insertion)\n",
			file, func, line, new, prev, next);
		__BUG("list_add: self-insertion", file, func, line);
	}
	if (next->prev != prev) {
		outputerr("list_add corruption at %s:%s:%u: next->prev should be prev (%p) but is %p (next=%p new=%p) — surrounding link trampled\n",
			file, func, line, prev, next->prev, next, new);
		__BUG("list_add: next->prev != prev", file, func, line);
	}
	if (prev->next != next) {
		outputerr("list_add corruption at %s:%s:%u: prev->next should be next (%p) but is %p (prev=%p new=%p) — surrounding link trampled\n",
			file, func, line, next, prev->next, prev, new);
		__BUG("list_add: prev->next != next", file, func, line);
	}
}

void __list_del_entry_valid_or_die(struct list_head *entry,
                                   const char *file,
                                   const char *func,
                                   unsigned int line)
{
	struct list_head *prev, *next;

	if (entry == NULL) {
		outputerr("list_del corruption at %s:%s:%u: entry pointer itself is NULL\n",
			file, func, line);
		__BUG("list_del: entry == NULL", file, func, line);
	}
	if (entry->next == NULL || entry->prev == NULL) {
		outputerr("list_del corruption at %s:%s:%u: entry=%p has NULL link (next=%p prev=%p) — entry was zeroed by a stray write or never INIT_LIST_HEAD'd\n",
			file, func, line, entry, entry->next, entry->prev);
		__BUG("list_del: entry next/prev is NULL", file, func, line);
	}
	if (entry->next == LIST_POISON1) {
		outputerr("list_del corruption at %s:%s:%u: entry=%p next is LIST_POISON1 — double list_del or use-after-list_del\n",
			file, func, line, entry);
		__BUG("list_del: entry->next == LIST_POISON1", file, func, line);
	}
	if (entry->prev == LIST_POISON2) {
		outputerr("list_del corruption at %s:%s:%u: entry=%p prev is LIST_POISON2 — double list_del or use-after-list_del\n",
			file, func, line, entry);
		__BUG("list_del: entry->prev == LIST_POISON2", file, func, line);
	}

	prev = entry->prev;
	next = entry->next;
	if (prev->next != entry) {
		outputerr("list_del corruption at %s:%s:%u: entry=%p prev=%p but prev->next=%p (expected entry) — back-link broken\n",
			file, func, line, entry, prev, prev->next);
		outputerr(" entry contents: list.next=%p list.prev=%p\n", entry->next, entry->prev);
		outputerr(" prev contents:  list.next=%p list.prev=%p\n", prev->next, prev->prev);
		__BUG("list_del: prev->next != entry", file, func, line);
	}
	if (next->prev != entry) {
		outputerr("list_del corruption at %s:%s:%u: entry=%p next=%p but next->prev=%p (expected entry) — back-link broken\n",
			file, func, line, entry, next, next->prev);
		outputerr(" entry contents: list.next=%p list.prev=%p\n", entry->next, entry->prev);
		outputerr(" next contents:  list.next=%p list.prev=%p\n", next->next, next->prev);
		/*
		 * Distinguish the three forensic states with a one-line summary:
		 *   - both next->next and next->prev are NULL  -> next was zeroed
		 *     wholesale (freelist_push of a still-linked obj, or a memset
		 *     that hit it).
		 *   - next->prev is NULL and next->next looks like a freelist
		 *     link (a shared-heap-range pointer)        -> next is on the
		 *     freelist right now (free_shared_obj without list_del).
		 *   - next->prev is NULL and next->next looks like a valid list
		 *     pointer                                   -> stray 8-byte
		 *     write to next->prev only.
		 */
		if (next->prev == NULL && next->next == NULL)
			outputerr(" forensic: next is fully zeroed (freelist-push leftover or wholesale memset)\n");
		else if (next->prev == NULL)
			outputerr(" forensic: only next->prev is zero; next->next=%p (single 8-byte clobber, or freelist-linked)\n", next->next);
		__BUG("list_del: next->prev != entry", file, func, line);
	}
}

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
