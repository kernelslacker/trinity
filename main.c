#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "child.h"
#include "debug.h"
#include "log.h"
#include "params.h"
#include "pids.h"
#include "post-mortem.h"
#include "random.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"


static unsigned long hiscore = 0;

/*
 * Make sure various entries in the shm look sensible.
 * We use this to make sure that random syscalls haven't corrupted it.
 *
 * also check the pids for sanity.
 */
static int shm_is_corrupt(void)
{
	unsigned int i;

	if (shm->stats.total_syscalls_done < shm->stats.previous_op_count) {
		output(0, "Execcount went backwards! (old:%ld new:%ld):\n",
			shm->stats.previous_op_count, shm->stats.total_syscalls_done);
		panic(EXIT_SHM_CORRUPTION);
		return TRUE;
	}
	shm->stats.previous_op_count = shm->stats.total_syscalls_done;

	for_each_child(i) {
		struct childdata *child;
		pid_t pid;

		child = shm->children[i];
		pid = pids[i];
		if (pid == EMPTY_PIDSLOT)
			continue;

		if (pid_is_valid(pid) == FALSE) {
			static bool once = FALSE;

			if (once != FALSE)
				return TRUE;

			output(0, "Sanity check failed! Found pid %u at pidslot %u!\n", pid, i);

			dump_childnos();

			if (shm->exit_reason == STILL_RUNNING)
				panic(EXIT_PID_OUT_OF_RANGE);
			dump_childdata(child);
			once = TRUE;
			return TRUE;
		}
	}

	return FALSE;
}

/*
 * reap_child: Remove all references to a running child.
 *
 * This can get called from two possible places.
 * 1. From reap_dead_kids if it finds reference to a pid that no longer exists.
 * 2. From handle_child() if it gets a SIGBUS or SIGSTOP from the child,
 *    or if it dies from natural causes.
 *
 * The reaper lock protects against these happening at the same time.
 */
void reap_child(pid_t childpid)
{
	struct childdata *child;
	int i;

	i = find_childno(childpid);
	if (i == CHILD_NOT_FOUND)
		return;

	child = shm->children[i];
	child->syscall.tp = (struct timespec){};
	unlock(&child->syscall.lock);
	shm->running_childs--;
	pids[i] = EMPTY_PIDSLOT;
}

/* Make sure there's no dead kids lying around.
 * We need to do this in case the oom killer has been killing them,
 * otherwise we end up stuck with no child processes.
 */
static void reap_dead_kids(void)
{
	unsigned int i;
	unsigned int reaped = 0;

	for_each_child(i) {
		pid_t pid;
		int ret;

		pid = pids[i];
		if (pid == EMPTY_PIDSLOT)
			continue;

		/* if we find corruption, just skip over it. */
		if (pid_is_valid(pid) == FALSE)
			continue;

		ret = kill(pid, 0);
		/* If it disappeared, reap it. */
		if (ret == -1) {
			if (errno == ESRCH) {
				output(0, "pid %u has disappeared. Reaping.\n", pid);
				reap_child(pid);
				reaped++;
			} else {
				output(0, "problem checking on pid %u (%d:%s)\n", pid, errno, strerror(errno));
			}
		}

		if (shm->running_childs == 0)
			return;
	}

	if (reaped != 0)
		output(0, "Reaped %d dead children\n", reaped);
}

static void kill_all_kids(void)
{
	unsigned int i;
	int children_seen = 0;

	shm->spawn_no_more = TRUE;

	reap_dead_kids();

	if (shm->running_childs == 0)
		return;

	/* Ok, some kids are still alive. 'help' them along with a SIGKILL */
	for_each_child(i) {
		pid_t pid;
		int ret;

		pid = pids[i];
		if (pid == EMPTY_PIDSLOT)
			continue;

		/* if we find corruption, just skip over it. */
		if (pid_is_valid(pid) == FALSE)
			continue;

		children_seen++;

		ret = kill(pid, SIGKILL);
		/* check we don't have anything stale in the pidlist */
		if (ret == -1) {
			if (errno == ESRCH)
				reap_child(pid);
		}
	}

	if (children_seen == 0)
		shm->running_childs = 0;

	/* Check that no dead children hold locks. */
	while (check_all_locks() == TRUE)
		reap_dead_kids();
}


/* if the first arg was an fd, find out which one it was.
 * Call with syscallrecord lock held. */
unsigned int check_if_fd(struct childdata *child, struct syscallrecord *rec)
{
	struct syscallentry *entry;
	unsigned int fd;

	entry = get_syscall_entry(rec->nr, rec->do32bit);

	if ((entry->arg1type != ARG_FD) &&
	    (entry->arg1type != ARG_SOCKETINFO))
	    return FALSE;

	/* in the SOCKETINFO case, post syscall, a1 is actually the fd,
	 * not the socketinfo.  In ARG_FD a1=fd.
	 */
	fd = rec->a1;

	/* if it's out of range, it's not going to be valid. */
	if (fd > 1024)
		return FALSE;

	if (logging == LOGGING_FILES) {
		if (child->logfile == NULL)
			return FALSE;

		if (fd <= (unsigned int) fileno(child->logfile))
			return FALSE;
	}
	return TRUE;
}

/*
 * This is only ever used by the main process, so we cache the FILE ptr
 * for each child there, to save having to constantly reopen it.
 */
static FILE * open_child_pidstat(pid_t target)
{
	FILE *fp;
	char filename[80];

	sprintf(filename, "/proc/%d/stat", target);

	fp = fopen(filename, "r");

	return fp;
}

static char get_pid_state(struct childdata *child)
{
	size_t n = 0;
	char *line = NULL;
	pid_t pid;
	char state = '?';
	char *procname = zmalloc(100);

	if (getpid() != mainpid)
		BUG("get_pid_state can only be called from main!\n");

	rewind(child->pidstatfile);
	if (getline(&line, &n, child->pidstatfile) != -1)
		sscanf(line, "%d %s %c", &pid, procname, &state);

	free(line);
	free(procname);
	return state;
}

static void stuck_syscall_info(struct childdata *child)
{
	struct syscallrecord *rec;
	unsigned int callno;
	char fdstr[20];
	bool do32;

	if (shm->debug == FALSE)
		return;

	rec = &child->syscall;

	if (trylock(&rec->lock) == FALSE)
		return;

	do32 = rec->do32bit;
	callno = rec->nr;

	memset(fdstr, 0, sizeof(fdstr));

	/* we can only be 'stuck' if we're still doing the syscall. */
	if (rec->state == BEFORE) {
		if (check_if_fd(child, rec) == TRUE) {
			sprintf(fdstr, "(fd = %u)", (unsigned int) rec->a1);
			shm->fd_lifetime = 0;
			//close(rec->a1);
			//TODO: Remove the fd from the object list.
		}
	}

	unlock(&rec->lock);

	output(0, "child %d (pid %u) Stuck in syscall %d:%s%s%s.\n",
		child->num, pids[child->num], callno,
		print_syscall_name(callno, do32),
		do32 ? " (32bit)" : "",
		fdstr);
}

/*
 * Check that a child is making forward progress by comparing the timestamps it
 * recorded before making its last syscall.
 * If no progress is being made, send SIGKILLs to it.
 */
static bool is_child_making_progress(struct childdata *child)
{
	struct syscallrecord *rec;
	struct timespec tp;
	time_t diff, old, now;
	pid_t pid;
	char state;

	pid = pids[child->num];

	if (pid == EMPTY_PIDSLOT)
		return TRUE;

	rec = &child->syscall;

	old = rec->tp.tv_sec;

	/* haven't done anything yet. */
	if (old == 0)
		return TRUE;

	clock_gettime(CLOCK_MONOTONIC, &tp);
	now = tp.tv_sec;

	if (old > now)
		diff = old - now;
	else
		diff = now - old;

	/* hopefully the common case. */
	if (diff < 30)
		return TRUE;

	/* if we're blocked in uninteruptible sleep, SIGKILL won't help. */
	state = get_pid_state(child);
	if (state == 'D') {
		//debugf("child %d (pid %u) is blocked in D state\n", child->num, pid);
		return FALSE;
	}

	/* After 30 seconds of no progress, send a kill signal. */
	if (diff == 30) {
		stuck_syscall_info(child);
		debugf("child %d (pid %u) hasn't made progress in 30 seconds! Sending SIGKILL\n",
				child->num, pid);
		child->kill_count++;
		kill_pid(pid);
	}

	/* if we're still around after 40s, repeatedly send SIGKILLs every second. */
	if (diff < 40)
		return FALSE;

	debugf("sending another SIGKILL to child %d (pid %u). [kill count:%d] [diff:%d]\n",
		child->num, pid, child->kill_count, diff);
	child->kill_count++;
	kill_pid(pid);

	return FALSE;
}

/*
 * If we call this, all children are stalled. Randomly kill a few.
 */
static void stall_genocide(void)
{
	unsigned int killed = 0;
	unsigned int i;

	for_each_child(i) {
		pid_t pid = pids[i];
		if (pid == EMPTY_PIDSLOT)
			continue;

		if (RAND_BOOL()) {
			int ret;

			ret = kill(pid, SIGKILL);
			if (ret == 0)
				killed++;
		}
		if (killed == (max_children / 4))
			break;
	}
}

static bool spawn_child(int childno)
{
	struct childdata *child = shm->children[childno];
	int pid = 0;

	/* Wipe out any state left from a previous child running in this slot. */
	clean_childdata(child);

	fflush(stdout);
	pid = fork();

	if (pid == 0) {
		/* Child process. */
		init_child(child, childno);

		child_process();

		shutdown_child_logging(child);

		debugf("child %d %d exiting.\n", childno, getpid());
		_exit(EXIT_SUCCESS);
	} else {
		if (pid == -1) {
			debugf("Couldn't fork a new child in pidslot %d. errno:%s\n",
					childno, strerror(errno));
			return FALSE;
		}
	}

	/* Child won't get out of init_child until we write the pid */
	pids[childno] = pid;
	child->pidstatfile = open_child_pidstat(pid);
	shm->running_childs++;

	debugf("Created child %d (pid:%d) [total:%d/%d]\n",
		childno, pid, shm->running_childs, max_children);
	return TRUE;
}

static void replace_child(int childno)
{
	if (shm->exit_reason != STILL_RUNNING)
		return;

	while (spawn_child(childno) == FALSE);
}

/* Generate children*/
static void fork_children(void)
{
	while (shm->running_childs < max_children) {
		int childno;

		if (shm->spawn_no_more == TRUE)
			return;

		/* a new child means a new seed, or the new child
		 * will do the same syscalls as the one in the child it's replacing.
		 * (special case startup, or we reseed unnecessarily)
		 */
		if (shm->ready == TRUE)
			reseed();

		/* Find a space for it in the pid map */
		childno = find_childno(EMPTY_PIDSLOT);
		if (childno == CHILD_NOT_FOUND) {
			outputerr("## Pid map was full!\n");
			dump_childnos();
			exit(EXIT_FAILURE);
		}

		if (spawn_child(childno) == FALSE) {
			outputerr("Couldn't fork initial children!\n");
			panic(EXIT_FORK_FAILURE);
			exit(EXIT_FAILURE);
		}

		if (shm->exit_reason != STILL_RUNNING)
			return;
	}
	shm->ready = TRUE;
}

static void handle_childsig(int childno, int childstatus, bool stop)
{
	struct childdata *child;
	int __sig;

	child = shm->children[childno];

	if (stop == TRUE)
		__sig = WSTOPSIG(childstatus);
	else
		__sig = WTERMSIG(childstatus);

	switch (__sig) {
	case SIGSTOP:
		if (stop != TRUE)
			return;
		debugf("Sending PTRACE_DETACH (and then KILL)\n");
		ptrace(PTRACE_DETACH, pids[childno], NULL, NULL);
		kill(pids[childno], SIGKILL);
		//FIXME: Won't we create a zombie here?
		reap_child(pids[childno]);
		replace_child(childno);
		return;

	case SIGALRM:
		debugf("got a alarm signal from child %d (pid %d)\n", childno, pids[childno]);
		break;
	case SIGFPE:
	case SIGSEGV:
	case SIGKILL:
	case SIGPIPE:
	case SIGABRT:
	case SIGBUS:
		if (stop == TRUE)
			debugf("Child %d (pid %d) was stopped by %s\n",
					childno, pids[childno], strsignal(WSTOPSIG(childstatus)));
		else
			debugf("got a signal from child %d (pid %d) (%s)\n",
					childno, pids[childno], strsignal(WTERMSIG(childstatus)));
		reap_child(pids[childno]);

		fclose(child->pidstatfile);
		child->pidstatfile = NULL;

		replace_child(childno);
		return;

	default:
		if (__sig >= SIGRTMIN) {
			debugf("Child %d got RT signal (%d). Ignoring.\n", pids[childno], __sig);
			return;
		}

		if (stop == TRUE)
			debugf("Child %d was stopped by unhandled signal (%s).\n", pids[childno], strsignal(WSTOPSIG(childstatus)));
		else
			debugf("** Child got an unhandled signal (%d)\n", WTERMSIG(childstatus));
		return;
	}
}


static void handle_child(int childno, pid_t childpid, int childstatus)
{
	switch (childpid) {
	case 0:
		//debugf("Nothing changed. children:%d\n", shm->running_childs);
		break;

	case -1:
		if (shm->exit_reason != STILL_RUNNING)
			return;

		if (errno == ECHILD) {
			unsigned int i;
			bool seen = FALSE;

			debugf("All children exited!\n");

			for_each_child(i) {
				pid_t pid = pids[i];
				if (pid != EMPTY_PIDSLOT) {
					if (pid_alive(pid) == -1) {
						pids[i] = EMPTY_PIDSLOT;
						shm->running_childs--;
						replace_child(i);
					} else {
						debugf("%d looks still alive! ignoring.\n", pid);
					}
					seen = TRUE;
				}
			}
			if (seen == FALSE)
				shm->running_childs = 0;
			break;
		}
		output(0, "error! (%s)\n", strerror(errno));
		break;

	default:
		if (WIFEXITED(childstatus)) {
			struct childdata *child = shm->children[childno];

			debugf("Child %d (pid %d) exited after %ld operations.\n",
				childno, childpid, child->syscall.op_nr);
			reap_child(childpid);
			fclose(child->pidstatfile);
			child->pidstatfile = NULL;

			replace_child(childno);
			break;

		} else if (WIFSIGNALED(childstatus)) {
			handle_childsig(childno, childstatus, FALSE);
		} else if (WIFSTOPPED(childstatus)) {
			handle_childsig(childno, childstatus, TRUE);
		} else if (WIFCONTINUED(childstatus)) {
			break;
		}
	}
}

static void handle_children(void)
{
	unsigned int i;
	sigset_t mask;
	sigset_t orig_mask;
	struct timespec timeout = { .tv_sec = 1 };
	int ret;

	if (shm->running_childs == 0)
		return;

	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);

	if (sigprocmask(SIG_BLOCK, &mask, &orig_mask) < 0) {
		perror ("sigprocmask");
		return;
	}

	ret = sigtimedwait(&mask, NULL, &timeout);
	if (ret < 0) {
		// timeout, go do something else.
		if (errno == EAGAIN) {
			return;
		}
	}

	/* If we get this far, we either got EINTR, a SIGCHLD, or some other signal.
	 * in either case, let's see if the children have anything going on
	 */
	for_each_child(i) {
		int childstatus;
		pid_t pid;

		pid = pids[i];

		if (pid == EMPTY_PIDSLOT)
			continue;

		pid = waitpid(pid, &childstatus, WUNTRACED | WCONTINUED | WNOHANG);
		handle_child(i, pid, childstatus);
	}
}

static const char *reasons[NUM_EXIT_REASONS] = {
	"Still running.",
	"No more syscalls enabled.",
	"Completed maximum number of operations.",
	"No file descriptors open.",
	"Lost track of a child.",
	"shm corruption - Found a pid out of range.",
	"ctrl-c",
	"kernel became tainted.",
	"SHM was corrupted!",
	"Child reparenting problem",
	"No files in file list.",
	"Main process disappeared.",
	"UID changed.",
	"Something happened during fd init.",
	"fork() failure",
	"some kind of locking catastrophe",
	"error while opening logfiles",
};

const char * decode_exit(void)
{
	return reasons[shm->exit_reason];
}

static unsigned int stall_count;

static void check_children_progressing(void)
{
	unsigned int i;

	stall_count = 0;

	for_each_child(i) {
		struct childdata *child = shm->children[i];
		struct syscallrecord *rec = &child->syscall;

		if (is_child_making_progress(child) == FALSE)
			stall_count++;

		if (rec->op_nr > hiscore)
			hiscore = rec->op_nr;
	}

	if (stall_count == shm->running_childs)
		stall_genocide();
}

static void print_stats(void)
{
	if (shm->stats.total_syscalls_done > 1) {
		static unsigned long lastcount = 0;

		if (shm->stats.total_syscalls_done - lastcount > 10000) {
			char stalltxt[]=" STALLED:XXXX";

			if (stall_count > 0)
				sprintf(stalltxt, " STALLED:%u", stall_count);
			output(0, "%ld iterations. [F:%ld S:%ld HI:%ld%s]\n",
				shm->stats.total_syscalls_done,
				shm->stats.failures, shm->stats.successes,
				hiscore,
				stall_count ? stalltxt : "");
			lastcount = shm->stats.total_syscalls_done;
		}
	}
}

void main_loop(void)
{
	int ret = 0;

	fork_children();

	while (shm->exit_reason == STILL_RUNNING) {

		handle_children();

		if (shm_is_corrupt() == TRUE)
			goto corrupt;

		while (check_all_locks() == TRUE)
			reap_dead_kids();

		if (syscalls_todo && (shm->stats.total_syscalls_done >= syscalls_todo)) {
			output(0, "Reached limit %d. Telling children to exit.\n", syscalls_todo);
			panic(EXIT_REACHED_COUNT);
		}

		check_children_progressing();

		/* Only check taint if the mask allows it */
		if (kernel_taint_mask != 0) {
			ret = check_tainted();
			if (((ret & kernel_taint_mask) & (~kernel_taint_initial)) != 0)
				tainted_postmortem(ret);
		}

		print_stats();

		/* This should never happen, but just to catch corner cases, like if
		 * fork() failed when we tried to replace a child.
		 */
		if (shm->running_childs < max_children)
			fork_children();
	}

	/* if the pid map is corrupt, we can't trust that we'll
	 * ever successfully finish pidmap_empty, so skip it */
	if ((shm->exit_reason == EXIT_LOST_CHILD) ||
	    (shm->exit_reason == EXIT_SHM_CORRUPTION))
		goto dont_wait;

	handle_children();

	/* Are there still children running ? */
	while (pidmap_empty() == FALSE) {
		static unsigned int last = 0;

		if (last != shm->running_childs) {
			last = shm->running_childs;

			output(0, "exit_reason=%d, but %d children still running.\n",
				shm->exit_reason, shm->running_childs);
		}

		/* Wait for all the children to exit. */
		while (shm->running_childs > 0) {
			handle_children();
			kill_all_kids();
			/* Give children a chance to exit before retrying. */
			sleep(1);
		}
	}

corrupt:
	kill_all_kids();

dont_wait:
	output(0, "Bailing main loop because %s.\n", decode_exit());
}


/*
 * Something potentially bad happened. Alert all processes by setting appropriate shm vars.
 * (not always 'bad', reaching max count for eg is one example).
 */
void panic(int reason)
{
	shm->spawn_no_more = TRUE;
	shm->exit_reason = reason;
}
