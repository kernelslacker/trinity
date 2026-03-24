#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "child.h"
#include "debug.h"
#include "kcov.h"
#include "params.h"
#include "pids.h"
#include "post-mortem.h"
#include "random.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "utils.h"

static void handle_child(int childno, pid_t childpid, int childstatus);
static void replace_child(int childno);

/* Parent-local array of /proc/<pid>/stat file handles, indexed by childno.
 * Kept out of shared memory so children's stray writes can't corrupt them. */
static FILE **pidstatfiles;

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

	unsigned long current_previous_op_count = shm->stats.previous_op_count;
	unsigned long current_op_count = shm->stats.op_count;

	//if (shm->stats.op_count < shm->stats.previous_op_count) {
	if (current_op_count < current_previous_op_count) {
		output(0, "Execcount went backwards! (old:%lu new:%lu):\n",
			shm->stats.previous_op_count, shm->stats.op_count);
		panic(EXIT_SHM_CORRUPTION);
		return true;
	}
	shm->stats.previous_op_count = shm->stats.op_count;

	for_each_child(i) {
		struct childdata *child;
		pid_t pid;

		if (shm->children == NULL)
			return true;

		child = shm->children[i];
		pid = pids[i];
		if (pid == EMPTY_PIDSLOT)
			continue;

		if (pid_is_valid(pid) == false) {
			static bool once = false;

			if (once != false)
				return true;

			output(0, "Sanity check failed! Found pid %d at pidslot %u!\n", pid, i);

			dump_childnos();

			if (shm->exit_reason == STILL_RUNNING)
				panic(EXIT_PID_OUT_OF_RANGE);
			dump_childdata(child);
			once = true;
			return true;
		}
	}

	return false;
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
void reap_child(struct childdata *child, int childno)
{
	/* Don't reap a child again */
	if( pids[childno] == EMPTY_PIDSLOT )
		return;
	child->tp = (struct timespec){ .tv_sec = 0, .tv_nsec = 0 };
	unlock(&child->syscall.lock);
	__atomic_sub_fetch(&shm->running_childs, 1, __ATOMIC_RELAXED);
	pids[childno] = EMPTY_PIDSLOT;
}

/* Make sure there's no dead kids lying around.
 * We need to do this in case the oom killer has been killing them,
 * otherwise we end up stuck with no child processes.
 */
static void reap_dead_kids(void)
{
	unsigned int i;
	unsigned int reaped = 0;

	if (shm->children == NULL)
		return;

	for_each_child(i) {
		pid_t pid;
		int childstatus;

		pid = pids[i];
		if (pid == EMPTY_PIDSLOT)
			continue;

		/* if we find corruption, just skip over it. */
		if (pid_is_valid(pid) == false)
			continue;

		if (pid_alive(pid) == false) {
			/* If it disappeared, reap it. */
			if (errno == ESRCH) {
				output(0, "pid %u has disappeared. Reaping.\n", pid);
				reap_child(shm->children[i], i);
				reaped++;
			} else {
				output(0, "problem checking on pid %u (%d:%s)\n", pid, errno, strerror(errno));
			}
			continue;
		}

		pid = waitpid(pid, &childstatus, WUNTRACED | WCONTINUED | WNOHANG);
		handle_child(i, pid, childstatus);

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

	shm->spawn_no_more = true;

	reap_dead_kids();

	if (shm->running_childs == 0)
		return;

	/* Ok, some kids are still alive. 'help' them along with a SIGKILL */
	for_each_child(i) {
		pid_t pid;

		pid = pids[i];
		if (pid == EMPTY_PIDSLOT)
			continue;

		/* if we find corruption, just skip over it. */
		if (pid_is_valid(pid) == false)
			continue;

		if (pid_alive(pid) == true) {
			kill_pid(pid);
			children_seen++;
		} else {
			/* check we don't have anything stale in the pidlist */
			if (errno == ESRCH)
				reap_child(shm->children[i], i);
		}
	}

	if (children_seen == 0)
		__atomic_store_n(&shm->running_childs, 0, __ATOMIC_RELAXED);

	/* Check that no dead children hold locks. */
	while (check_all_locks() == true)
		reap_dead_kids();
}


/* if the first arg was an fd, find out which one it was.
 * Call with syscallrecord lock held. */
unsigned int check_if_fd(struct syscallrecord *rec)
{
	struct syscallentry *entry;
	unsigned int fd;

	entry = get_syscall_entry(rec->nr, rec->do32bit);
	if (entry == NULL)
		return false;

	if (!is_typed_fdarg(entry->arg1type)) {
		switch (entry->arg1type) {
		case ARG_FD:
		case ARG_SOCKETINFO:
			break;
		default:
			return false;
		}
	}

	/* in the SOCKETINFO case, post syscall, a1 is actually the fd,
	 * not the socketinfo.  In ARG_FD a1=fd.
	 */
	fd = rec->a1;

	/* if it's out of range, it's not going to be valid. */
	if (fd > 1024)
		return false;

	return true;
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

static char get_pid_state(int childno)
{
	size_t n = 0;
	char *line = NULL;
	pid_t pid;
	char state = '?';
	char procname[100];
	FILE *fp;

	if (getpid() != mainpid)
		BUG("get_pid_state can only be called from main!\n");

	fp = pidstatfiles[childno];
	if (fp == NULL)
		return '?';

	fseek(fp, 0L, SEEK_SET);
	fflush(fp);

	if (getline(&line, &n, fp) != -1)
		sscanf(line, "%d %99s %c", &pid, procname, &state);

	free(line);
	return state;
}

static void dump_pid_stack(int pid)
{
	FILE *fp;
	char filename[80];

	sprintf(filename, "/proc/%d/stack", pid);

	fp = fopen(filename, "r");
	if (fp == NULL) {
		output(0, "Couldn't dump stack info for pid %d: %s\n", pid, strerror(errno));
		return;
	}

	while (!(feof(fp))) {
		size_t n = 0;
		char *line = NULL;
		if (getline(&line, &n, fp) != -1) {
			output(0, "pid %d stack: %s", pid, line);
		} else {
			if (errno != EAGAIN)
				output(0, "Error reading /proc/%d/stack :%s\n", pid, strerror(errno));
			free(line);
			fclose(fp);
			return;
		}
		free(line);
	}
	output(0, "------------------------------------------------\n");

	fclose(fp);
}

static void stuck_syscall_info(struct childdata *child, int childno)
{
	struct syscallrecord *rec;
	unsigned int callno;
	char fdstr[20];
	pid_t pid;
	bool do32;
	char state;

	pid = pids[childno];

	if (shm->debug == false)
		return;

	rec = &child->syscall;

	if (trylock(&rec->lock) == false)
		return;

	do32 = rec->do32bit;
	callno = rec->nr;

	memset(fdstr, 0, sizeof(fdstr));

	state = rec->state;

	/* we can only be 'stuck' if we're still doing the syscall. */
	if (state == BEFORE) {
		if (check_if_fd(rec) == true) {
			sprintf(fdstr, "(fd = %u)", (unsigned int) rec->a1);
			child->fd_lifetime = 0;
			//close(rec->a1);
			//TODO: Remove the fd from the object list.
		}
	}

	unlock(&rec->lock);

	output(0, "child %d (pid %u. state:%d) Stuck in syscall %d:%s%s%s.\n",
		childno, pid, state, callno,
		print_syscall_name(callno, do32),
		do32 ? " (32bit)" : "",
		fdstr);
	if (state >= BEFORE)
		dump_pid_stack(pid);
}

/*
 * Check that a child is making forward progress by comparing the timestamps it
 * recorded before making its last syscall.
 * If no progress is being made, send SIGKILLs to it.
 */
static bool is_child_making_progress(struct childdata *child, int childno)
{
	struct syscallrecord *rec;
	struct timespec tp;
	time_t diff, old, now;
	pid_t pid;
	char state;

	pid = pids[childno];

	if (pid == EMPTY_PIDSLOT)
		return true;
	// bail if we've not done a syscall yet, we probably just haven't
	// been scheduled due to other pids hogging the cpu
	rec = &child->syscall;
	if (trylock(&rec->lock) == false)
		return true;

	if (rec->state < BEFORE) {
		unlock(&rec->lock);
		return true;
	}
	unlock(&rec->lock);

	old = child->tp.tv_sec;

	/* haven't done anything yet. */
	if (old == 0)
		return true;

	clock_gettime(CLOCK_MONOTONIC, &tp);
	now = tp.tv_sec;

	if (old > now)
		diff = old - now;
	else
		diff = now - old;

	/* hopefully the common case. */
	if (diff < 30)
		return true;

	/* if we're blocked in uninteruptible sleep, SIGKILL won't help.
	 * Still increment kill_count so we eventually reap the slot. */
	state = get_pid_state(childno);
	if (state == 'D') {
		child->kill_count++;
		return false;
	}

	/* After 30 seconds of no progress, send a kill signal. */
	if (diff == 30) {
		stuck_syscall_info(child, childno);
		debugf("child %d (pid %u) hasn't made progress in 30 seconds! Sending SIGKILL\n",
				childno, pid);
		child->kill_count++;
		kill_pid(pid);
	}

	/* if we're still around after 40s, repeatedly send SIGKILLs every second. */
	if (diff < 40)
		return false;

	/* After too many kill attempts, the child is truly stuck (D state,
	 * frozen cgroup, etc). Forcibly reap the slot so we can spawn a
	 * replacement. The original process becomes a zombie but at least
	 * we don't permanently lose a child slot. */
	if (child->kill_count >= 10) {
		output(0, "child %d (pid %u) unkillable after %u attempts, "
			"forcibly reaping slot.\n",
			childno, pid, child->kill_count);
		if (pidstatfiles[childno])
			fclose(pidstatfiles[childno]);
		pidstatfiles[childno] = NULL;
		reap_child(child, childno);
		replace_child(childno);
		return true;
	}

	debugf("sending another SIGKILL to child %u (pid:%u). [kill count:%u] [diff:%lu]\n",
		childno, pid, child->kill_count, diff);
	child->kill_count++;
	kill_pid(pid);

	return false;
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
			if (pid_alive(pid) == true) {
				kill_pid(pid);
				killed++;
			}
		}
		if (killed == (max_children / 4))
			break;
	}
}

static bool spawn_child(int childno)
{
	struct childdata *child;
	int pid = 0;

	if (shm->children == NULL)
		return false;

	child = shm->children[childno];

	/* a new child means a new seed, or the new child
	 * will do the same syscalls as the one in the child it's replacing.
	 * (special case startup, or we reseed unnecessarily)
	 */
	if (shm->ready == true)
		reseed();

	/* Wipe out any state left from a previous child running in this slot. */
	clean_childdata(child);

	fflush(stdout);
	pid = fork();

	if (pid == 0) {
		child_process(child, childno);
		_exit(EXIT_SUCCESS);
	} else {
		if (pid == -1) {
			debugf("Couldn't fork a new child in pidslot %d. errno:%s\n",
					childno, strerror(errno));
			return false;
		}
	}

	/* Child won't get out of init_child until we write the pid */
	pids[childno] = pid;
	int nr_fds = get_num_fds();
	if ((max_files_rlimit.rlim_cur - nr_fds) < 3)
	{
		// pidstatfiles[childno] may be NULL below if fd limit is reached.
		outputerr("current number of fd: %d, please consider ulimit -n xxx to increase fd limition\n", nr_fds);
		panic(EXIT_NO_FDS);
	}
	pidstatfiles[childno] = open_child_pidstat(pid);
	__atomic_add_fetch(&shm->running_childs, 1, __ATOMIC_RELAXED);

	debugf("Created child %d (pid:%d) [total:%u/%u]\n",
		childno, pid, shm->running_childs, max_children);
	return true;
}

static void replace_child(int childno)
{
	if (shm->exit_reason != STILL_RUNNING)
		return;

	while (spawn_child(childno) == false);
}

/* Generate children*/
static void fork_children(void)
{
	while (shm->running_childs < max_children) {
		int childno;

		if (shm->spawn_no_more == true)
			return;

		/* Find a space for it in the pid map */
		childno = find_childno(EMPTY_PIDSLOT);
		if (childno == CHILD_NOT_FOUND) {
			outputerr("## Pid map was full!\n");
			dump_childnos();
			exit(EXIT_FAILURE);
		}

		if (spawn_child(childno) == false) {
			outputerr("Couldn't fork initial children!\n");
			panic(EXIT_FORK_FAILURE);
			exit(EXIT_FAILURE);
		}

		if (shm->exit_reason != STILL_RUNNING)
			return;
	}
	shm->ready = true;
}

static void handle_childsig(int childno, int childstatus, bool stop)
{
	int __sig;
	pid_t pid = pids[childno];

	if (shm->children == NULL)
		return;

	if (stop == true)
		__sig = WSTOPSIG(childstatus);
	else
		__sig = WTERMSIG(childstatus);

	switch (__sig) {
	case SIGSTOP:
		if (stop != true)
			return;
		debugf("Sending PTRACE_DETACH (and then KILL)\n");
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		kill_pid(pid);
		//FIXME: Won't we create a zombie here?
		reap_child(shm->children[childno], childno);
		replace_child(childno);
		return;

	case SIGALRM:
		debugf("got a alarm signal from child %d (pid %d)\n", childno, pid);
		break;
	case SIGFPE:
	case SIGSEGV:
	case SIGKILL:
	case SIGPIPE:
	case SIGABRT:
	case SIGBUS:
	case SIGILL:
		if (stop == true)
			debugf("Child %d (pid %d) was stopped by %s\n",
					childno, pid, strsignal(WSTOPSIG(childstatus)));
		else {
			debugf("got a signal from child %d (pid %d) (%s)\n",
					childno, pid, strsignal(WTERMSIG(childstatus)));
		}
		reap_child(shm->children[childno], childno);
		if (pidstatfiles[childno])
			fclose(pidstatfiles[childno]);
		pidstatfiles[childno] = NULL;

		replace_child(childno);
		return;

	default:
		if (__sig >= SIGRTMIN) {
			debugf("Child %d got RT signal (%d). Ignoring.\n", pid, __sig);
			return;
		}

		if (stop == true)
			debugf("Child %d was stopped by unhandled signal (%s).\n", pid, strsignal(WSTOPSIG(childstatus)));
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
		break;

	default:
		if (shm->children == NULL)
			break;

		if (WIFEXITED(childstatus)) {
			struct childdata *child = shm->children[childno];

			debugf("Child %d (pid:%u) exited after %ld operations.\n",
				childno, childpid, child->op_nr);
			reap_child(shm->children[childno], childno);
			if (pidstatfiles[childno] != NULL)
				fclose(pidstatfiles[childno]);
			pidstatfiles[childno] = NULL;

			replace_child(childno);
			break;

		} else if (WIFSIGNALED(childstatus)) {
			handle_childsig(childno, childstatus, false);
		} else if (WIFSTOPPED(childstatus)) {
			handle_childsig(childno, childstatus, true);
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

	if (shm->children == NULL)
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

static unsigned int stall_count;

static void check_children_progressing(void)
{
	unsigned int i;

	stall_count = 0;

	if (shm->children == NULL)
		return;

	for_each_child(i) {
		struct childdata *child = shm->children[i];

		if (is_child_making_progress(child, i) == false)
			stall_count++;

		if (child->op_nr > hiscore)
			hiscore = child->op_nr;
	}

	if (stall_count == shm->running_childs)
		stall_genocide();
}

static void print_stats(void)
{
	if (shm->stats.op_count > 1) {
		static unsigned long lastcount = 0;
		static struct timespec last_tp = { 0 };

		if (shm->stats.op_count - lastcount > 10000) {
			struct timespec now;
			unsigned long rate = 0;
			char stalltxt[]=" STALLED:XXXX";

			clock_gettime(CLOCK_MONOTONIC, &now);
			if (last_tp.tv_sec > 0) {
				double elapsed = (now.tv_sec - last_tp.tv_sec) +
					(now.tv_nsec - last_tp.tv_nsec) / 1e9;
				if (elapsed > 0.01)
					rate = (unsigned long)((shm->stats.op_count - lastcount) / elapsed);
			}
			last_tp = now;

			if (stall_count > 0 && stall_count < 10000)
				sprintf(stalltxt, " STALLED:%u", stall_count);
			output(0, "%ld iterations. [F:%ld S:%ld HI:%ld%s] %lu/sec\n",
				shm->stats.op_count,
				shm->stats.failures, shm->stats.successes,
				hiscore,
				stall_count ? stalltxt : "",
				rate);
			if (kcov_shm != NULL) {
				static unsigned long last_edges = 0;
				static unsigned int plateau_intervals = 0;
				unsigned long edges = kcov_shm->edges_found;

				if (edges == last_edges && last_edges > 0) {
					plateau_intervals++;
					if (plateau_intervals == 10)
						output(0, "  KCOV: coverage plateau at %lu edges\n", edges);
					else if (plateau_intervals > 10 && (plateau_intervals % 50) == 0)
						output(0, "  KCOV: still at plateau (%lu edges, %u intervals)\n",
							edges, plateau_intervals);
					else
						output(0, "  KCOV: %lu edges\n", edges);
				} else {
					if (plateau_intervals >= 10)
						output(0, "  KCOV: %lu edges (plateau broken!)\n", edges);
					else
						output(0, "  KCOV: %lu edges\n", edges);
					plateau_intervals = 0;
				}
				last_edges = edges;
			}
			lastcount = shm->stats.op_count;
		}
	}
}

static bool handled_taint = false;

static void taint_check(void)
{
	if (handled_taint == true)
		return;

	if (is_tainted() == true) {
		tainted_postmortem();
		handled_taint = true;
	}
}

void main_loop(void)
{
	pidstatfiles = zmalloc(max_children * sizeof(FILE *));

	fork_children();

	while (shm->exit_reason == STILL_RUNNING) {

		handle_children();

		taint_check();

		if (shm_is_corrupt() == true)
			goto corrupt;

		while (check_all_locks() == true) {
			reap_dead_kids();
			if (shm->exit_reason == EXIT_REACHED_COUNT)
				kill_all_kids();
		}

		if (syscalls_todo && (shm->stats.op_count >= syscalls_todo)) {
			output(0, "Reached limit %lu. Telling children to exit.\n", syscalls_todo);
			panic(EXIT_REACHED_COUNT);
		}

		check_children_progressing();

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
	while (pidmap_empty() == false) {
		static unsigned int last = 0;
		static unsigned int shutdown_attempts = 0;

		if (++shutdown_attempts > 10) {
			output(0, "Gave up waiting for children after %u attempts.\n",
				shutdown_attempts);
			break;
		}

		if (last != shm->running_childs) {
			last = shm->running_childs;

			output(0, "exit_reason=%d, but %u children still running.\n",
				shm->exit_reason, shm->running_childs);
		}

		/* Wait for all the children to exit. */
		while (shm->running_childs > 0) {
			taint_check();

			handle_children();
			kill_all_kids();
			/* Give children a chance to exit before retrying. */
			sleep(1);
		}
		reap_dead_kids();
	}

corrupt:
	kill_all_kids();

dont_wait:
	output(0, "Bailing main loop because %s.\n", decode_exit(shm->exit_reason));
}


/*
 * Something potentially bad happened. Alert all processes by setting appropriate shm vars.
 * (not always 'bad', reaching max count for eg is one example).
 */
void panic(int reason)
{
	shm->spawn_no_more = true;
	shm->exit_reason = reason;
}
