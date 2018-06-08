#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "decode.h"
#include "exit.h"
#include "socketinfo.h"
#include "trinity.h"
#include "types.h"
#include "udp.h"
#include "utils.h"

char * decode_syscalls_enabled(char *buf)
{
	struct msg_syscallsenabled *scmsg;
	char *p = zmalloc(1024);
	char *str = p;
	int nr;
	int i;

	scmsg = (struct msg_syscallsenabled *) buf;
	nr = scmsg->nr_enabled;
	if (scmsg->arch_is_biarch == TRUE) {
		p += sprintf(p, "Enabled %d %s bit syscalls : { ", nr, scmsg->is_64 ? "64" : "32");
		for (i = 0 ; i < nr; i++)
			p += sprintf(p, "%d ", scmsg->entries[i]);
		sprintf(p, "}\n");
	} else {
		p += sprintf(p, "Enabled %d syscalls : { ", nr);
		for (i = 0 ; i < nr; i++)
			p += sprintf(p, "%d ", scmsg->entries[i]);
		sprintf(p, "}\n");
	}
	return str;
}

/*
 * TODO: buffer the 'prep' stage, and only output it when we get a 'result' msg with matching
 * child/seqnr.
 * - if we see another prep from the same child, we must have segv'd.
 *   (maybe handle this in decode_child_signalled ?)
 */
char * decode_syscall_prep(char *buf)
{
	struct msg_syscallprep *scmsg;
	struct timespec *ts;
	void *p = zmalloc(1024);

	scmsg = (struct msg_syscallprep *) buf;
	ts = &scmsg->hdr.tp;

	sprintf(p, "%d.%d Child %d [%d] syscall prep [op:%ld] %d%s (0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)\n",
		(int) ts->tv_sec, (int) ts->tv_nsec,
		scmsg->hdr.childno, scmsg->hdr.pid, scmsg->sequence_nr, scmsg->nr,
		scmsg->is32bit ? "[32bit]" : "",
		scmsg->a1, scmsg->a2, scmsg->a3,
		scmsg->a4, scmsg->a5, scmsg->a6);
	return p;
}

char * decode_syscall_result(char *buf)
{
	struct msg_syscallresult *scmsg;
	struct timespec *ts;
	void *p = zmalloc(1024);

	scmsg = (struct msg_syscallresult *) buf;
	ts = &scmsg->hdr.tp;

	sprintf(p, "%d.%d Child %d [%d] syscall [op:%ld]  result %lx %s\n",
		(int) ts->tv_sec, (int) ts->tv_nsec,
		scmsg->hdr.childno, scmsg->hdr.pid, scmsg->sequence_nr,
		scmsg->retval,
		scmsg->retval == -1 ? strerror(scmsg->errno_post) : ""
	      );
	return p;
}
