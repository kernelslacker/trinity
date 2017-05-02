#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "decode.h"
#include "exit.h"
#include "socketinfo.h"
#include "trinity.h"
#include "types.h"
#include "udp.h"
#include "utils.h"

void decode_syscalls_enabled(char *buf)
{
	struct msg_syscallsenabled *scmsg;
	int nr;
	int i;

	scmsg = (struct msg_syscallsenabled *) buf;
	nr = scmsg->nr_enabled;
	if (scmsg->arch_is_biarch == TRUE) {
		printf("Enabled %d %s bit syscalls : { ", nr, scmsg->is_64 ? "64" : "32");
		for (i = 0 ; i < nr; i++)
			printf("%d ", scmsg->entries[i]);
		printf("}\n");
	} else {
		printf("Enabled %d syscalls : { ", nr);
		for (i = 0 ; i < nr; i++)
			printf("%d ", scmsg->entries[i]);
		printf("}\n");
	}
}

/*
 * TODO: buffer the 'prep' stage, and only output it when we get a 'result' msg with matching
 * child/seqnr.
 * - if we see another prep from the same child, we must have segv'd.
 *   (maybe handle this in decode_child_signalled ?)
 */
void decode_syscall_prep(char *buf)
{
	struct msg_syscallprep *scmsg;

	scmsg = (struct msg_syscallprep *) buf;

	printf("Child %d [%d] syscall prep [op:%ld] %d%s (0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)\n",
		scmsg->hdr.childno, scmsg->hdr.pid, scmsg->sequence_nr, scmsg->nr,
		scmsg->is32bit ? "[32bit]" : "",
		scmsg->a1, scmsg->a2, scmsg->a3,
		scmsg->a4, scmsg->a5, scmsg->a6);
}

void decode_syscall_result(char *buf)
{
	struct msg_syscallresult *scmsg;

	scmsg = (struct msg_syscallresult *) buf;

	printf("Child %d [%d] syscall [op:%ld]  result %lx %s\n",
		scmsg->hdr.childno, scmsg->hdr.pid, scmsg->sequence_nr,
		scmsg->retval,
		scmsg->retval == -1 ? strerror(scmsg->errno_post) : ""
	      );
}
