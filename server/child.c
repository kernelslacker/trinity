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
#include "session.h"
#include "socketinfo.h"
#include "trinity.h"
#include "types.h"
#include "udp.h"
#include "utils.h"

char * decode_child_spawned(char *buf)
{
	struct msg_childspawned *childmsg;
	struct timespec *ts;
	struct childdata *child;
	void *p = zmalloc(1024);

	childmsg = (struct msg_childspawned *) buf;
	ts = &childmsg->hdr.tp;
	sprintf(p, "%d.%d Child spawned. id:%d pid:%d\n",
		(int) ts->tv_sec, (int) ts->tv_nsec,
		childmsg->hdr.childno, childmsg->hdr.pid);

	child = &session.children[childmsg->hdr.childno];
	child->childpid = childmsg->hdr.pid;
	return p;
}

char * decode_child_exited(char *buf)
{
	struct msg_childexited *childmsg;
	struct timespec *ts;
	void *p = zmalloc(1024);

	childmsg = (struct msg_childexited *) buf;
	ts = &childmsg->hdr.tp;
	sprintf(p, "%d.%d Child exited. id:%d pid:%d lastop:%lu\n",
		(int) ts->tv_sec, (int) ts->tv_nsec,
		childmsg->hdr.childno, childmsg->hdr.pid, childmsg->op_nr);
	return p;
}

char * decode_child_signalled(char *buf)
{
	struct msg_childsignalled *childmsg;
	struct timespec *ts;
	void *p = zmalloc(1024);

	childmsg = (struct msg_childsignalled *) buf;
	ts = &childmsg->hdr.tp;
	sprintf(p, "%d.%d Child signal. id:%d pid:%d signal: %s. After op:%lu\n",
		(int) ts->tv_sec, (int) ts->tv_nsec,
		childmsg->hdr.childno, childmsg->hdr.pid, strsignal(childmsg->sig),
		childmsg->op_nr);
	return p;
}
