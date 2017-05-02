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

void decode_child_spawned(char *buf)
{
	struct msg_childspawned *childmsg;

	childmsg = (struct msg_childspawned *) buf;
	printf("Child spawned. id:%d pid:%d\n", childmsg->hdr.childno, childmsg->hdr.pid);
}

void decode_child_exited(char *buf)
{
	struct msg_childexited *childmsg;

	childmsg = (struct msg_childexited *) buf;
	printf("Child exited. id:%d pid:%d\n", childmsg->hdr.childno, childmsg->hdr.pid);
}

void decode_child_signalled(char *buf)
{
	struct msg_childsignalled *childmsg;

	childmsg = (struct msg_childsignalled *) buf;
	printf("Child signal. id:%d pid:%d signal: %s\n",
		childmsg->hdr.childno, childmsg->hdr.pid, strsignal(childmsg->sig));
}
