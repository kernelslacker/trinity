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
#include "trinity.h"
#include "types.h"
#include "udp.h"
#include "utils.h"

static void decode_main_started(void)
{
	struct msg_mainstarted *mainmsg;

	mainmsg = (struct msg_mainstarted *) &buf;
	printf("Main started. pid:%d number of children: %d. shm:%p-%p\n",
		mainmsg->pid, mainmsg->num_children, mainmsg->shm_begin, mainmsg->shm_end);
}

static void decode_main_exiting(void)
{
	struct msg_mainexiting *mainmsg;

	mainmsg = (struct msg_mainexiting *) &buf;
	printf("Main exiting. pid:%d Reason: %s\n", mainmsg->pid, decode_exit(mainmsg->reason));
}

static void decode_child_spawned(void)
{
	struct msg_childspawned *childmsg;

	childmsg = (struct msg_childspawned *) &buf;
	printf("Child spawned. id:%d pid:%d\n", childmsg->childno, childmsg->pid);
}

static void decode_child_exited(void)
{
	struct msg_childexited *childmsg;

	childmsg = (struct msg_childexited *) &buf;
	printf("Child exited. id:%d pid:%d\n", childmsg->childno, childmsg->pid);
}

static void decode_child_signalled(void)
{
	struct msg_childsignalled *childmsg;

	childmsg = (struct msg_childsignalled *) &buf;
	printf("Child signal. id:%d pid:%d signal: %s\n",
		childmsg->childno, childmsg->pid, strsignal(childmsg->sig));
}

static void decode_obj_created_file(void)
{
	struct msg_objcreatedfile *objmsg;

	objmsg = (struct msg_objcreatedfile *) &buf;

	if (objmsg->fopened) {
		printf("%s object created at %p by pid %d: fd %d = fopen(\"%s\") ; fcntl(fd, 0x%x)\n",
			objmsg->global ? "local" : "global",
			objmsg->address, objmsg->pid,
			objmsg->fd, objmsg->filename,
			objmsg->fcntl_flags);
	} else {
		printf("%s object created at %p by pid %d: fd %d = open(\"%s\", 0x%x)\n",
			objmsg->global ? "local" : "global",
			objmsg->address, objmsg->pid,
			objmsg->fd, objmsg->filename, objmsg->flags);
	}
}

const struct msgfunc decodefuncs[MAX_LOGMSGTYPE] = {
	[MAIN_STARTED] = { decode_main_started },
	[MAIN_EXITING] = { decode_main_exiting },
	[CHILD_SPAWNED] = { decode_child_spawned },
	[CHILD_EXITED] = { decode_child_exited },
	[CHILD_SIGNALLED] = { decode_child_signalled },
	[OBJ_CREATED_FILE] = { decode_obj_created_file },
};
