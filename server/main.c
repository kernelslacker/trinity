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

char * decode_main_started(char *buf)
{
	struct msg_mainstarted *mainmsg;
	void *p = zmalloc(1024);

	mainmsg = (struct msg_mainstarted *) buf;
	sprintf(p, "Main started. pid:%d shm:%p-%p initial seed: %u\n",
		mainmsg->hdr.pid, mainmsg->shm_begin, mainmsg->shm_end,
		mainmsg->initial_seed);
	return p;
}

char * decode_main_exiting(char *buf)
{
	struct msg_mainexiting *mainmsg;
	void *p = zmalloc(1024);

	mainmsg = (struct msg_mainexiting *) buf;
	sprintf(p, "Main exiting. pid:%d Reason: %s\n", mainmsg->hdr.pid, decode_exit(mainmsg->reason));
	return p;
}

char * decode_reseed(char *buf)
{
	struct msg_reseed *rsmsg;
	void *p = zmalloc(1024);

	rsmsg = (struct msg_reseed *) buf;

	sprintf(p, "pid %d Reseed. New seed = %d\n", rsmsg->hdr.pid, rsmsg->new_seed);
	return p;
}
