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

void decode_main_started(char *buf)
{
	struct msg_mainstarted *mainmsg;

	mainmsg = (struct msg_mainstarted *) buf;
	printf("Main started. pid:%d number of children: %d. shm:%p-%p initial seed: %u\n",
		mainmsg->hdr.pid, mainmsg->num_children, mainmsg->shm_begin, mainmsg->shm_end,
		mainmsg->initial_seed);
}

void decode_main_exiting(char *buf)
{
	struct msg_mainexiting *mainmsg;

	mainmsg = (struct msg_mainexiting *) buf;
	printf("Main exiting. pid:%d Reason: %s\n", mainmsg->hdr.pid, decode_exit(mainmsg->reason));
}

void decode_reseed(char *buf)
{
	struct msg_reseed *rsmsg;

	rsmsg = (struct msg_reseed *) buf;

	printf("pid %d Reseed. New seed = %d\n", rsmsg->hdr.pid, rsmsg->new_seed);
	sleep(5);
}
