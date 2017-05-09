#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "decode.h"
#include "exit.h"
#include "handshake.h"
#include "list.h"
#include "logfiles.h"
#include "trinity.h"
#include "types.h"
#include "udp.h"
#include "udp-server.h"
#include "utils.h"

struct packet {
	struct list_head list;
	char * data;
};

struct childdata {
	pid_t childpid;
	struct packet packets;
	pthread_mutex_t packetmutex;
	int logfile;
};

// TODO: dynamically allocate
#define MAX_CHILDREN 1024
struct fuzzsession {
	pid_t mainpid;
	int num_children;
	struct childdata children[MAX_CHILDREN];
	pthread_t childthreads[MAX_CHILDREN];

	pthread_mutex_t packetmutex;
	struct packet mainpackets;
	int logfile;
};

static struct fuzzsession session;


static char * decode(struct packet *pkt)
{
	char *buffer = pkt->data;
	char *str;
	enum logmsgtypes type = buffer[0];

	str = decodefuncs[type].func((char *) pkt->data);

	list_del(&pkt->list);
	free(pkt->data);
	free(pkt);
	return str;
}

static void * decoder_child_func(void *data)
{
	struct childdata *child = (struct childdata *) data;
	struct list_head *node, *tmp;

	while (1) {
		pthread_mutex_lock(&child->packetmutex);
		if (!list_empty(&child->packets.list)) {
			list_for_each_safe(node, tmp, &child->packets.list) {
				if (node != NULL) {
					char *str;
					str = decode((struct packet *)node);
					write(child->logfile, str, strlen(str));
					free(str);
				}
			}
		}
		pthread_mutex_unlock(&child->packetmutex);
		//TODO: if main session exits, we should exit this thread.
	}
	return NULL;
}

static void * decoder_main_func(void *data)
{
	struct fuzzsession *fs = (struct fuzzsession *) data;
	struct list_head *node, *tmp;

	while (1) {
		// iterate through queue for main
		pthread_mutex_lock(&fs->packetmutex);
		if (!list_empty(&fs->mainpackets.list)) {
			list_for_each_safe(node, tmp, &fs->mainpackets.list) {
				if (node != NULL) {
					char *str;
					str = decode((struct packet *)node);
					write(fs->logfile, str, strlen(str));
					free(str);
				}
			}
		}
		pthread_mutex_unlock(&fs->packetmutex);
		//TODO: if main session exits, we should exit this thread.
	}
	return NULL;
}

/* simple 2-way handshake just to agree on protocol. */
static bool __handshake(void)
{
	struct hellostruct *hs = (struct hellostruct *) buf;
	int i;

	/* if we got here, we know we got a correct size message, but the contents
	 * need to match also for it to be a handshake.
	 */
	if (strncmp((char *)hs->hello, "Trinity\0", HELLOLEN) != 0)
		return FALSE;

	printf("Handshake request. (Pid:%d Numchildren:%d) sending reply (%ld bytes)\n",
			hs->mainpid, hs->num_children, strlen(serverreply));

	session.mainpid = hs->mainpid;
	session.num_children = hs->num_children;
	//TODO: mkdir("logs/") ; chdir ("logs/")
	//TODO mkdir session-mainpid
	session.logfile = open_logfile("trinity-main.log");

	INIT_LIST_HEAD(&session.mainpackets.list);
	pthread_mutex_init(&session.packetmutex, NULL);

	for (i = 0; i < hs->num_children; i++) {
		struct childdata *child = &session.children[i];
		int ret;

		child->logfile = open_child_logfile(i);
		INIT_LIST_HEAD(&child->packets.list);
		pthread_mutex_init(&child->packetmutex, NULL);
		ret = pthread_create(&session.childthreads[i], NULL, decoder_child_func, child);
		assert(!ret);
	}

	printf("Received handshake from %s:%d\n", inet_ntoa(udpclient.sin_addr), ntohs(udpclient.sin_port));
	sendudp(serverreply, strlen(serverreply));

	return TRUE;
}

static void handshake(void)
{
	int ret = -1;

retry:	while (ret != sizeof(struct hellostruct))
		ret = readudp();

	if (__handshake() == FALSE) {
		ret = -1;
		goto retry;
	}
}

static bool check_handshake(int ret)
{
	if (ret != sizeof(struct hellostruct))
		return FALSE;

	return __handshake();
}

static void add_to_main_queue(void *data, int len)
{
	struct packet *pkt = malloc(sizeof(struct packet));
	// TODO: find session from pid in pkt. (easy for now, we only support 1 session)
	struct fuzzsession *fs = &session;
	pkt->data = malloc(len);
	if (pkt->data == NULL) {
		free(pkt);
		return;
	}
	memcpy(pkt->data, data, len);

	pthread_mutex_lock(&fs->packetmutex);
	list_add_tail(&pkt->list, &fs->mainpackets.list);
	pthread_mutex_unlock(&fs->packetmutex);
}

static void add_to_child_queue(void *data, int len)
{
	struct packet *pkt = malloc(sizeof(struct packet));
	// TODO: find session from pid in pkt. (easy for now, we only support 1 session)
	// TODO: might be easier if we have mainpid in pkt to find session.
	struct fuzzsession *fs = &session;
	struct trinity_msgchildhdr *childhdr;
	struct childdata *child;

	pkt->data = malloc(len);
	if (pkt->data == NULL) {
		free(pkt);
		return;
	}
	memcpy(pkt->data, data, len);

	// We know this is a child packet, so we can assume a trinity_msgchildhdr
	// FIXME: Not true for objects!
	childhdr = (struct trinity_msgchildhdr *) pkt->data;
	child = &fs->children[childhdr->childno];
	pthread_mutex_lock(&child->packetmutex);
	list_add_tail(&pkt->list, &child->packets.list);
	pthread_mutex_unlock(&child->packetmutex);
}

static void queue_object_msg(struct trinity_msgobjhdr *obj, int len)
{
	if (obj->global == TRUE)
		add_to_main_queue(obj, len);
// TODO: figure out which child created this obj and pass it down
//	else
//		add_to_child_queue(obj, len);
}

static void * queue_packets(__unused__ void *data)
{
	int len;
	enum logmsgtypes type;

	while (1) {
		int ret = readudp();
		if (ret <= 0)
			continue;

		len = ret;

		/* We may see a new handshake appear at any time
		 * if a client dies without sending a 'main has exited' message.
		 * Just re-handshake for now. Later, we'll tear down any context etc.
		 */
		if (check_handshake(len) == TRUE)
			continue;

		type = buf[0];

		if (type >= MAX_LOGMSGTYPE) {
			printf("Unknown msgtype: %d\n", type);
			continue;
		}

		switch (type) {
		case MAIN_STARTED:
		case MAIN_EXITING:
		case SYSCALLS_ENABLED:
		case RESEED:
			add_to_main_queue(buf, len);
			break;

		case OBJ_CREATED_FILE ... OBJ_DESTROYED:
			queue_object_msg((struct trinity_msgobjhdr *) buf, len);
			break;

		case CHILD_SPAWNED:
		case CHILD_EXITED:
		case CHILD_SIGNALLED:
		case SYSCALL_PREP:
		case SYSCALL_RESULT:
			add_to_child_queue(buf, len);
			break;

		case MAX_LOGMSGTYPE:
			break;
		};
	}
	return NULL;
}

int main(__unused__ int argc, __unused__ char* argv[])
{
	pthread_t udpthread, decode_main_thr;
	struct fuzzsession *fs = &session;	// TODO; find session from packets
	int ret;

	if (setup_socket() == FALSE)
		goto out;

	handshake();		// TODO: eventually fold into queue_packets

	ret = pthread_create(&udpthread, NULL, queue_packets, NULL);	// TODO: pass session down. one thread per session.
	assert(!ret);

	while (1) {
		ret = pthread_create(&decode_main_thr, NULL, decoder_main_func, fs);
		assert(!ret);
		pthread_join(decode_main_thr, NULL);
	}


	pthread_exit(NULL);

	close(socketfd);
out:
	exit(EXIT_FAILURE);
}
