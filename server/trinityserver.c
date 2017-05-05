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
#include "handshake.h"
#include "list.h"
#include "trinity.h"
#include "types.h"
#include "udp.h"
#include "utils.h"

struct packet {
	struct list_head list;
	char * data;
};

struct childdata {
	pid_t childpid;
	struct packet packets;
};

// TODO: dynamically allocate
#define MAX_CHILDREN 1024
struct fuzzsession {
	pid_t mainpid;
	int num_children;
	struct childdata children[MAX_CHILDREN];
	struct packet mainpackets;
};

static struct fuzzsession session;


static void decode(struct packet *pkt)
{
	char *buffer = pkt->data;
	enum logmsgtypes type = buffer[0];

	decodefuncs[type].func((char *) pkt->data);
	list_del(&pkt->list);
	free(pkt->data);
	free(pkt);
}

static void decoder_func(struct fuzzsession *fs)
{
	struct list_head *node, *tmp;
	int i;

	// iterate through queue for main
	if (!list_empty(&fs->mainpackets.list)) {
		list_for_each_safe(node, tmp, &fs->mainpackets.list) {
			if (node != NULL)
				decode((struct packet *)node);
		}
	}

	// iterate through child queues
	for (i = 0; i < fs->num_children; i++) {
		if (!list_empty(&fs->children[i].packets.list)) {
			list_for_each_safe(node, tmp, &fs->children[i].packets.list) {
				if (node != NULL)
					decode((struct packet *)node);
			}
		}
	}
}


// TODO: ipv6

struct sockaddr_in udpclient;

int socketfd;

#define MAXBUF 10240
static char buf[MAXBUF];

void sendudp(char *buffer, size_t len)
{
	int ret;

	ret = sendto(socketfd, buffer, len, 0, (struct sockaddr *) &udpclient, sizeof(udpclient));
	if (ret == -1) {
		fprintf(stderr, "sendto: %s\n", strerror(errno));
	}
}

static size_t readudp(void)
{
	int ret;
	socklen_t addrlen = 0;

	memset(buf, 0, MAXBUF);

	addrlen = sizeof(udpclient);
	ret = recvfrom(socketfd, buf, MAXBUF, 0, (struct sockaddr *) &udpclient, &addrlen);
	if (ret == -1)
		fprintf(stderr, "recvfrom: %s\n", strerror(errno));

	return ret;
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

	sendudp(serverreply, strlen(serverreply));
	INIT_LIST_HEAD(&session.mainpackets.list);
	for (i = 0; i < hs->num_children; i++)
		INIT_LIST_HEAD(&session.children[i].packets.list);

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

static bool setup_socket(void)
{
	struct sockaddr_in udpserver;

	socketfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (socketfd == -1) {
		fprintf(stderr, "Could not create a socket\n");
		return FALSE;
	}

	udpserver.sin_family = AF_INET;
	udpserver.sin_addr.s_addr = htonl(INADDR_ANY);
	udpserver.sin_port = htons(TRINITY_LOG_PORT);

	if (bind(socketfd, (struct sockaddr *) &udpserver, sizeof(udpserver)) != 0) {
		fprintf(stderr, "Could not bind to address!\n");
		close(socketfd);
		return FALSE;
	}
	return TRUE;
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

	list_add_tail(&pkt->list, &fs->mainpackets.list);
}

static void add_to_child_queue(void *data, int len)
{
	struct packet *pkt = malloc(sizeof(struct packet));
	// TODO: find session from pid in pkt. (easy for now, we only support 1 session)
	// TODO: might be easier if we have mainpid in pkt to find session.
	struct fuzzsession *fs = &session;
	struct trinity_msgchildhdr *childhdr;

	pkt->data = malloc(len);
	if (pkt->data == NULL) {
		free(pkt);
		return;
	}
	memcpy(pkt->data, data, len);

	// We know this is a child packet, so we can assume a trinity_msgchildhdr
	// FIXME: Not true for objects!
	childhdr = (struct trinity_msgchildhdr *) pkt->data;
	list_add_tail(&pkt->list, &fs->children[childhdr->childno].packets.list);
}

static void queue_object_msg(struct trinity_msgobjhdr *obj, int len)
{
	if (obj->global == TRUE)
		add_to_main_queue(obj, len);
// TODO: figure out which child created this obj and pass it down
//	else
//		add_to_child_queue(obj, len);
}

static void queue_packets(void)
{
	int ret;
	int len;
	enum logmsgtypes type;

	ret = readudp();
	if (ret <= 0)
		return;

	len = ret;

	/* We may see a new handshake appear at any time
	 * if a client dies without sending a 'main has exited' message.
	 * Just re-handshake for now. Later, we'll tear down any context etc.
	 */
	if (check_handshake(len) == TRUE)
		return;

	type = buf[0];

	if (type >= MAX_LOGMSGTYPE) {
		printf("Unknown msgtype: %d\n", type);
		return;
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

int main(__unused__ int argc, __unused__ char* argv[])
{
	if (setup_socket() == FALSE)
		goto out;

	handshake();

	while (1) {
		struct fuzzsession *fs = &session;	// TODO; find session from packets
		queue_packets();
		decoder_func(fs);
	}

	close(socketfd);
out:
	exit(EXIT_FAILURE);
}
