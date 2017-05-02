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

void decode_obj_created_file(char *buf)
{
	struct msg_objcreatedfile *objmsg;

	objmsg = (struct msg_objcreatedfile *) buf;

	if (objmsg->fopened) {
		printf("%s file object created at %p by pid %d: fd %d = fopen(\"%s\") ; fcntl(fd, 0x%x)\n",
			objmsg->hdr.global ? "global" : "local",
			objmsg->hdr.address, objmsg->hdr.pid,
			objmsg->fd, objmsg->filename,
			objmsg->fcntl_flags);
	} else {
		printf("%s file object created at %p by pid %d: fd %d = open(\"%s\", 0x%x)\n",
			objmsg->hdr.global ? "global" : "local",
			objmsg->hdr.address, objmsg->hdr.pid,
			objmsg->fd, objmsg->filename, objmsg->flags);
	}
}

void decode_obj_created_map(char *buf)
{
	struct msg_objcreatedmap *objmsg;
	const char *maptypes[] = {
		"initial anon mmap",
		"child created anon mmap",
		"mmap'd file",
	};
	objmsg = (struct msg_objcreatedmap *) buf;

	printf("%s map object created at %p by pid %d: start:%p size:%ld name:%s prot:%x type:%s\n",
		objmsg->hdr.global ? "global" : "local",
		objmsg->hdr.address, objmsg->hdr.pid,
		objmsg->start, objmsg->size, objmsg->name, objmsg->prot, maptypes[objmsg->type - 1]);
}

void decode_obj_created_pipe(char *buf)
{
	struct msg_objcreatedpipe *objmsg;
	objmsg = (struct msg_objcreatedpipe *) buf;

	printf("%s pipe object created at %p by pid %d: fd:%d flags:%x [%s]\n",
		objmsg->hdr.global ? "global" : "local",
		objmsg->hdr.address, objmsg->hdr.pid,
		objmsg->fd, objmsg->flags,
		objmsg->reader ? "reader" : "writer");
}

void decode_obj_created_perf(char *buf)
{
	struct msg_objcreatedperf *objmsg;
	char *p;
	int i;

	objmsg = (struct msg_objcreatedperf *) buf;
	printf("%s perf object created at %p by pid %d: fd:%d pid:%d cpu:%d group_fd:%d flags:%lx eventattr len:%d\n",
		objmsg->hdr.global ? "global" : "local",
		objmsg->hdr.address, objmsg->hdr.pid,
		objmsg->fd, objmsg->pid, objmsg->cpu, objmsg->group_fd, objmsg->flags,
		objmsg->eventattrsize);

	printf("perf_event_attr: ");
	p = (char *) &objmsg->eventattr;
	for (i = 0; i < objmsg->eventattrsize; i++) {
		printf("%02x ", (unsigned char) p[i]);
	}
	printf("\n");
}

void decode_obj_created_epoll(char *buf)
{
	struct msg_objcreatedepoll *objmsg;
	objmsg = (struct msg_objcreatedepoll *) buf;

	printf("%s epoll object created at %p by pid %d: fd:%d create1: %s flags:%x\n",
		objmsg->hdr.global ? "global" : "local",
		objmsg->hdr.address, objmsg->hdr.pid, objmsg->fd,
		objmsg->create1 ? "false" : "true",
		objmsg->flags);
}

void decode_obj_created_eventfd(char *buf)
{
	struct msg_objcreatedeventfd *objmsg;
	objmsg = (struct msg_objcreatedeventfd *) buf;

	printf("%s eventfd object created at %p by pid %d: fd:%d count: %d flags:%x\n",
		objmsg->hdr.global ? "global" : "local",
		objmsg->hdr.address, objmsg->hdr.pid, objmsg->fd,
		objmsg->count, objmsg->flags);
}


void decode_obj_created_timerfd(char *buf)
{
	struct msg_objcreatedtimerfd *objmsg;
	objmsg = (struct msg_objcreatedtimerfd *) buf;

	printf("%s timerfd object created at %p by pid %d: fd:%d clockid: %d flags:%x\n",
		objmsg->hdr.global ? "global" : "local",
		objmsg->hdr.address, objmsg->hdr.pid, objmsg->fd,
		objmsg->clockid, objmsg->flags);
}

void decode_obj_created_testfile(char *buf)
{
	struct msg_objcreatedfile *objmsg;

	objmsg = (struct msg_objcreatedfile *) buf;

	if (objmsg->fopened) {
		printf("%s testfile object created at %p by pid %d: fd %d = fopen(\"%s\") ; fcntl(fd, 0x%x)\n",
			objmsg->hdr.global ? "global" : "local",
			objmsg->hdr.address, objmsg->hdr.pid,
			objmsg->fd, objmsg->filename,
			objmsg->fcntl_flags);
	} else {
		printf("%s testfile object created at %p by pid %d: fd %d = open(\"%s\", 0x%x)\n",
			objmsg->hdr.global ? "global" : "local",
			objmsg->hdr.address, objmsg->hdr.pid,
			objmsg->fd, objmsg->filename, objmsg->flags);
	}
}

void decode_obj_created_memfd(char *buf)
{
	struct msg_objcreatedmemfd *objmsg;
	objmsg = (struct msg_objcreatedmemfd *) buf;

	printf("%s memfd object created at %p by pid %d: fd:%d name: %s flags:%x\n",
		objmsg->hdr.global ? "global" : "local",
		objmsg->hdr.address, objmsg->hdr.pid, objmsg->fd,
		objmsg->name, objmsg->flags);
}

void decode_obj_created_drm(char *buf)
{
	struct msg_objcreateddrm *objmsg;
	objmsg = (struct msg_objcreateddrm *) buf;

	printf("%s drm object created at %p by pid %d: fd:%d\n",
		objmsg->hdr.global ? "global" : "local",
		objmsg->hdr.address, objmsg->hdr.pid, objmsg->fd);
}

void decode_obj_created_inotify(char *buf)
{
	struct msg_objcreatedinotify *objmsg;
	objmsg = (struct msg_objcreatedinotify *) buf;

	printf("%s inotify object created at %p by pid %d: fd:%d flags:%x\n",
		objmsg->hdr.global ? "global" : "local",
		objmsg->hdr.address, objmsg->hdr.pid, objmsg->fd, objmsg->flags);
}

void decode_obj_created_userfault(char *buf)
{
	struct msg_objcreateduserfault *objmsg;
	objmsg = (struct msg_objcreateduserfault *) buf;

	printf("%s userfault object created at %p by pid %d: fd:%d flags:%x\n",
		objmsg->hdr.global ? "global" : "local",
		objmsg->hdr.address, objmsg->hdr.pid, objmsg->fd, objmsg->flags);
}

void decode_obj_created_fanotify(char *buf)
{
	struct msg_objcreatedfanotify *objmsg;
	objmsg = (struct msg_objcreatedfanotify *) buf;

	printf("%s fanotify object created at %p by pid %d: fd:%d flags:%x eventflags:%x\n",
		objmsg->hdr.global ? "global" : "local",
		objmsg->hdr.address, objmsg->hdr.pid, objmsg->fd,
		objmsg->flags, objmsg->eventflags);
}

void decode_obj_created_bpfmap(char *buf)
{
	struct msg_objcreatedbpfmap *objmsg;
	const char *bpfmaptypes[] = {
		"hash", "array", "prog array", "perf_event_array",
		"percpu hash", "percpu array", "stack trace", "cgroup array",
		"lru hash", "lru hash (no common LRU)", "LRU percpu hash", "LPM TRIE",
	};

	objmsg = (struct msg_objcreatedbpfmap *) buf;

	printf("%s bpf map object created at %p by pid %d: fd:%d type:%s\n",
		objmsg->hdr.global ? "global" : "local",
		objmsg->hdr.address, objmsg->hdr.pid, objmsg->map_fd,
		bpfmaptypes[objmsg->map_type]);
}

void decode_obj_created_socket(char *buf)
{
	struct msg_objcreatedsocket *objmsg;
	objmsg = (struct msg_objcreatedsocket *) buf;

	printf("%s socket object created at %p by pid %d: fd:%d family:%d type:%d protocol:%d\n",
		objmsg->hdr.global ? "global" : "local",
		objmsg->hdr.address, objmsg->hdr.pid, objmsg->si.fd,
		objmsg->si.triplet.family,
		objmsg->si.triplet.type,
		objmsg->si.triplet.protocol);
}

void decode_obj_created_futex(char *buf)
{
	struct msg_objcreatedfutex *objmsg;
	objmsg = (struct msg_objcreatedfutex *) buf;

	printf("%s futex object created at %p by pid %d: futex:%d owner:%d\n",
		objmsg->hdr.global ? "global" : "local",
		objmsg->hdr.address, objmsg->hdr.pid,
		objmsg->futex, objmsg->owner);
}

void decode_obj_created_shm(char *buf)
{
	struct msg_objcreatedshm *objmsg;
	objmsg = (struct msg_objcreatedshm *) buf;

	printf("%s shm object created at %p by pid %d: id:%u size:%zu flags:%x ptr:%p\n",
		objmsg->hdr.global ? "global" : "local",
		objmsg->hdr.address, objmsg->hdr.pid,
		objmsg->id, objmsg->size, objmsg->flags, objmsg->ptr);
}

void decode_obj_destroyed(char *buf)
{
	struct msg_objdestroyed *objmsg;
	objmsg = (struct msg_objdestroyed *) buf;

	printf("%s object at %p destroyed by pid %d. type:%d\n",
		objmsg->hdr.global ? "global" : "local",
		objmsg->hdr.address, objmsg->hdr.pid,
		objmsg->hdr.type);
}
