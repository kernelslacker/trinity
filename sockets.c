#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "constants.h"
#include "log.h"
#include "net.h"
#include "maps.h"
#include "params.h"	// verbose, do_specific_proto
#include "protocols.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "uid.h"
#include "utils.h"

unsigned int nr_sockets = 0;

static const char *cachefilename="trinity.socketcache";

#define MAX_PER_DOMAIN 5
#define MAX_TRIES_PER_DOMAIN 10

static int open_socket(unsigned int domain, unsigned int type, unsigned int protocol)
{
	int fd;
	__unused__ int ret;
	struct sockaddr *sa = NULL;
	socklen_t salen;
	struct sockopt so = { 0, 0, 0, 0 };

	fd = socket(domain, type, protocol);
	if (fd == -1)
		return fd;

	shm->sockets[nr_sockets].fd = fd;
	shm->sockets[nr_sockets].triplet.family = domain;
	shm->sockets[nr_sockets].triplet.type = type;
	shm->sockets[nr_sockets].triplet.protocol = protocol;

	output(2, "fd[%i] = domain:%i (%s) type:0x%x protocol:%i\n",
		fd, domain, get_proto_name(domain), type, protocol);

	/* Set some random socket options. */
	sso_socket(&shm->sockets[nr_sockets].triplet, &so, fd);

	nr_sockets++;

	/* Sometimes, listen on created sockets. */
	if (rand_bool()) {
		/* fake a sockaddr. */
		generate_sockaddr((struct sockaddr **) &sa, (socklen_t *) &salen, domain);

		ret = bind(fd, sa, salen);
/*		if (ret == -1)
			debugf("bind: %s\n", strerror(errno));
		else
			debugf("bind: success!\n");
*/
		ret = listen(fd, (rand() % 2) + 1);
/*		if (ret == -1)
			debugf("listen: %s\n", strerror(errno));
		else
			debugf("listen: success!\n");
*/
	}

	/* If we didn't have a function for this sockaddr type, we would
	 * have returned page_rand, so don't free() it or we segv. */
	if (sa == (struct sockaddr *) page_rand)
		return fd;

	if (sa != NULL)
		free(sa);

	return fd;
}

static void lock_cachefile(int cachefile, int type)
{
	struct flock fl = {
		.l_len = 0,
		.l_start = 0,
		.l_whence = SEEK_SET,
	};

	fl.l_pid = getpid();
	fl.l_type = type;

	if (verbose)
		output(2, "waiting on lock for cachefile\n");

	if (fcntl(cachefile, F_SETLKW, &fl) == -1) {
		perror("fcntl F_SETLKW");
		exit(1);
	}

	if (verbose)
		output(2, "took lock for cachefile\n");
}

static void unlock_cachefile(int cachefile)
{
	struct flock fl = {
		.l_len = 0,
		.l_start = 0,
		.l_whence = SEEK_SET,
	};

	fl.l_pid = getpid();
	fl.l_type = F_UNLCK;

	if (fcntl(cachefile, F_SETLK, &fl) == -1) {
		perror("fcntl F_UNLCK F_SETLK ");
		exit(1);
	}

	if (verbose)
		output(2, "dropped lock for cachefile\n");
}

static unsigned int valid_proto(unsigned int family)
{
	const char *famstr;

	famstr = get_proto_name(family);

	/* Not used for creating sockets. */
	if (strncmp(famstr, "PF_UNSPEC", 9) == 0)
		return FALSE;
	if (strncmp(famstr, "PF_BRIDGE", 9) == 0)
		return FALSE;
	if (strncmp(famstr, "PF_SECURITY", 11) == 0)
		return FALSE;

	/* Not actually implemented (or now removed). */
	if (strncmp(famstr, "PF_NETBEUI", 10) == 0)
		return FALSE;
	if (strncmp(famstr, "PF_ASH", 6) == 0)
		return FALSE;
	if (strncmp(famstr, "PF_ECONET", 9) == 0)
		return FALSE;
	if (strncmp(famstr, "PF_SNA", 6) == 0)
		return FALSE;
	if (strncmp(famstr, "PF_WANPIPE", 10) == 0)
		return FALSE;

	/* Needs root. */
	if (orig_uid != 0) {
		if (strncmp(famstr, "PF_KEY", 6) == 0)
			return FALSE;
		if (strncmp(famstr, "PF_PACKET", 9) == 0)
			return FALSE;
		if (strncmp(famstr, "PF_LLC", 6) == 0)
			return FALSE;
	}

	return TRUE;
}

static int generate_sockets(void)
{
	int fd, n, ret = FALSE;
	int cachefile;
	unsigned int nr_to_create = NR_SOCKET_FDS;
	unsigned int buffer[3];

	cachefile = creat(cachefilename, S_IWUSR|S_IRUSR);
	if (cachefile == -1)
		outputerr("Couldn't open cachefile for writing! (%s)\n", strerror(errno));
	else
		lock_cachefile(cachefile, F_WRLCK);

	/*
	 * Don't loop forever if all protos all are disabled.
	 */
	if (!do_specific_proto) {
		for (n = 0; n < (int)ARRAY_SIZE(no_protos); n++) {
			if (!no_protos[n])
				break;
		}

		if (n >= (int)ARRAY_SIZE(no_protos))
			nr_to_create = 0;
	}

	while (nr_to_create > 0) {

		struct socket_triplet st;

		for (st.family = 0; st.family < TRINITY_PF_MAX; st.family++) {

			/* check for ctrl-c again. */
			if (shm->exit_reason != STILL_RUNNING)
				goto out_unlock;

			if (do_specific_proto == TRUE) {
				st.family = specific_proto;
				//FIXME: If we've passed -P and we're spinning here without making progress
				// then we should abort after a few hundred loops.
			}

			if (get_proto_name(st.family) == NULL)
				continue;

			if (valid_proto(st.family) == FALSE) {
				if (do_specific_proto == TRUE) {
					outputerr("Can't do protocol %s\n", get_proto_name(st.family));
					goto out_unlock;
				} else {
					continue;
				}
			}

			BUG_ON(st.family >= ARRAY_SIZE(no_protos));
			if (no_protos[st.family])
				continue;

			if (sanitise_socket_triplet(&st) == -1)
				rand_proto_type(&st);

			fd = open_socket(st.family, st.type, st.protocol);
			if (fd > -1) {
				nr_to_create--;

				if (cachefile != -1) {
					buffer[0] = st.family;
					buffer[1] = st.type;
					buffer[2] = st.protocol;
					n = write(cachefile, &buffer, sizeof(int) * 3);
					if (n == -1) {
						outputerr("something went wrong writing the cachefile!\n");
						goto out_unlock;
					}
				}

				if (nr_to_create == 0)
					goto done;
			} else {
				//outputerr("Couldn't open family:%d (%s)\n", st.family, get_proto_name(st.family));
			}
		}
	}

done:
	ret = TRUE;

	output(1, "created %d sockets\n", nr_sockets);

out_unlock:
	if (cachefile != -1) {
		unlock_cachefile(cachefile);
		close(cachefile);
	}

	return ret;
}


void close_sockets(void)
{
	unsigned int i;
	int fd;
	int r = 0;
	struct linger ling = { .l_onoff = FALSE, .l_linger = 0 };

	for (i = 0; i < nr_sockets; i++) {

		//FIXME: This is a workaround for a weird bug where we hang forevre
		// waiting for bluetooth sockets when we setsockopt.
		// Hopefully at some point we can remove this when someone figures out what's going on.
		if (shm->sockets[i].triplet.family == PF_BLUETOOTH)
			continue;

		/* Grab an fd, and nuke it before someone else uses it. */
		fd = shm->sockets[i].fd;
		shm->sockets[i].fd = 0;

		/* disable linger */
		r = setsockopt(fd, SOL_SOCKET, SO_LINGER, &ling, sizeof(struct linger));
		if (r)
			perror("setsockopt");

		r = shutdown(fd, SHUT_RDWR);
		if (r)
			perror("shutdown");

		if (close(fd) != 0)
			output(1, "failed to close socket [%d:%d:%d].(%s)\n",
				shm->sockets[i].triplet.family,
				shm->sockets[i].triplet.type,
				shm->sockets[i].triplet.protocol,
				strerror(errno));
	}

	nr_sockets = 0;
}

unsigned int open_sockets(void)
{
	int cachefile;
	unsigned int domain, type, protocol;
	unsigned int buffer[3];
	int bytesread=-1;
	int fd;
	int ret;

	cachefile = open(cachefilename, O_RDONLY);
	if (cachefile < 0) {
		output(1, "Couldn't find socket cachefile. Regenerating.\n");
		ret = generate_sockets();
		return ret;
	}

	lock_cachefile(cachefile, F_RDLCK);

	while (bytesread != 0) {
		bytesread = read(cachefile, buffer, sizeof(int) * 3);
		if (bytesread == 0)
			break;

		domain = buffer[0];
		type = buffer[1];
		protocol = buffer[2];

		if ((do_specific_proto == TRUE && domain != specific_proto) ||
		    (domain < ARRAY_SIZE(no_protos) && no_protos[domain] == TRUE)) {
			output(1, "ignoring socket cachefile due to specific "
			       "protocol request (or protocol disabled), "
			       "and stale data in cachefile.\n");
regenerate:
				unlock_cachefile(cachefile);	/* drop the reader lock. */
				close(cachefile);
				unlink(cachefilename);
				ret = generate_sockets();
				return ret;
		}

		fd = open_socket(domain, type, protocol);
		if (fd < 0) {
			output(1, "Cachefile is stale. Need to regenerate.\n");
			close_sockets();
			goto regenerate;
		}

		/* check for ctrl-c */
		if (shm->exit_reason != STILL_RUNNING) {
			close(cachefile);
			return FALSE;
		}
	}

	if (nr_sockets < NR_SOCKET_FDS) {
		output(1, "Insufficient sockets in cachefile (%d). Regenerating.\n", nr_sockets);
		goto regenerate;
	}

	output(1, "%d sockets created based on info from socket cachefile.\n", nr_sockets);

	unlock_cachefile(cachefile);
	close(cachefile);

	return TRUE;
}
