#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "debug.h"
#include "log.h"
#include "net.h"
#include "params.h"	// verbose, do_specific_domain
#include "domains.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "uid.h"
#include "utils.h"

unsigned int nr_sockets = 0;

static const char *cachefilename="trinity.socketcache";

static void sso_socket(struct socket_triplet *triplet, struct sockopt *so, int fd)
{
	int ret;
	unsigned int tries = 0;

	/* skip over bluetooth due to weird linger bug */
	if (triplet->family == PF_BLUETOOTH)
		return;

	so->optval = 0;

retry:
	if (so->optval != 0)
		free((void *) so->optval);

	do_setsockopt(so, triplet);

	ret = setsockopt(fd, so->level, so->optname, (void *)so->optval, so->optlen);
	if (ret == 0) {
		output(2, "setsockopt(%lx %lx %lx %lx) on fd %d [%d:%d:%d]\n",
			so->level, so->optname, so->optval, so->optlen, fd,
			triplet->family, triplet->type, triplet->protocol);
	} else {
		tries++;
		if (tries != 100)
			goto retry;
	}

	if (so->optval != 0)
		free((void *) so->optval);
}

static int open_socket(unsigned int domain, unsigned int type, unsigned int protocol)
{
	int fd;
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
		fd, domain, get_domain_name(domain), type, protocol);

	/* Set some random socket options. */
	sso_socket(&shm->sockets[nr_sockets].triplet, &so, fd);

	nr_sockets++;

	/* Sometimes, listen on created sockets. */
	if (RAND_BOOL()) {
		int ret, one = 1;

		/* fake a sockaddr. */
		generate_sockaddr((struct sockaddr **) &sa, (socklen_t *) &salen, domain);

		ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		if (ret != -1)
			goto skip_bind;
		ret = bind(fd, sa, salen);
		if (ret != -1)
			(void) listen(fd, RAND_RANGE(1, 128));
	}
skip_bind:

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
		exit_main_fail();
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
		exit_main_fail();
	}

	if (verbose)
		output(2, "dropped lock for cachefile\n");
}

static unsigned int valid_proto(unsigned int family)
{
	const char *famstr;

	famstr = get_domain_name(family);

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

static bool write_socket_to_cache(int cachefile, struct socket_triplet *st)
{
	unsigned int buffer[3];
	int n;

	if (cachefile == -1)
		return FALSE;

	buffer[0] = st->family;
	buffer[1] = st->type;
	buffer[2] = st->protocol;
	n = write(cachefile, &buffer, sizeof(int) * 3);
	if (n == -1) {
		outputerr("something went wrong writing the cachefile!\n");
		return FALSE;
	}
	return TRUE;
}

static int generate_sockets(void)
{
	int fd, n, ret = FALSE;
	int cachefile;
	unsigned int nr_to_create = NR_SOCKET_FDS;

	cachefile = creat(cachefilename, S_IWUSR|S_IRUSR);
	if (cachefile == -1)
		outputerr("Couldn't open cachefile for writing! (%s)\n", strerror(errno));
	else
		lock_cachefile(cachefile, F_WRLCK);

	/*
	 * Don't loop forever if all domains all are disabled.
	 */
	if (!do_specific_domain) {
		for (n = 0; n < (int)ARRAY_SIZE(no_domains); n++) {
			if (!no_domains[n])
				break;
		}

		if (n >= (int)ARRAY_SIZE(no_domains))
			nr_to_create = 0;
	}

	while (nr_to_create > 0) {

		struct socket_triplet st;

		for (st.family = 0; st.family < TRINITY_PF_MAX; st.family++) {

			/* check for ctrl-c again. */
			if (shm->exit_reason != STILL_RUNNING)
				goto out_unlock;

			if (do_specific_domain == TRUE) {
				st.family = specific_domain;
				//FIXME: If we've passed -P and we're spinning here without making progress
				// then we should abort after a few hundred loops.
			}

			if (get_domain_name(st.family) == NULL)
				continue;

			if (valid_proto(st.family) == FALSE) {
				if (do_specific_domain == TRUE) {
					outputerr("Can't do protocol %s\n", get_domain_name(st.family));
					goto out_unlock;
				} else {
					continue;
				}
			}

			BUG_ON(st.family >= ARRAY_SIZE(no_domains));
			if (no_domains[st.family])
				continue;

			if (sanitise_socket_triplet(&st) == -1)
				rand_proto_type(&st);

			fd = open_socket(st.family, st.type, st.protocol);
			if (fd > -1) {
				if (write_socket_to_cache(cachefile, &st) == FALSE)
					goto out_unlock;

				nr_to_create--;
				if (nr_to_create == 0)
					goto done;
			} else {
				//outputerr("Couldn't open family:%d (%s)\n", st.family, get_domain_name(st.family));
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
		(void) setsockopt(fd, SOL_SOCKET, SO_LINGER, &ling, sizeof(struct linger));

		(void) shutdown(fd, SHUT_RDWR);

		if (close(fd) != 0)
			output(1, "failed to close socket [%d:%d:%d].(%s)\n",
				shm->sockets[i].triplet.family,
				shm->sockets[i].triplet.type,
				shm->sockets[i].triplet.protocol,
				strerror(errno));
	}

	nr_sockets = 0;
}

static int open_sockets(void)
{
	int cachefile;
	unsigned int domain, type, protocol;
	unsigned int buffer[3];
	int bytesread = -1;
	int fd;
	int ret;

	/* If we're doing victim files we probably don't care about sockets. */
	//FIXME: Is this really true ? We might want to sendfile for eg
	if (victim_path != NULL)
		return TRUE;

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

		if ((do_specific_domain == TRUE && domain != specific_domain) ||
		    (domain < ARRAY_SIZE(no_domains) && no_domains[domain] == TRUE)) {
			output(1, "ignoring socket cachefile due to specific "
			       "protocol request (or protocol disabled), "
			       "and stale data in cachefile.\n");
regenerate:
				unlock_cachefile(cachefile);	/* drop the reader lock. */
				close(cachefile);
				unlink(cachefilename);

				close_sockets();
				ret = generate_sockets();
				return ret;
		}

		fd = open_socket(domain, type, protocol);
		if (fd < 0) {
			output(1, "Cachefile is stale. Need to regenerate.\n");
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

static int get_rand_socket_fd(void)
{
	int fd;

	/* When using victim files, sockets can be 0. */
	if (nr_sockets == 0)
		return -1;

	fd = shm->sockets[rand() % nr_sockets].fd;

	return fd;
}

struct socketinfo * get_rand_socketinfo(void)
{
	/* When using victim files, sockets can be 0. */
	if (nr_sockets == 0)
		return NULL;

	return &shm->sockets[rand() % nr_sockets];
}

int generic_fd_from_socketinfo(struct socketinfo *si)
{
	if (ONE_IN(1000))
		return get_random_fd();
	else
		return si->fd;
}

const struct fd_provider socket_fd_provider = {
	.name = "sockets",
	.enabled = TRUE,
	.open = &open_sockets,
	.get = &get_rand_socket_fd,
};
