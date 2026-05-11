/*
 * ipvs_sysctl_writer - per-netns IP_VS sysctl write driver.
 *
 * Targets the conn_tab_bits resize path: a write to
 * /proc/sys/net/ipv4/vs/conn_tab_bits feeds ip_vs_rht_desired_size,
 * which calls roundup_pow_of_two() on the parsed value.  Boundary values
 * (0, negatives, INT_MAX) hit the corner the upstream UBSAN trip
 * (4ee52b7021a7) addressed.  The generic procfs walker doesn't reach
 * the per-netns /proc/sys/net/ipv4/vs tree reliably: the sysctl table is
 * registered lazily on first access from inside ip_vs_init_net(), and
 * the walker's bounded depth + access(W_OK) gate often skips it.  This
 * op forces the per-netns init then writes a curated path list.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "child.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "text-payloads.h"
#include "trinity.h"

#define IPVS_CANONICAL_PATH	"/proc/sys/net/ipv4/vs/conn_tab_bits"
#define IPVS_WRITE_BASE		4U
#define IPVS_WRITE_CAP		16U

/* Conn-table burn-in: a virtual TCP service is set up once via ipvsadm
 * inside the netns, then short-lived non-blocking TCP sockets to the VIP
 * drive sustained insert/expire pressure on the per-net ip_vs_conn table.
 * That is the shape that exposed an upstream sleeping-while-atomic in
 * ip_vs_conn_expire on PREEMPT_RT; the same path is harmless but cheap
 * coverage on non-RT.  Iteration cap + parent-armed SIGALRM bound the
 * worst case; ONE_IN gate keeps overall cost low. */
#define IPVS_BURN_VIP		"127.0.0.7:80"
#define IPVS_BURN_RIP		"127.0.0.2:80"
#define IPVS_BURN_FREQ		8U
#define IPVS_BURN_BASE		6U
#define IPVS_BURN_CAP		32U

static const char * const ipvs_sysctls[] = {
	"/proc/sys/net/ipv4/vs/conn_tab_bits",
	"/proc/sys/net/ipv4/vs/am_droprate",
	"/proc/sys/net/ipv4/vs/expire_nodest_conn",
	"/proc/sys/net/ipv4/vs/expire_quiescent_template",
	"/proc/sys/net/ipv4/vs/sync_threshold",
	"/proc/sys/net/ipv4/vs/sync_qlen_max",
	"/proc/sys/net/ipv4/vs/drop_packet",
	"/proc/sys/net/ipv4/vs/sloppy_tcp",
	"/proc/sys/net/ipv4/vs/sloppy_sctp",
};
#define NR_IPVS_SYSCTLS		ARRAY_SIZE(ipvs_sysctls)

static bool ns_unsupported_ipvs_sysctl;
static bool setup_done;
static bool burn_setup_done;

static void try_modprobe(const char *mod)
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		return;
	if (pid == 0) {
		int devnull = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (devnull >= 0) {
			(void)dup2(devnull, 0);
			(void)dup2(devnull, 1);
			(void)dup2(devnull, 2);
			close(devnull);
		}
		execlp("modprobe", "modprobe", "-q", mod, (char *)NULL);
		_exit(127);
	}
	(void)waitpid(pid, &status, 0);
}

static void try_ipvsadm(const char *const argv[])
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		return;
	if (pid == 0) {
		int devnull = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (devnull >= 0) {
			(void)dup2(devnull, 0);
			(void)dup2(devnull, 1);
			(void)dup2(devnull, 2);
			close(devnull);
		}
		execvp("ipvsadm", (char *const *)argv);
		_exit(127);
	}
	(void)waitpid(pid, &status, 0);
}

static void ipvs_conn_burn(void)
{
	struct sockaddr_in dst = {
		.sin_family = AF_INET,
		.sin_port = htons(80),
	};
	unsigned int i, iters;

	if (!burn_setup_done) {
		const char *svc[] = { "ipvsadm", "-A", "-t", IPVS_BURN_VIP,
				      "-s", "rr", NULL };
		const char *rs[]  = { "ipvsadm", "-a", "-t", IPVS_BURN_VIP,
				      "-r", IPVS_BURN_RIP, "-m", NULL };
		struct ifreq ifr = { .ifr_name = "lo", .ifr_flags = IFF_UP };
		int s = socket(AF_INET, SOCK_DGRAM, 0);

		if (s >= 0) {
			(void)ioctl(s, SIOCSIFFLAGS, &ifr);
			close(s);
		}
		try_ipvsadm(svc);
		try_ipvsadm(rs);
		burn_setup_done = true;
	}

	(void)inet_pton(AF_INET, "127.0.0.7", &dst.sin_addr);
	iters = BUDGETED(CHILD_OP_IPVS_SYSCTL_WRITER, JITTER_RANGE(IPVS_BURN_BASE));
	if (iters > IPVS_BURN_CAP)
		iters = IPVS_BURN_CAP;

	for (i = 0; i < iters; i++) {
		int fd = socket(AF_INET,
				SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
		if (fd < 0)
			continue;
		(void)connect(fd, (struct sockaddr *)&dst, sizeof(dst));
		close(fd);
		__atomic_add_fetch(&shm->stats.ipvs_sysctl_writer_burn_iters,
				   1, __ATOMIC_RELAXED);
	}
}

bool ipvs_sysctl_writer(struct childdata *child)
{
	unsigned int iters, i;
	int probe;

	(void)child;

	__atomic_add_fetch(&shm->stats.ipvs_sysctl_writer_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_ipvs_sysctl)
		return true;

	if (!setup_done) {
		if (unshare(CLONE_NEWNET) < 0) {
			ns_unsupported_ipvs_sysctl = true;
			__atomic_add_fetch(&shm->stats.ipvs_sysctl_writer_unsupported_latched,
					   1, __ATOMIC_RELAXED);
			return true;
		}
		try_modprobe("ip_vs");
		try_modprobe("ip_vs_rr");

		/* First open of the canonical path triggers ip_vs_init_net()
		 * which registers the per-net sysctl table. */
		probe = open(IPVS_CANONICAL_PATH, O_RDONLY);
		if (probe < 0) {
			ns_unsupported_ipvs_sysctl = true;
			__atomic_add_fetch(&shm->stats.ipvs_sysctl_writer_unsupported_latched,
					   1, __ATOMIC_RELAXED);
			return true;
		}
		close(probe);
		setup_done = true;
	}

	iters = BUDGETED(CHILD_OP_IPVS_SYSCTL_WRITER, JITTER_RANGE(IPVS_WRITE_BASE));
	if (iters > IPVS_WRITE_CAP)
		iters = IPVS_WRITE_CAP;

	for (i = 0; i < iters; i++) {
		const char *path = ipvs_sysctls[rand() % NR_IPVS_SYSCTLS];
		char buf[128];
		unsigned int len;
		ssize_t n;
		int fd;

		fd = open(path, O_WRONLY | O_NONBLOCK);
		if (fd < 0) {
			__atomic_add_fetch(&shm->stats.ipvs_sysctl_writer_writes_failed,
					   1, __ATOMIC_RELAXED);
			continue;
		}

		if (strcmp(path, "/proc/sys/net/ipv4/vs/sync_threshold") == 0) {
			len = (unsigned int)snprintf(buf, sizeof(buf), "%d %d",
						     (int)rand32(), (int)rand32());
		} else {
			len = gen_text_payload(buf, sizeof(buf));
		}

		n = write(fd, buf, len);
		close(fd);

		if (n > 0)
			__atomic_add_fetch(&shm->stats.ipvs_sysctl_writer_writes_ok,
					   1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(&shm->stats.ipvs_sysctl_writer_writes_failed,
					   1, __ATOMIC_RELAXED);
	}

	if (ONE_IN(IPVS_BURN_FREQ))
		ipvs_conn_burn();

	return true;
}
