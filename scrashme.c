/* crashme.c 
 * 
 * Call random system calls with random arguments.
 * Based on an original program by Kurt Garloff <garloff@suse.de>
 *
 * License: Artistic
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>

extern char *syscall_names[];

long res=0;
long specificsyscall=0;
long regval=0;
char zeromask=0;
char *progname=0;
char dopause=0;
char *structptr=NULL;

#define MODE_UNDEFINED 0
#define MODE_RANDOM 1
#define MODE_ZEROREGS 2
#define MODE_REGVAL 3
#define MODE_STRUCT 4

char opmode= MODE_UNDEFINED;

#ifdef __i386__

# define NR_SYSCALLS 310

# define __syscall_return(type, res) \
do { \
	if ((unsigned long)(res) >= (unsigned long)(-125)) { \
		errno = -(res); \
		res = -1; \
	} \
	return (type) (res); \
} while (0)

long call5 (int nr, long a1, long a2, long a3, long a4, long a5)
{
	long __res; 
	__asm__ volatile ("int $0x80"
			  : "=a" (__res) 
			  : "0" (nr),"b" ((long)(a1)),"c" ((long)(a2)),
			    "d" ((long)(a3)), "S" ((long)(a4)),
			    "D" ((long)(a5)));
	__syscall_return(long,__res);
	return __res;
}
#endif

#ifdef __x86_64__
#define NR_SYSCALLS 272
long call5 (int nr, long a1, long a2, long a3, long a4, long a5)
{
	return(syscall(nr, a1, a2, a3, a4, a5));
}
#endif

void sighandler (int sig)
{
	printf ("%s ", strsignal (sig));
	fflush (stdout);
	_exit(0);
}


long mkcall (int call)
{
	unsigned long a1=0, a2=0, a3=0, a4=0, a5=0, a6=0;
	long ret = 0;
	switch (opmode) {
	case MODE_ZEROREGS:
		if (!(zeromask & (1<<0))) a6 = (long) rand() * rand();
		if (!(zeromask & (1<<1))) a5 = (long) rand() * rand();
		if (!(zeromask & (1<<2))) a4 = (long) rand() * rand();
		if (!(zeromask & (1<<3))) a3 = (long) rand() * rand();
		if (!(zeromask & (1<<4))) a2 = (long) rand() * rand();
		if (!(zeromask & (1<<5))) a1 = (long) rand() * rand();
		break;

	case MODE_REGVAL:
		a1 = a2 = a3 = a4 = a5 = a6 = regval;
		break;

	case MODE_STRUCT:
		a1 = a2 = a3 = a4 = a5 = a6 = (long) structptr;
		break;

	case MODE_RANDOM:
	default:
		a1 = rand();
		a2 = rand();
		a3 = rand();
		a4 = rand();
		a5 = rand();
		a6 = rand();
		break;
	}
	if (call >= NR_SYSCALLS)
		printf ("%d", call);
	else
		printf ("%s", syscall_names[call]);
	printf ("(0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx) ", a1, a2, a3, a4, a5, a6);

	fflush (stdout);

	if (call != __NR_exit && call != __NR_pause)
		ret = call5 (call, a1, a2, a3, a4, a5);
	printf ("= %ld", ret);

	if (ret < 0)
		printf (" %s\n", strerror (errno));
	else
		printf ("\n");
	return ret;
}

void usage(void)
{
	fprintf (stderr, "%s\n", progname);
	fprintf (stderr, "   -bN: begin at offset N.\n");
	fprintf (stderr, "   -cN: do syscall N with random inputs.\n");
	fprintf (stderr, "   -f:  pass struct filled with 0xff.\n");
	fprintf (stderr, "   -j:  pass struct filled with random junk.\n");
	fprintf (stderr, "   -k:  pass kernel addresses as arguments.\n");
	fprintf (stderr, "   -n:  pass struct filled with 0x00.\n");
	fprintf (stderr, "   -p;  pause after syscall.\n");
	fprintf (stderr, "   -r:  call random syscalls with random inputs.\n");
	fprintf (stderr, "   -sN: use N as random seed.\n");
	fprintf (stderr, "   -t:  use time of day as seed.\n");
	fprintf (stderr, "   -xN:  use value as arguments.\n");
	fprintf (stderr, "   -z:  Use all zeros as register parameters.\n");
	exit(1);
}


void do_call(int cl)
{
	if (opmode == MODE_RANDOM)
retry:
		cl = rand () / (RAND_MAX/NR_SYSCALLS);

	switch (cl) {
		case __NR_exit:
		case __NR_fork:
#ifdef __i386__
		case __NR_sigsuspend:
		case __NR_sigreturn:
#endif
		case __NR_select:
		case __NR_clone:
		case __NR_rt_sigreturn:
		case __NR_exit_group:
			goto retry;
		default:
			break;
	}

	alarm (2);

	if(specificsyscall!=0)
		cl = specificsyscall;

	res = mkcall(cl);
	if (dopause==1)
		sleep(1);
}

#define STRUCTMODE_FF 1
#define STRUCTMODE_RAND 2
#define STRUCTMODE_0 3


int main (int argc, char* argv[])
{
	volatile int rep=0;
	int c=0, i;
	int seed=0;
	struct timeval t;
	volatile char randomtime;
	int structmode=0;

	progname = argv[0];

	while ((c = getopt(argc, argv, "b:c:fjknprs:tx:z")) != -1) {
		switch (c) {
			case 'b':
				rep = strtol(optarg, NULL, 10);
				break;
			case 'c':
				specificsyscall = strtol(optarg, NULL, 10);
				break;
			case 'f':
				opmode = MODE_STRUCT;
				structmode = STRUCTMODE_FF;
				structptr = malloc(4096);
				memset (structptr, 0xff, 4096);
				break;
			case 'j':
				opmode = MODE_STRUCT;
				structmode = STRUCTMODE_RAND;
				structptr = malloc(4096);
				for (i=0;i<4096;i++)
					structptr[i]= rand();
				break;
			case 'k':
				opmode = MODE_REGVAL;
#ifdef __x86_64__
				regval = 0xffffffff80100f18;
#endif
#ifdef __i386__
				regval = 0xc0100220;
#endif
				break;
			case 'p':
				dopause =1;
				break;
			case 'n':
				opmode = MODE_STRUCT;
				structmode = STRUCTMODE_0;
				structptr = malloc(4096);
				memset (structptr, 0, 4096);
				break;
			case 'r':
				opmode = MODE_RANDOM;
				break;
			case 's':
				seed = strtol(optarg, NULL, 10);
				break;
			case 't':
				gettimeofday(&t, 0);
				seed = t.tv_usec;
				randomtime = 1;
				break;
			case 'x':
				regval=strtoul(optarg, NULL, 10);
				opmode = MODE_REGVAL;
				break;
			case 'z':
				opmode = MODE_ZEROREGS;
				break;
		}
	}

	if (argc==1)
		usage();

	if (opmode==MODE_UNDEFINED) {
		fprintf (stderr, "Must be either random (-r), specific (-c) or zero-sweep (-z).\n");
		usage();
	}

	seteuid(65536);
	seteuid(65536);
	setgid(65536);
	seteuid(65536);

	for (i=0; i<512; i++)  {
		struct sigaction sa;
		sa.sa_flags = SA_RESTART;
		sa.sa_handler = sighandler;
		sigaction(i, &sa, NULL);
	}
	signal(SIGCHLD, SIG_IGN);

	srand (seed);

	for (;;) {
		switch (opmode) {
			case MODE_REGVAL:
				if (rep == NR_SYSCALLS)
					goto done;
				break;

			case MODE_ZEROREGS:
				if (rep == NR_SYSCALLS) {
					/* Pointless running > once. */
					if (zeromask == (1<<6)-1)
						goto done;
					rep = 0;
					zeromask++;
				}
				break;

			case MODE_STRUCT:
				switch (structmode) {
				case STRUCTMODE_RAND:
					for (i=0;i<4096;i++)
						structptr[i]= rand();
					break;
				}
				if (rep == NR_SYSCALLS)
					goto done;
				break;
		}

		if (randomtime == 1) {
			gettimeofday(&t, 0);
			seed = t.tv_usec;
			srand(seed);
		}

		if (fork() == 0) {
			printf ("%i: ", rep);
			alarm(1);
			do_call(rep);
			_exit(0);
		}
		rand();
		waitpid(-1, NULL, 0);
		rep++;
	}

done:
	if (structptr!=NULL)
		free(structptr);
	return 0;
}

