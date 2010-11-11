/*
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
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#include <setjmp.h>
#include <asm/unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "arch.h"
#include "arch-syscalls.h"
#include "scrashme.h"
#include "files.h"

struct syscalltable *syscalls;
struct syscalltable *syscalls32;

static unsigned int rep=0;
static long res=0;
static long specificsyscall=0;
static unsigned long regval=0;
static char *progname=NULL;
static char *structptr=NULL;
static unsigned char rotate_mask=1;
static unsigned char dopause=0;
static unsigned char intelligence=0;
static unsigned char do_specific_syscall=0;
static unsigned char check_poison = 0;
static unsigned char bruteforce = 0;
static unsigned int seed=0;
static long long syscallcount=0;
static long long execcount=0;

static int do_32bit=0;

static unsigned int nofork=0;

static unsigned int max_nr_syscalls;
static unsigned int max_nr_syscalls32;

static int ctrlc_hit = 0;

struct shm_s {
	unsigned long successes;
	unsigned long failures;
	unsigned long retries;
};
struct shm_s *shm;

char poison = 0x55;

unsigned int page_size;

jmp_buf ret_jump;

#define MODE_UNDEFINED 0
#define MODE_RANDOM 1
#define MODE_ROTATE 2
#define MODE_CAPCHECK 3
static int opmode = MODE_UNDEFINED;

#define STRUCT_UNDEFINED 0
#define STRUCT_CONST 1
#define STRUCT_RAND 2
static int structmode = STRUCT_UNDEFINED;

static long struct_fill;		/* value to fill struct with if CONST */

char *opmodename[] = {
	[MODE_UNDEFINED] = "undef",
	[MODE_RANDOM] = "random",
	[MODE_ROTATE] = "rotate",
	[MODE_CAPCHECK] = "capabilities_check",
};
char *structmodename[] = {
	[STRUCT_UNDEFINED] = "unknown",
	[STRUCT_CONST] = "constant",
	[STRUCT_RAND]  = "random",
};

#define TYPE_UNDEFINED 0
#define TYPE_VALUE 1
#define TYPE_STRUCT 2
static char passed_type = TYPE_UNDEFINED;


static const char *logfilename = "scrashme.log";
FILE *logfile;

#define writelog(...) do {      \
        logfile = fopen(logfilename, "a"); \
        if (!logfile) { \
                perror("couldn't open logfile\n"); \
                exit(EXIT_FAILURE); \
        } \
        fprintf(logfile, ## __VA_ARGS__); \
	fflush(logfile); \
        fclose(logfile); \
} while (0)



static char *userbuffer;
char *useraddr;
void init_buffer()
{
	userbuffer = malloc(4096*3);
	if (!userbuffer) {
		exit(EXIT_FAILURE);
	}
	memset(userbuffer, poison, 4096);
	memset(userbuffer+4096+4096, poison, 4096);

	useraddr = userbuffer+4096;
	memset(useraddr, 0, 4096);
}

static void sighandler(int sig)
{
	printf("signal: %s\n", strsignal (sig));
	(void)fflush(stdout);
	(void)signal(sig, sighandler);
	if (sig == SIGALRM)
		printf("Alarm clock.\n");
	if (nofork==1) {
			printf("jumping back from sighandler\n");
			siglongjmp(ret_jump, sig);
	}
	_exit(0);
}

#define __syscall_return(type, res) \
do { \
	if ((unsigned long)(res) >= (unsigned long)(-125)) { \
		errno = -(res); \
		res = -1; \
	} \
	return (type) (res); \
} while (0)

static long call_syscall(__unused int num_args, unsigned int call,
	unsigned long a1, unsigned long a2, unsigned long a3,
	unsigned long a4, unsigned long a5, unsigned long a6)
{
	if (!do_32bit)
		return syscall(call, a1, a2, a3, a4, a5, a6);

	if (num_args < 6) {
		long __res;
		__asm__ volatile ("int $0x80"
		: "=a" (__res)
		: "0" (call),"b" ((long)(a1)),"c" ((long)(a2)),
		"d" ((long)(a3)), "S" ((long)(a4)),
		"D" ((long)(a5)));
		__syscall_return(long,__res);
		return __res;
	}
	/* TODO: 6 arg 32bit syscall goes here.*/

	return 0;

}

unsigned long rand64()
{
	unsigned long r;

	r = (unsigned long)rand();
	r *= (unsigned long)rand();
	return r;
}

static long mkcall(unsigned int call)
{
	unsigned long olda1=0, olda2=0, olda3=0, olda4=0, olda5=0, olda6=0;
	unsigned long a1=0, a2=0, a3=0, a4=0, a5=0, a6=0;
	int ret = 0;
	int i, j;
	int poisoned = 0;

	switch (opmode) {
	case MODE_ROTATE:
		a1 = a2 = a3 = a4 = a5 = a6 = regval;
		if (!(rotate_mask & (1<<0))) a6 = rand64();
		if (!(rotate_mask & (1<<1))) a5 = rand64();
		if (!(rotate_mask & (1<<2))) a4 = rand64();
		if (!(rotate_mask & (1<<3))) a3 = rand64();
		if (!(rotate_mask & (1<<4))) a2 = rand64();
		if (!(rotate_mask & (1<<5))) a1 = rand64();
		break;

	case MODE_RANDOM:
	default:
		a1 = rand64();
		a2 = rand64();
		a3 = rand64();
		a4 = rand64();
		a5 = rand64();
		a6 = rand64();
		break;
	}
	if (call > max_nr_syscalls)
		printf("%u", call);
	else
		printf("%s", syscalls[call].name);

	/* If there are no inputs, we can't fuzz anything. */
	if (syscalls[call].num_args == 0) {
		syscalls[call].flags |= AVOID_SYSCALL;
		printf(" syscall has no inputs:- skipping\n");
		return 0;
	}

	olda1=a1; olda2=a2; olda3=a3; olda4=a4; olda5=a5; olda6=a6;

	if (intelligence == 1) {
		generic_sanitise(call, &a1, &a2, &a3, &a4, &a5, &a6);
		if (syscalls[call].sanitise)
			syscalls[call].sanitise(&a1, &a2, &a3, &a4, &a5, &a6);
	}

	printf(WHITE "(");
	if (syscalls[call].num_args >= 1) {
		if (syscalls[call].arg1name)
			printf("%s=", syscalls[call].arg1name);
		if (olda1==a1)
			printf(WHITE "0x%lx", a1);
		else
			printf(CYAN "0x%lx" WHITE, a1);
	}
	if (syscalls[call].num_args >= 2) {
		printf(", ");
		if (syscalls[call].arg2name)
			printf("%s=", syscalls[call].arg2name);
		if (olda2==a2)
			printf(WHITE "0x%lx", a2);
		else
			printf(CYAN "0x%lx" WHITE, a2);
	}
	if (syscalls[call].num_args >= 3) {
		printf(", ");
		if (syscalls[call].arg3name)
			printf("%s=", syscalls[call].arg3name);
		if (olda3==a3)
			printf(WHITE "0x%lx", a3);
		else
			printf(CYAN "0x%lx" WHITE, a3);
	}
	if (syscalls[call].num_args >= 4) {
		printf(", ");
		if (syscalls[call].arg4name)
			printf("%s=", syscalls[call].arg4name);
		if (olda4==a4)
			printf(WHITE "0x%lx", a4);
		else
			printf(CYAN "0x%lx" WHITE, a4);
	}
	if (syscalls[call].num_args >= 5) {
		printf(", ");
		if (syscalls[call].arg5name)
			printf("%s=", syscalls[call].arg5name);
		if (olda5==a5)
			printf(WHITE "0x%lx", a5);
		else
			printf(CYAN "0x%lx" WHITE, a5);
	}
	if (syscalls[call].num_args == 6) {
		printf(", ");
		if (syscalls[call].arg6name)
			printf("%s=", syscalls[call].arg6name);
		if (olda6==a6)
			printf(WHITE "0x%lx", a6);
		else
			printf(CYAN "0x%lx" WHITE, a6);
	}
	printf(WHITE ") ");


	if (opmode == MODE_ROTATE) {
		printf("(");
		if (rotate_mask & (1<<5))
			printf(YELLOW "0x%lx, " WHITE, a1);
		else
			printf(WHITE "0x%lx, " WHITE, a1);

		if (rotate_mask & (1<<4))
			printf(YELLOW "0x%lx, " WHITE, a2);
		else
			printf(WHITE "0x%lx, " WHITE, a2);

		if (rotate_mask & (1<<3))
			printf(YELLOW "0x%lx, " WHITE, a3);
		else
			printf(WHITE "0x%lx, " WHITE, a3);

		if (rotate_mask & (1<<2))
			printf(YELLOW "0x%lx, " WHITE, a4);
		else
			printf(WHITE "0x%lx, " WHITE, a4);

		if (rotate_mask & (1<<1))
			printf(YELLOW "0x%lx, " WHITE, a5);
		else
			printf(WHITE "0x%lx, " WHITE, a5);

		if (rotate_mask & (1<<0))
			printf(YELLOW "0x%lx" WHITE, a6);
		else
			printf(WHITE "0x%lx" WHITE, a6);

		printf(")");
//	} else {
//		if (syscalls[call].num_args == 6)
//			printf("(0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx) ", a1, a2, a3, a4, a5, a6);
	}

	writelog("%s (0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx) ",
		syscalls[call].name, a1, a2, a3, a4, a5, a6);


	(void)fflush(stdout);

/* IA64 is retarde^Wspecial. */
#ifdef __ia64__
	call += 1024;
#endif

	ret = call_syscall(syscalls[call].num_args, call, a1, a2, a3, a4, a5, a6);

	if (ret < 0) {
		printf(RED "= %d (%s)\n" WHITE, ret, strerror(errno));
		writelog("= %d (%s)\n", ret, strerror(errno));
		shm->failures++;
	} else {
		printf(GREEN "= %d\n" WHITE, ret);
		writelog("= %d\n" , ret);
		shm->successes++;
	}
	(void)fflush(stdout);

	if (check_poison==1) {
		for (i = 0; i < 4096; i++) {
			if (userbuffer[i]!=poison)
				poisoned = 1;
		}
		for (i = 4096*2; i < 4096*3; i++) {
			if (userbuffer[i]!=poison)
				poisoned = 2;
		}

		if (poisoned==1) {
			printf ("Yikes! pre-buffer poison was overwritten!\n");
			for (i = 0; i < 4096; i+=32) {
				printf("%d: ", i);
				for (j=0; j < 32; j++)
					printf("%x ", (unsigned int) userbuffer[i+j]);
				printf("\n");
			}
			(void)fflush(stdout);
			(void)sleep(10);
		}
		if (poisoned==2) {
			printf ("Yikes! post-buffer poison was overwritten!\n");
			for (i = 4096*2; i < 4096*3; i+=32) {
				printf("%i: ", i);
				for (j=0; j < 32; j++)
					printf("%x ", (unsigned int) userbuffer[i+j]);
				printf("\n");
			}
			(void)fflush(stdout);
			(void)sleep(10);
		}
	}


	/* If the syscall doesn't exist don't bother calling it next time. */
	if (ret == -ENOSYS)
		syscalls[call].flags |= AVOID_SYSCALL;

	printf("\n");
	return ret;
}

static void usage(void)
{
	fprintf(stderr, "%s\n", progname);
	fprintf(stderr, "   --mode=random : pass random values in registers to random syscalls\n");
	fprintf(stderr, "     -s#: use # as random seed.\n");
	fprintf(stderr, "     --bruteforce : Keep retrying syscalls until it succeeds (needs -i) [EXPERIMENTAL]\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "   --mode=rotate : rotate value through all register combinations\n");
	fprintf(stderr, "     -k:  pass kernel addresses as arguments.\n");
	fprintf(stderr, "     -u:  pass userspace addresses as arguments.\n");
	fprintf(stderr, "     -x#: use value as register arguments.\n");
	fprintf(stderr, "     -z:  use all zeros as register parameters.\n");
	fprintf(stderr, "     -Sr: pass struct filled with random junk.\n");
	fprintf(stderr, "     -Sxx: pass struct filled with hex value xx.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "   --mode=capcheck:  check syscalls that call capable() return -EPERM.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "   -b#: begin at offset #.\n");
	fprintf(stderr, "   -c#: target syscall # only.\n");
	fprintf(stderr, "   -F:  don't fork after each syscall.\n");
	fprintf(stderr, "   -i:  pass sensible parameters where possible.\n");
	fprintf(stderr, "   -N#: do # syscalls then exit.\n");
	fprintf(stderr, "   -P:  poison buffers before calling syscall, and check afterwards.\n");
	fprintf(stderr, "   -p:  pause after syscall.\n");
	exit(EXIT_SUCCESS);
}

static void seed_from_tod()
{
	struct timeval t;

	gettimeofday(&t, 0);
	seed = t.tv_sec * t.tv_usec;
	srand(seed);
}

static int do_syscall(int cl)
{
	int retrycount = 0;

	printf ("%i: ", cl);

	seed_from_tod();

	if (opmode == MODE_RANDOM)
retry:
		cl = rand() / (RAND_MAX/max_nr_syscalls);

retry_same:
	if (syscalls[cl].flags & AVOID_SYSCALL)
		goto retry;

	(void)alarm(3);

	if (do_specific_syscall != 0)
		cl = specificsyscall;

	res = mkcall(cl);

	/*  Brute force the same syscall until it succeeds */
	if ((opmode == MODE_RANDOM) && (intelligence == 1) && (bruteforce == 1)) {
		// Don't bother trying to bruteforce ni_syscall
		if (res == -ENOSYS)
			goto failed_repeat;

		if (retrycount == 100) {
			//printf("100 retries done without success. moving on\n");
			goto failed_repeat;
		}

		if (res < 0) {
			//printf ("syscall failed. Retrying\n");
			retrycount++;
			shm->retries++;
			goto retry_same;
		}
	}

failed_repeat:

	if (dopause==1)
		(void)sleep(1);

	return res;
}

static void do_syscall_from_child(int cl)
{
	int ret;

	if (nofork==1) {
		ret = do_syscall(cl);
		return;
	}

	if (fork() == 0) {
		ret = do_syscall(cl);
		//if (intelligence==1)
		//	close_fds();
		_exit(ret);
	}
	(void)waitpid(-1, NULL, 0);
}

static void syscall_list()
{
	unsigned int i;

	for (i=0; i<=max_nr_syscalls; i++)
		 printf("%u: %s\n", i, syscalls[i].name);
}

static void parse_args(int argc, char *argv[])
{
	unsigned int i;
	int opt;

	struct option longopts[] = {
		{ "list", optional_argument, NULL, 'L' },
		{ "help", no_argument, NULL, 'h' },
		{ "mode", required_argument, NULL, 'm' },
		{ "nofork", optional_argument, NULL, 'F' },
		{ "bruteforce", optional_argument, NULL, 'B' },
		{ "32bit", optional_argument, &do_32bit, 1 },
		{ NULL, 0, NULL, 0 } };

	while ((opt = getopt_long(argc, argv, "b:Bc:FhikLN:m:pPs:S:ux:z", longopts, NULL)) != -1) {
		switch (opt) {
		default:
		case '\0':
			return;

		/* Get the mode we want to run */
		case 'm':
			if (!strcmp(optarg, "random"))
				opmode = MODE_RANDOM;
			if (!strcmp(optarg, "rotate"))
				opmode = MODE_ROTATE;
			if (!strcmp(optarg, "capcheck"))
				opmode = MODE_CAPCHECK;
			break;

		case 'b':
			rep = strtol(optarg, NULL, 10);
			break;

		case 'B':
			bruteforce = 1;
			break;

		case 'c':
			do_specific_syscall = 1;
			specificsyscall = strtol(optarg, NULL, 10);

			for (i=0; i<=max_nr_syscalls; i++) {
				if (strcmp(optarg, syscalls[i].name) == 0) {
					printf("Found %s at %u\n", syscalls[i].name, i);
					specificsyscall = i;
					break;
				}
			}

			if (i>max_nr_syscalls) {

				if (!max_nr_syscalls32)
					goto no_sys32;

				/* Try looking in the 32bit table. */
				for (i=0; i<=max_nr_syscalls32; i++) {
					if (strcmp(optarg, syscalls32[i].name) == 0) {
						printf("Found in the 32bit syscall table %s at %u\n", syscalls32[i].name, i);
						specificsyscall = i;
						printf("Forcing into 32bit mode.\n");
						do_32bit = 1;
						break;
					}
				}

				if (i>max_nr_syscalls32) {
no_sys32:
					printf("syscall not found :(\n");
					exit(EXIT_FAILURE);
				}
				break;
			}
			break;
		case 'F':
			nofork = 1;
			break;

		/* Show help */
		case 'h':
			usage();
			exit(EXIT_SUCCESS);

		/* use semi-intelligent options */
		case 'i':
			intelligence = 1;
			setup_fds();
			break;

		case 'L':
			syscall_list();
			exit(EXIT_SUCCESS);

		/* Pass in address of kernel text */
		case 'k':
			passed_type = TYPE_VALUE;
			regval = KERNEL_ADDR;
			break;

		/* Set syscall loop counter */
		case 'N':
			syscallcount = strtoll(optarg, NULL, 10);
			break;

		/* Pause after each syscall */
		case 'p':
			dopause = 1;
			break;

		/* Poison buffers before syscall, and check afterwards. */
		case 'P':
			check_poison = 1;
			break;

		/* Set seed */
		case 's':
			seed = strtol(optarg, NULL, 10);
			break;

		/* Set Struct fill mode */
		case 'S':
			switch (*optarg) {
				/* Pass a ptr to a struct filled with random junk */
			case 'r':
				structmode = STRUCT_RAND;
				structptr = malloc(page_size);
				if (!structptr)
					exit(EXIT_FAILURE);
				for (i=0; i<page_size; i++)
					structptr[i]= rand();
				break;
			case '\0':
			case ' ':
				fprintf(stderr,
					"-S requires 'r' or a hex value\n");
				exit(EXIT_FAILURE);

			/* Pass a ptr to a struct filled with the
			 * user-specified constant value. */
			default:
				structmode = STRUCT_CONST;
				if (!isxdigit(*optarg)) {
					fprintf(stderr,
					    "-S requires 'r' or a "
					    "hex value\n");
					exit(EXIT_FAILURE);
				}
				struct_fill = strtol(optarg, NULL, 16);
				structptr = malloc(page_size);
				if (!structptr)
					exit(EXIT_FAILURE);
				memset(structptr, struct_fill, page_size);
				break;
			}
			passed_type = TYPE_STRUCT;
			regval = (unsigned long) structptr;
			break;

		/* Pass in address of kernel text */
		case 'u':
			passed_type = TYPE_VALUE;
			regval = (unsigned long) useraddr;
			break;

		/* Set registers to specific value */
		case 'x':
			regval = strtoul(optarg, NULL, 0);
			passed_type = TYPE_VALUE;
			break;

		/* Wander a 0 through every register */
		case 'z':
			regval = 0;
			passed_type = TYPE_VALUE;
			break;
		}
	}

	if (bruteforce == 1) {
		if (opmode != MODE_RANDOM) {
			printf("Brute-force only works in --mode=random\n");
			exit(EXIT_FAILURE);
		}
		if (intelligence != 1) {
			printf("Brute-force needs -i\n");
			exit(EXIT_FAILURE);
		}
	}

	if (opmode == MODE_UNDEFINED) {
		fprintf(stderr, "Unrecognised mode \'%s\'\n", optarg);
		fprintf(stderr, "--mode must be one of random, rotate, regval, "
			"struct, or capcheck\n\n");
		usage();
		exit(EXIT_FAILURE);
	}
}

static void ctrlc(__attribute((unused)) int sig)
{
	ctrlc_hit=1;
}

static void run_setup(void)
{
	int i;

	seteuid(65536);
	seteuid(65536);
	(void)setgid(65536);
	seteuid(65536);

	for (i=1; i<512; i++)  {
		struct sigaction sa;
		sigset_t ss;

		(void)sigfillset(&ss);
		sa.sa_flags = SA_RESTART;
		sa.sa_handler = sighandler;
		sa.sa_mask = ss;
		(void)sigaction(i, &sa, NULL);
	}
	(void)signal(SIGWINCH, SIG_IGN);
	(void)signal(SIGCHLD, SIG_IGN);
	(void)signal(SIGINT, ctrlc);

	srand(seed);

	chroot("tmp");
}

static void run_mode(void)
{
	unsigned int i;

	printf("scrashme mode: %s\n", opmodename[opmode]);

	switch (opmode) {

	case MODE_ROTATE:
		switch (passed_type) {
		case TYPE_STRUCT:
			printf("struct mode = %s\n", structmodename[structmode]);
			if (structmode == STRUCT_CONST)
				printf("struct fill value is 0x%x\n", (int)struct_fill);
			break;
		}

		printf("Rotating value %lx though all registers\n", regval);
		break;
	}

	(void)fflush(stdout);

	/* This is our main loop. */

	for (;;) {

		if (ctrlc_hit == 1)
			return;

		switch (opmode) {
		case MODE_ROTATE:
			/* It's easier to just use all regs for now. */
			for (i=0; i<=max_nr_syscalls; i++) {
				syscalls[i].num_args = 6;
			}

			if (do_specific_syscall == 1) {
				rotate_mask++;
				if (rotate_mask == (1<<6)-1)
					goto done;
			} else {
				if (rep > max_nr_syscalls) {
					/* Pointless running > once. */
					if (rotate_mask == (1<<6)-1)
						goto done;
					rep = 0;
					rotate_mask++;
				}
			}
			do_syscall_from_child(rep);
			break;

		case MODE_CAPCHECK:
			if (rep > max_nr_syscalls)
				goto done;
			if (syscalls[rep].flags & CAPABILITY_CHECK) {
				int r;
				printf ("%i: ", rep);
				r = do_syscall(rep);
				if (r != -EPERM)
					printf ("Didn't return EPERM!\n");
			}
			break;

		case MODE_RANDOM:
			do_syscall_from_child(rep);
			break;
		}

		rep++;
		execcount++;
		if (syscallcount && (execcount >= syscallcount))
			break;

		/*
		 * If we're passing random structs, regenerate the
		 * buffer every time we make a syscall.
		 */
		if (passed_type == TYPE_STRUCT) {
			if (structmode == STRUCT_RAND) {
				for (i=0; i<page_size; i++) {
					structptr[i]= rand();
					break;
				}
			}
		}

		/* If we're passing userspace addresses, mess with alignment */
		if ((passed_type == TYPE_VALUE) &&
		    ((regval & ~0xf) == (unsigned long)useraddr))
			regval = (unsigned long)useraddr+(rand() & 0xf);

	}
done: ;
}


int main(int argc, char* argv[])
{
	//unsigned int i;
	//int ret;

	int shmid;
	key_t key;

#ifdef __x86_64__
	syscalls32 = syscalls_i386;
	syscalls = syscalls_x86_64;
	max_nr_syscalls = NR_X86_64_SYSCALLS;
	max_nr_syscalls32 = NR_I386_SYSCALLS;
#elif __i386__
	syscalls = syscalls_i386;
	max_nr_syscalls = NR_I386_SYSCALLS;
#elif __powerpc__
	syscalls = syscalls_ppc;
#elif __ia64__
	syscalls = syscalls_ia64;
#elif __sparc__
	syscalls = syscalls_sparc;
#else
	syscalls = syscalls_i386;
#endif

	progname = argv[0];
	parse_args(argc, argv);
	if (argc==1)
		usage();

	max_nr_syscalls = NR_SYSCALLS;


#ifdef __x86_64__
	if (do_32bit) {
		syscalls = syscalls_i386;
		max_nr_syscalls = NR_I386_SYSCALLS;
		printf("32bit mode. Fuzzing %d syscalls.\n", max_nr_syscalls);
	} else {
		printf("64bit mode. Fuzzing %d syscalls.\n", max_nr_syscalls);
	}
#endif


	page_size = getpagesize();

	unlink(logfilename);

	if (!seed)
		seed_from_tod();

	key = rand64();
	if ((shmid = shmget(key, sizeof(struct shm_s), IPC_CREAT | 0666)) < 0) {
		perror("shmget");
		exit(EXIT_FAILURE);
	}
	if ((shm = shmat(shmid, NULL, 0)) == (void *) -1) {
		perror("shmat");
		exit(EXIT_FAILURE);
	}
	shm->successes = 0;
	shm->failures = 0;

	init_buffer();


	/* Sanity test. All NI_SYSCALL's should return ENOSYS. */
	/* disable for now, breaks with 32bit calls.
	for (i=0; i<= max_nr_syscalls; i++) {
		if (syscalls[i].flags & NI_SYSCALL) {
			ret = syscall(i);
			if (ret == -1) {
				if (errno != ENOSYS) {
					printf("syscall %d (%s) should be ni_syscall, but returned %d(%s) !\n",
						i, syscalls[i].name, errno, strerror(errno));
					exit(EXIT_FAILURE);
				}
			}
		}
	}
	*/

	run_setup();

	sigsetjmp(ret_jump, 1);

	run_mode();

	if (structptr!=NULL)
		free(structptr);

	printf("\nRan %lld syscalls (%ld retries). Successes: %ld  Failures: %ld\n",
		execcount, shm->retries, shm->successes, shm->failures);

	exit(EXIT_SUCCESS);
}
