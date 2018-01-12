#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>

int main()
{
	long s;
	long *p = (long*)mmap(NULL, 24 * 1024 * 1024, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS|MAP_HUGETLB, -1, 0);
	perror("mmap");
	*p = 0xbeafbeafbeafbeaf;
	printf("debug: pid = %lu, user_addr = %p, (*user_addr): %lx\n", getpid(), p, *p);
	scanf("%ld", &s);
        munmap(p, 24 * 1024 * 1024);
}

