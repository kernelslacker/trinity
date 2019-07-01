/*
 * SYSCALL_DEFINE5(perf_event_open,
	 struct perf_event_attr __user *, attr_uptr,
	 pid_t, pid, int, cpu, int, group_fd, unsigned long, flags)
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include "maps.h"
#include "perf.h"
#include "perf_event.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"
#include "compat.h"
#include <time.h>

#define SYSFS "/sys/bus/event_source/devices/"

struct generic_event_type {
	const char *name;
	const char *value;
	long long config;
	long long config1;
	long long config2;
};

struct format_type {
	const char *name;
	const char *value;
	int field;
	unsigned long long mask;
};

struct pmu_type {
	const char *name;
	int type;
	int num_formats;
	int num_generic_events;
	struct format_type *formats;
	struct generic_event_type *generic_events;
};

/* Not static so other tools can access the PMU data */
int num_pmus=0;
struct pmu_type *pmus=NULL;


#define FIELD_UNKNOWN	0
#define FIELD_CONFIG	1
#define FIELD_CONFIG1	2
#define FIELD_CONFIG2	3
#define MAX_FIELDS	4


static int parse_format(const char *string, int *field_type, unsigned long long *mask) {

	int i, secondnum, bits;
	char format_string[BUFSIZ];

	*mask=0;

	/* get format */
	/* according to Documentation/ABI/testing/sysfs-bus-event_source-devices-format */
	/* the format is something like config1:1,6-10,44 */

	i=0;
	while(1) {
		format_string[i]=string[i];
		if (string[i]==':') {
			format_string[i]=0;
			break;
		}
		if (string[i]==0) break;
		i++;
	}

	if (!strcmp(format_string,"config")) {
		*field_type=FIELD_CONFIG;
	} else if (!strcmp(format_string,"config1")) {
		*field_type=FIELD_CONFIG1;
	} else if (!strcmp(format_string,"config2")) {
		*field_type=FIELD_CONFIG2;
	}
	else {
		*field_type=FIELD_UNKNOWN;
	}

	while(1) {
		int firstnum, shift;

		/* Read first number */
		i++;
		firstnum=0;
		while(1) {
			if (string[i]==0) break;
			if (string[i]=='-') break;
			if (string[i]==',') break;
			if ((string[i]<'0') || (string[i]>'9')) {
				outputerr("Unknown format char %c\n", string[i]);
				return -1;
			}
			firstnum*=10;
			firstnum+=(string[i])-'0';
			i++;
		}
		shift=firstnum;

		/* check if no second num */
		if ((string[i]==0) || (string[i]==',')) {
			bits=1;
		}
		else {
			/* Read second number */
			i++;
			secondnum=0;
			while(1) {
				if (string[i]==0) break;
				if (string[i]=='-') break;
				if (string[i]==',') break;
				if ((string[i]<'0') || (string[i]>'9')) {
					outputerr("Unknown format char %c\n", string[i]);
					return -1;
				}
				secondnum*=10;
				secondnum+=(string[i])-'0';
				i++;
			}
			bits=(secondnum-firstnum)+1;
		}

		if (bits==64) {
			*mask=0xffffffffffffffffULL;
		} else {
			*mask|=((1ULL<<bits)-1)<<shift;
		}

		if (string[i]==0) break;

	}
	return 0;
}

static unsigned long long separate_bits(unsigned long long value,
					unsigned long long mask) {

	int value_bit=0,i;
	unsigned long long result=0;

	for(i=0;i<64;i++) {
		if ((1ULL<<i)&mask) {
			result|=((value>>value_bit)&1)<<i;
			value_bit++;
		}
	}

	return result;
}

static int update_configs(int pmu, const char *field,
			long long value,
			long long *c,
			long long *c1,
			long long *c2) {

	int i;

	for(i=0;i<pmus[pmu].num_formats;i++) {
		if (!strcmp(field,pmus[pmu].formats[i].name)) {
			if (pmus[pmu].formats[i].field==FIELD_CONFIG) {
				*c|=separate_bits(value,
						pmus[pmu].formats[i].mask);
				return 0;
			}

			if (pmus[pmu].formats[i].field==FIELD_CONFIG1) {
				*c1|=separate_bits(value,
						pmus[pmu].formats[i].mask);
				return 0;
			}

			if (pmus[pmu].formats[i].field==FIELD_CONFIG2) {
				*c2|=separate_bits(value,
						pmus[pmu].formats[i].mask);
				return 0;
			}

		}
	}

	return 0;
}

static int parse_generic(int pmu, const char *value,
			long long *config, long long *config1, long long *config2) {

	long long c=0,c1=0,c2=0,temp;
	char field[BUFSIZ];
	int ptr=0;
	int base=10;

	while(1) {
		int i;
		i=0;
		while(1) {
			field[i]=value[ptr];
			if (value[ptr]==0) break;
			if ((value[ptr]=='=') || (value[ptr]==',')) {
				field[i]=0;
				break;
			}
			i++;
			ptr++;
		}

		/* if at end, was parameter w/o value */
		/* So it is a flag with a value of 1  */
		if ((value[ptr]==',') || (value[ptr]==0)) {
			temp=0x1;
		}
		else {
			/* get number */

			base=10;

			ptr++;

			if (value[ptr]=='0') {
				if (value[ptr+1]=='x') {
					ptr++;
					ptr++;
					base=16;
				}
			}
			temp=0x0;
			while(1) {

				if (value[ptr]==0) break;
				if (value[ptr]==',') break;
				if (! ( ((value[ptr]>='0') && (value[ptr]<='9'))
					|| ((value[ptr]>='a') && (value[ptr]<='f'))
					|| ((value[ptr]>='A') && (value[ptr]<='F'))) ) {
					outputerr("Unexpected char %c\n", value[ptr]);
				}
				temp*=base;
				if ((value[ptr]>='0') && (value[ptr]<='9')) {
					temp+=value[ptr]-'0';
				}
				else if ((value[ptr]>='a') && (value[ptr]<='f')) {
					temp+=(value[ptr]-'a')+10;
				}
				else {
					temp+=(value[ptr]-'A')+10;
				}
				i++;
				ptr++;
			}
		}
		update_configs(pmu,field,temp,&c,&c1,&c2);
		if (value[ptr]==0) break;
		ptr++;
	}
	*config=c;
	*config1=c1;
	*config2=c2;
	return 0;
}


static int init_pmus(void) {

	DIR *dir,*event_dir,*format_dir;
	struct dirent *entry,*event_entry,*format_entry;
	char dir_name[BUFSIZ] = "";
	char event_name[BUFSIZ+7] = "";
	char event_value[BUFSIZ] = "";
	char temp_name[BUFSIZ*2] = "";
	char format_name[BUFSIZ+7] = "";
	char format_value[BUFSIZ] = "";
	int type,pmu_num=0,format_num=0,generic_num=0;
	FILE *fff;
	int result = -1;


	/* Count number of PMUs */
	/* This may break if PMUs are ever added/removed on the fly? */

	dir=opendir(SYSFS);
	if (dir==NULL) {
		return -1;
	}

	while(1) {
		entry=readdir(dir);
		if (entry==NULL) break;
		if (!strcmp(".",entry->d_name)) continue;
		if (!strcmp("..",entry->d_name)) continue;
		num_pmus++;
	}

	if (num_pmus<1)
		goto out;

	pmus=calloc(num_pmus,sizeof(struct pmu_type));
	if (pmus==NULL)
		goto out;

	/****************/
	/* Add each PMU */
	/****************/

	rewinddir(dir);

	while(1) {
		entry=readdir(dir);
		if (entry==NULL) break;
		if (!strcmp(".",entry->d_name)) continue;
		if (!strcmp("..",entry->d_name)) continue;

		/* read name */
		pmus[pmu_num].name=strdup(entry->d_name);
		sprintf(dir_name,SYSFS"/%s",
			entry->d_name);

		/* read type */
		sprintf(temp_name,"%s/type",dir_name);
		fff=fopen(temp_name,"r");
		if (fff==NULL) {
		}
		else {
			result=fscanf(fff,"%d",&type);
			if (result==1) pmus[pmu_num].type=type;
			fclose(fff);
		}

		/***********************/
		/* Scan format strings */
		/***********************/
		sprintf(format_name,"%s/format",dir_name);
		format_dir=opendir(format_name);
		if (format_dir==NULL) {
			/* Can be normal to have no format strings */
		}
		else {
			/* Count format strings */
			while(1) {
				format_entry=readdir(format_dir);
				if (format_entry==NULL) break;
				if (!strcmp(".",format_entry->d_name)) continue;
				if (!strcmp("..",format_entry->d_name)) continue;
				pmus[pmu_num].num_formats++;
			}

			/* Allocate format structure */
			pmus[pmu_num].formats=calloc(pmus[pmu_num].num_formats,
							sizeof(struct format_type));
			if (pmus[pmu_num].formats==NULL) {
				pmus[pmu_num].num_formats=0;
				closedir(dir);
				closedir(format_dir);
				return -1;
			}

			/* Read format string info */
			rewinddir(format_dir);
			format_num=0;
			while(1) {
				format_entry=readdir(format_dir);

				if (format_entry==NULL) break;
				if (!strcmp(".",format_entry->d_name)) continue;
				if (!strcmp("..",format_entry->d_name)) continue;

				pmus[pmu_num].formats[format_num].name=
					strdup(format_entry->d_name);
				sprintf(temp_name,"%s/format/%s",
					dir_name,format_entry->d_name);
				fff=fopen(temp_name,"r");
				if (fff!=NULL) {
					result=fscanf(fff,"%s",format_value);
					if (result==1) { 
						pmus[pmu_num].formats[format_num].value=
						strdup(format_value);
					}
					fclose(fff);

					parse_format(format_value,
						&pmus[pmu_num].formats[format_num].field,
						&pmus[pmu_num].formats[format_num].mask);
					format_num++;
				}
			}
			closedir(format_dir);
		}

		/***********************/
		/* Scan generic events */
		/***********************/
		sprintf(event_name,"%s/events",dir_name);
		event_dir=opendir(event_name);
		if (event_dir==NULL) {
			/* It's sometimes normal to have no generic events */
		}
		else {

			/* Count generic events */
			while(1) {
				event_entry=readdir(event_dir);
				if (event_entry==NULL) break;
				if (!strcmp(".",event_entry->d_name)) continue;
				if (!strcmp("..",event_entry->d_name)) continue;
				pmus[pmu_num].num_generic_events++;
			}

			/* Allocate generic events */
			pmus[pmu_num].generic_events=calloc(
				pmus[pmu_num].num_generic_events,
				sizeof(struct generic_event_type));
			if (pmus[pmu_num].generic_events==NULL) {
				pmus[pmu_num].num_generic_events=0;
				closedir(dir);
				closedir(event_dir);
				return -1;
			}

			/* Read in generic events */
			rewinddir(event_dir);
			generic_num=0;
			while(1) {
				event_entry=readdir(event_dir);
				if (event_entry==NULL) break;
				if (!strcmp(".",event_entry->d_name)) continue;
				if (!strcmp("..",event_entry->d_name)) continue;

				pmus[pmu_num].generic_events[generic_num].name=
					strdup(event_entry->d_name);
				sprintf(temp_name,"%s/events/%s",
					dir_name,event_entry->d_name);
				fff=fopen(temp_name,"r");
				if (fff!=NULL) {
					result=fscanf(fff,"%s",event_value);
					if (result==1) {
						pmus[pmu_num].generic_events[generic_num].value=
							strdup(event_value);
					}
					fclose(fff);
				}
				parse_generic(pmu_num,event_value,
						&pmus[pmu_num].generic_events[generic_num].config,
						&pmus[pmu_num].generic_events[generic_num].config1,
						&pmus[pmu_num].generic_events[generic_num].config2);
				generic_num++;
			}
			closedir(event_dir);
		}
		pmu_num++;
	}

	result = 0;

out:
	closedir(dir);

	return result;
}


static long long random_sysfs_config(__u32 *type,
				__u64 *config1,
				__u64 *config2) {

	int i,j;
	long long c=0,c1=0,c2=0;

	if (num_pmus==0) {
		/* For some reason we didn't get initialized */
		/* Fake it so we don't divide by zero        */
		*type=rand32();
		*config1=rand64();
		return rand64();
	}

	i=rnd()%num_pmus;

	*type=pmus[i].type;

	switch(rnd()%3) {
		/* Random by Format */
		case 0:
			if (pmus[i].num_formats==0) goto out;
			for(j=0;j<pmus[i].num_formats;j++) {
				/* 50% chance of having field set */
				if (rnd()%2) {
					if (pmus[i].formats[j].field==FIELD_CONFIG) {
						c|=(rand64()&pmus[i].formats[j].mask);
					} else if (pmus[i].formats[j].field==FIELD_CONFIG1) {
						c1|=(rand64()&pmus[i].formats[j].mask);
					} else {
						c2|=(rand64()&pmus[i].formats[j].mask);
					}
				}
			}
			break;


		/* Random by generic event */
		case 1:
			if (pmus[i].num_generic_events==0) goto out;
			j=rnd()%pmus[i].num_generic_events;
			c=pmus[i].generic_events[j].config;
			c1=pmus[i].generic_events[j].config1;
			c2=pmus[i].generic_events[j].config2;
			break;

		case 2:
			goto out;
			break;

		default:
			goto out;
			break;
	}
	*config1=c1;
	*config2=c2;
	return c;
out:
	*config1=rnd()%64;
	return rnd()%64;
}

/* arbitrary high number unlikely to be used by perf_event */
#define PERF_TYPE_READ_FROM_SYSFS 1027


static long long random_cache_config(void)
{

	int cache_id, hw_cache_op_id, hw_cache_op_result_id;

	switch (rnd() % 8) {
	case 0:
		cache_id = PERF_COUNT_HW_CACHE_L1D;
		break;
	case 1:
		cache_id = PERF_COUNT_HW_CACHE_L1I;
		break;
	case 2:
		cache_id = PERF_COUNT_HW_CACHE_LL;
		break;
	case 3:
		cache_id = PERF_COUNT_HW_CACHE_DTLB;
		break;
	case 4:
		cache_id = PERF_COUNT_HW_CACHE_ITLB;
		break;
	case 5:
		cache_id = PERF_COUNT_HW_CACHE_BPU;
		break;
	case 6:
		cache_id = PERF_COUNT_HW_CACHE_NODE;
		break;
	case 7:
		cache_id = RAND_BYTE();
		break;
	default:
		cache_id = 0;
		break;
	}

	switch (rnd() % 4) {
	case 0:
		hw_cache_op_id = PERF_COUNT_HW_CACHE_OP_READ;
		break;
	case 1:
		hw_cache_op_id = PERF_COUNT_HW_CACHE_OP_WRITE;
		break;
	case 2:
		hw_cache_op_id = PERF_COUNT_HW_CACHE_OP_PREFETCH;
		break;
	case 3:
		hw_cache_op_id = RAND_BYTE();
		break;
	default:
		hw_cache_op_id = 0;
		break;
	}

	switch (rnd() % 3) {
	case 0:
		hw_cache_op_result_id = PERF_COUNT_HW_CACHE_RESULT_ACCESS;
		break;
	case 1:
		hw_cache_op_result_id = PERF_COUNT_HW_CACHE_RESULT_MISS;
		break;
	case 2:
		hw_cache_op_result_id = RAND_BYTE();
		break;
	default:
		hw_cache_op_result_id = 0;
		break;
	}

	return (cache_id) | (hw_cache_op_id << 8) | (hw_cache_op_result_id << 16);
}

static int random_event_type(void)
{

	int type=0;

	switch (rnd() % 8) {
	case 0:
		type = PERF_TYPE_HARDWARE;
		break;
	case 1:
		type = PERF_TYPE_SOFTWARE;
		break;
	case 2:
		type = PERF_TYPE_TRACEPOINT;
		break;
	case 3:
		type = PERF_TYPE_HW_CACHE;
		break;
	case 4:
		type = PERF_TYPE_RAW;
		break;
	case 5:
		type = PERF_TYPE_BREAKPOINT;
		break;
	case 6:
		type = PERF_TYPE_READ_FROM_SYSFS;
		break;
	case 7:
		type = rand32();
		break;
	default:
		break;
	}
	return type;
}

static long long random_event_config(__u32 *event_type,
					__u64 *config1,
					__u64 *config2)
{
	unsigned long long config=0;

	switch (*event_type) {
	case PERF_TYPE_HARDWARE:
		switch (rnd() % 11) {
		case 0:
			config = PERF_COUNT_HW_CPU_CYCLES;
			break;
		case 1:
			config = PERF_COUNT_HW_INSTRUCTIONS;
			break;
		case 2:
			config = PERF_COUNT_HW_CACHE_REFERENCES;
			break;
		case 3:
			config = PERF_COUNT_HW_CACHE_MISSES;
			break;
		case 4:
			config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
			break;
		case 5:
			config = PERF_COUNT_HW_BRANCH_MISSES;
			break;
		case 6:
			config = PERF_COUNT_HW_BUS_CYCLES;
			break;
		case 7:
			config = PERF_COUNT_HW_STALLED_CYCLES_FRONTEND;
			break;
		case 8:
			config = PERF_COUNT_HW_STALLED_CYCLES_BACKEND;
			break;
		case 9:
			config = PERF_COUNT_HW_REF_CPU_CYCLES;
			break;
		case 10:
			config = rand64();
			break;
		default:
			break;
		}
		break;
	case PERF_TYPE_SOFTWARE:
		switch (rnd() % 12) {
		case 0:
			config = PERF_COUNT_SW_CPU_CLOCK;
			break;
		case 1:
			config = PERF_COUNT_SW_TASK_CLOCK;
			break;
		case 2:
			config = PERF_COUNT_SW_PAGE_FAULTS;
			break;
		case 3:
			config = PERF_COUNT_SW_CONTEXT_SWITCHES;
			break;
		case 4:
			config = PERF_COUNT_SW_CPU_MIGRATIONS;
			break;
		case 5:
			config = PERF_COUNT_SW_PAGE_FAULTS_MIN;
			break;
		case 6:
			config = PERF_COUNT_SW_PAGE_FAULTS_MAJ;
			break;
		case 7:
			config = PERF_COUNT_SW_ALIGNMENT_FAULTS;
			break;
		case 8:
			config = PERF_COUNT_SW_EMULATION_FAULTS;
			break;
		case 9:
			config = PERF_COUNT_SW_DUMMY;
			break;
		case 10:
			config = PERF_COUNT_SW_BPF_OUTPUT;
			break;
		case 11:
			config = rand64();
			break;
		default:
			break;
		}
		break;
	case PERF_TYPE_TRACEPOINT:
		/* Actual values to use can be found under */
		/* debugfs tracing/events/?*?/?*?/id       */
		/* usually a small < 4096 number           */
		switch(rnd()%2) {
		case 0:
			/* Try a value < 4096 */
			config = rnd()&0xfff;
			break;
		case 1:
			config = rand64();
			break;
		default:
			config = rand64();
			break;
		}
		break;
	case PERF_TYPE_HW_CACHE:
		config = random_cache_config();
		break;
	case PERF_TYPE_RAW:
		/* can be arbitrary 64-bit value */
		/* there are some constraints we can add */
		/* to make it more likely to be a valid event */
		config = rand64();
		break;
	case PERF_TYPE_BREAKPOINT:
		/* Breakpoint type only valid if config==0 */
		/* Set it to something else too anyway     */
		if (RAND_BOOL())
			config = rand64();
		else
			config = 0;
		break;

	case PERF_TYPE_READ_FROM_SYSFS:
		config = random_sysfs_config(event_type,config1,config2);
		break;

	default:
		config = rand64();
		*config1 = rand64();
		*config2 = rand64();
		break;
	}
	return config;
}

static void setup_breakpoints(struct perf_event_attr *attr)
{

	switch (rnd() % 6) {
	case 0:
		attr->bp_type = HW_BREAKPOINT_EMPTY;
		break;
	case 1:
		attr->bp_type = HW_BREAKPOINT_R;
		break;
	case 2:
		attr->bp_type = HW_BREAKPOINT_W;
		break;
	case 3:
		attr->bp_type = HW_BREAKPOINT_RW;
		break;
	case 4:
		attr->bp_type = HW_BREAKPOINT_X;
		break;
	case 5:
		attr->bp_type = rand32();
		break;
	default:
		break;
	}

	/* This might be more interesting if this were    */
	/* a valid executable address for HW_BREAKPOINT_X */
	/* or a valid mem location for R/W/RW             */
	attr->bp_addr = (long)get_address();

	switch (rnd() % 5) {
	case 0:
		attr->bp_len = HW_BREAKPOINT_LEN_1;
		break;
	case 1:
		attr->bp_len = HW_BREAKPOINT_LEN_2;
		break;
	case 2:
		attr->bp_len = HW_BREAKPOINT_LEN_4;
		break;
	case 3:
		attr->bp_len = HW_BREAKPOINT_LEN_8;
		break;
	case 4:
		attr->bp_len = rand64();
		break;
	default:
		break;
	}
}

static long long random_sample_type(void)
{

	long long sample_type = 0;

	if (RAND_BOOL())
		return rand64();

	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_IP;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_TID;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_TIME;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_ADDR;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_READ;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_CALLCHAIN;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_ID;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_CPU;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_PERIOD;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_STREAM_ID;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_RAW;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_BRANCH_STACK;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_REGS_USER;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_STACK_USER;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_WEIGHT;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_DATA_SRC;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_IDENTIFIER;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_TRANSACTION;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_REGS_INTR;
	if (RAND_BOOL())
		sample_type |= PERF_SAMPLE_PHYS_ADDR;

	return sample_type;
}

static long long random_read_format(void)
{

	long long read_format = 0;

	if (RAND_BOOL())
		return rand64();

	if (RAND_BOOL())
		read_format |= PERF_FORMAT_GROUP;
	if (RAND_BOOL())
		read_format |= PERF_FORMAT_ID;
	if (RAND_BOOL())
		read_format |= PERF_FORMAT_TOTAL_TIME_ENABLED;
	if (RAND_BOOL())
		read_format |= PERF_FORMAT_TOTAL_TIME_RUNNING;

	return read_format;
}

static int random_attr_size(void) {

	int size=0;

	switch(rnd() % 10) {
	case 0:	size = PERF_ATTR_SIZE_VER0;
		break;
	case 1: size = PERF_ATTR_SIZE_VER1;
		break;
	case 2: size = PERF_ATTR_SIZE_VER2;
		break;
	case 3: size = PERF_ATTR_SIZE_VER3;
		break;
	case 4: size = PERF_ATTR_SIZE_VER4;
		break;
	case 5: size = PERF_ATTR_SIZE_VER5;
		break;
	case 6: size = sizeof(struct perf_event_attr);
		break;
	case 7: size = rand32();
		break;
	case 8:	size = get_len();
		break;
	case 9: size = 0;
		break;
	default:
		break;
	}

	return size;
}

static long long random_branch_sample_type(void)
{

	long long branch_sample = 0;

	if (RAND_BOOL())
		return rand64();

	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_USER;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_KERNEL;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_HV;

	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_ANY;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_ANY_CALL;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_ANY_RETURN;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_IND_CALL;

	/* Transactional Memory Types */
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_ABORT_TX;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_IN_TX;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_NO_TX;


	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_COND;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_CALL_STACK;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_IND_JUMP;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_CALL;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_NO_FLAGS;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_NO_CYCLES;
	if (RAND_BOOL())
		branch_sample |= PERF_SAMPLE_BRANCH_TYPE_SAVE;


	return branch_sample;
}


static void create_mostly_valid_counting_event(struct perf_event_attr *attr,
						int group_leader)
{

	attr->type = random_event_type();
	attr->size = random_attr_size();
	attr->config = random_event_config(&attr->type,
					&attr->config1,
					&attr->config2);

	/* no freq for counting event */
	/* no sample type for counting event */

	attr->read_format = random_read_format();

	/* Bitfield parameters, mostly boolean */
	attr->disabled = RAND_BOOL();
	attr->inherit = RAND_BOOL();
	if (group_leader) {
		attr->pinned = RAND_BOOL();
	}
	attr->exclusive = RAND_BOOL();
	attr->exclude_user = RAND_BOOL();
	attr->exclude_kernel = RAND_BOOL();
	attr->exclude_hv = RAND_BOOL();
	attr->exclude_idle = RAND_BOOL();
	attr->mmap = RAND_BOOL();
	attr->comm = RAND_BOOL();
	attr->freq = RAND_BOOL();
	attr->inherit_stat = RAND_BOOL();
	attr->enable_on_exec = RAND_BOOL();
	attr->task = RAND_BOOL();
	attr->watermark = RAND_BOOL();
	attr->precise_ip = rnd() % 4;	// two bits
	attr->mmap_data = RAND_BOOL();
	attr->sample_id_all = RAND_BOOL();
	attr->exclude_host = RAND_BOOL();
	attr->exclude_guest = RAND_BOOL();
	attr->exclude_callchain_kernel = RAND_BOOL();
	attr->exclude_callchain_user = RAND_BOOL();
	attr->mmap2 = RAND_BOOL();
	attr->comm_exec = RAND_BOOL();
	attr->use_clockid = RAND_BOOL();
	attr->context_switch = RAND_BOOL();
	attr->write_backward = RAND_BOOL();

	/* wakeup events not relevant */

	/* breakpoint events unioned with config */
	if (attr->type == PERF_TYPE_BREAKPOINT) {
		setup_breakpoints(attr);
	} else {
		/* config1 set earlier */
		/* leave config2 alone for now */
	}

	/* branch_sample_type not relevant if not sampling */

	/* sample_regs_user not relevant if not sampling */

	/* sample_stack_user not relevant if not sampling */

	/* aux_watermark not relevant if not sampling */

	/* sample_max_stack not relevant if not sampling */
}

static void create_mostly_valid_sampling_event(struct perf_event_attr *attr,
						int group_leader)
{

	attr->type = random_event_type();
	attr->size = random_attr_size();
	attr->config = random_event_config(&attr->type,
					&attr->config1,
					&attr->config2);

	/* low values more likely to have "interesting" results */
	attr->sample_period = rand64();
	attr->sample_type = random_sample_type();
	attr->read_format = random_read_format();

	/* Bitfield parameters, mostly boolean */
	attr->disabled = RAND_BOOL();
	attr->inherit = RAND_BOOL();
	/* only group leaders can be pinned */
	if (group_leader) {
		attr->pinned = RAND_BOOL();
	} else {
		attr->pinned = 0;
	}
	attr->exclusive = RAND_BOOL();
	attr->exclude_user = RAND_BOOL();
	attr->exclude_kernel = RAND_BOOL();
	attr->exclude_hv = RAND_BOOL();
	attr->exclude_idle = RAND_BOOL();
	attr->mmap = RAND_BOOL();
	attr->comm = RAND_BOOL();
	attr->freq = RAND_BOOL();
	attr->inherit_stat = RAND_BOOL();
	attr->enable_on_exec = RAND_BOOL();
	attr->task = RAND_BOOL();
	attr->watermark = RAND_BOOL();
	attr->precise_ip = rnd() % 4;	// two bits
	attr->mmap_data = RAND_BOOL();
	attr->sample_id_all = RAND_BOOL();
	attr->exclude_host = RAND_BOOL();
	attr->exclude_guest = RAND_BOOL();
	attr->exclude_callchain_kernel = RAND_BOOL();
	attr->exclude_callchain_user = RAND_BOOL();
	attr->mmap2 = RAND_BOOL();
	attr->comm_exec = RAND_BOOL();
	attr->use_clockid = RAND_BOOL();
	attr->context_switch = RAND_BOOL();
	attr->write_backward = RAND_BOOL();

	attr->wakeup_events = rand32();

	if (attr->type == PERF_TYPE_BREAKPOINT) {
		setup_breakpoints(attr);
	}
	else {
		/* breakpoint fields unioned with config fields */
		/* config1 set earlier */
	}

	attr->branch_sample_type = random_branch_sample_type();

	/* sample_regs_user is a bitmask of CPU registers to record.     */
	/* The values come from arch/ARCH/include/uapi/asm/perf_regs.h   */
	/* Most architectures have fewer than 64 registers...            */
	switch(rnd()%3) {
		case 0:		attr->sample_regs_user = rnd()%16;
				break;
		case 1:		attr->sample_regs_user = rnd()%64;
				break;
		case 2:		attr->sample_regs_user = rand64();
				break;
		default:
				break;
	}

	/* sample_stack_user is the size of user stack backtrace we want  */
	/* if we pick too large of a value the kernel in theory truncates */
	attr->sample_stack_user = rand32();

	if (attr->use_clockid) {
		switch(rnd()%6) {
			case 0:	attr->clockid = CLOCK_MONOTONIC;
				break;
			case 1: attr->clockid = CLOCK_MONOTONIC_RAW;
				break;
			case 2: attr->clockid = CLOCK_REALTIME;
				break;
			case 3: attr->clockid = CLOCK_BOOTTIME;
				break;
			/* Most possible values < 32 */
			case 4: attr->clockid = RAND_BYTE();
				break;
			case 5:	attr->clockid = rnd();
				break;
		}
	}

	attr->aux_watermark = rand32();
	attr->sample_max_stack = rand32();
}


/* Creates a global event: one that is not per-process, but system-wide	*/
/* To be valid must be created with pid=-1 and cpu being a valid CPU.   */
/* Also usually only root can create these unless                       */
/*    /proc/sys/kernel/perf_event_paranoid is less than 1.              */
/* Most custom PMU types (uncore/northbridge/RAPL) are covered here.    */

static void create_mostly_valid_global_event(struct perf_event_attr *attr,
						int group_leader)
{

	attr->type = random_event_type();
	attr->size = random_attr_size();
	attr->config = random_event_config(&attr->type,
					&attr->config1,
					&attr->config2);

	attr->read_format = random_read_format();

	/* Bitfield parameters, mostly boolean */
	attr->disabled = RAND_BOOL();
	attr->inherit = RAND_BOOL();
	if (group_leader) {
		attr->pinned = RAND_BOOL();
	}

	/* Not setting most other paramaters */
	/* As they tend to be not valid in a global event */
}

/* Creates a completely random event, unlikely to be valid */
static void create_random_event(struct perf_event_attr *attr)
{

	attr->type = random_event_type();

	attr->size = random_attr_size();

	attr->config = random_event_config(&attr->type,
					&attr->config1,
					&attr->config2);

	attr->sample_period = rand64();
	attr->sample_type = random_sample_type();
	attr->read_format = random_read_format();

	/* bitfields */
	attr->disabled = RAND_BOOL();
	attr->inherit = RAND_BOOL();
	attr->pinned = RAND_BOOL();
	attr->exclusive = RAND_BOOL();
	attr->exclude_user = RAND_BOOL();
	attr->exclude_kernel = RAND_BOOL();
	attr->exclude_hv = RAND_BOOL();
	attr->exclude_idle = RAND_BOOL();
	attr->mmap = RAND_BOOL();
	attr->comm = RAND_BOOL();
	attr->freq = RAND_BOOL();
	attr->inherit_stat = RAND_BOOL();
	attr->enable_on_exec = RAND_BOOL();
	attr->task = RAND_BOOL();
	attr->watermark = RAND_BOOL();
	attr->precise_ip = rnd() % 4;
	attr->mmap_data = RAND_BOOL();
	attr->sample_id_all = RAND_BOOL();
	attr->exclude_host = RAND_BOOL();
	attr->exclude_guest = RAND_BOOL();
	attr->exclude_callchain_kernel = RAND_BOOL();
	attr->exclude_callchain_user = RAND_BOOL();
	attr->mmap2 = RAND_BOOL();
	attr->comm_exec = RAND_BOOL();

	attr->wakeup_events=rand32();

	/* Breakpoints are unioned with the config values */
	if (RAND_BOOL()) {
		setup_breakpoints(attr);
	}
	else {
		/* config1 set earlier */
		attr->config2 = rand64();
	}

	attr->branch_sample_type = rand64();
	attr->sample_regs_user = rand64();
	attr->sample_stack_user = rand32();

}

void sanitise_perf_event_open(struct syscallrecord *rec)
{
	struct perf_event_attr *attr;
	unsigned long flags;
	pid_t pid;
	int group_leader=0;
	void *addr;

	addr = zmalloc(sizeof(struct perf_event_attr));
	rec->a1 = (unsigned long) addr;
	attr = (struct perf_event_attr *) addr;

	/* cpu */
	/* requires ROOT to select specific CPU if pid==-1 (all processes) */
	/* -1 means all CPUs */

	if (RAND_BOOL()) {
		/* Any CPU */
		rec->a3 = -1;
	} else {
		/* Default to the get_cpu() value */
		/* set by ARG_CPU                 */
	}

	/* group_fd */
	/* should usually be -1 or another perf_event fd         */
	/* Anything but -1 unlikely to work unless the other pid */
	/* was properly set up to be a group master              */
	switch (rnd() % 3) {
	case 0:
		rec->a4 = -1;
		group_leader = 1;
		break;
	case 1:
		/* Try to get a previous random perf_event_open() fd  */
		rec->a4 = get_rand_perf_fd();
		break;
	case 2:
		/* Rely on ARG_FD */
		break;
	default:
		break;
	}

	/* flags */
	/* You almost never set these unless you're playing with cgroups */
	flags = 0;
	if (RAND_BOOL()) {
		flags = rand64();
	} else {
		if (RAND_BOOL())
			flags |= PERF_FLAG_FD_NO_GROUP;
		if (RAND_BOOL())
			flags |= PERF_FLAG_FD_OUTPUT;
		if (RAND_BOOL())
			flags |= PERF_FLAG_PID_CGROUP;
		if (RAND_BOOL())
			flags |= PERF_FLAG_FD_CLOEXEC;
	}
	rec->a5 = flags;

	/* pid */
	/* requires ROOT to select pid that doesn't belong to us */

	if (flags & PERF_FLAG_PID_CGROUP) {
		/* In theory in this case we should pass in */
		/* a file descriptor from /dev/cgroup       */
		pid = get_random_fd();
	} else {
		switch(rnd() % 4) {
		case 0:	/* use current thread */
			pid = 0;
			break;
		case 1: /* get an arbitrary pid */
			pid = get_pid();
			break;
		case 2:	/* measure *all* pids.  Might require root */
			pid = -1;
			break;
		case 3: /* measure our actual pid */
			pid=getpid();
			break;
		default:
			pid = 0;
			break;
		}
	}
	rec->a2 = pid;

	/* set up attr structure */
	switch (rnd() % 4) {
	case 0:
		create_mostly_valid_counting_event(attr,group_leader);
		break;
	case 1:
		create_mostly_valid_sampling_event(attr,group_leader);
		break;
	case 2:
		create_mostly_valid_global_event(attr,group_leader);
		break;
	case 3:
		create_random_event(attr);
		break;
	default:
		break;
	}
}

static void post_perf_event_open(struct syscallrecord *rec)
{
	freeptr(&rec->a1);
}

static unsigned long perf_event_open_flags[] = {
	PERF_FLAG_FD_NO_GROUP, PERF_FLAG_FD_OUTPUT, PERF_FLAG_PID_CGROUP,
};

struct syscallentry syscall_perf_event_open = {
	.name = "perf_event_open",
	.num_args = 5,
	.arg1name = "attr_uptr",
	.arg1type = ARG_ADDRESS,
	.arg2name = "pid",
	.arg2type = ARG_PID,
	.arg3name = "cpu",
	.arg3type = ARG_CPU,
	.arg4name = "group_fd",
	.arg4type = ARG_FD,
	.arg5name = "flags",
	.arg5type = ARG_LIST,
	.arg5list = ARGLIST(perf_event_open_flags),
	.sanitise = sanitise_perf_event_open,
	.post = post_perf_event_open,
	.init = init_pmus,
	.flags = NEED_ALARM | IGNORE_ENOSYS,
};
