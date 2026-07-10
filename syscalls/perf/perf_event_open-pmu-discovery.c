/*
 * perf_event_open: PMU enumeration + tracepoint-id pool builder.
 *
 * Walks /sys/bus/event_source/devices to populate pmus[] (the sysfs PMU
 * format / generic-event tables consumed by random_sysfs_config in
 * perf_event_open.c) and walks /sys/kernel/tracing/events (or the legacy
 * debugfs path) to populate tracepoint_ids[] (the live id pool consumed
 * by random_tracepoint_config below).  Both populators are driven from
 * init_pmus, which the syscall_perf_event_open dispatch table reaches
 * through the .init hook.
 */

#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "perf.h"
#include "perf_event_open-internal.h"
#include "random.h"
#include "rnd.h"
#include "trinity.h"
#include "utils.h"

#define SYSFS "/sys/bus/event_source/devices/"

/* Not static so other tools can access the PMU data */
int num_pmus=0;
struct pmu_type *pmus=NULL;


static int parse_format(const char *string, int *field_type, unsigned long long *mask) {

	int i, secondnum, bits;
	char format_string[BUFSIZ];

	*mask=0;

	/* get format */
	/* according to Documentation/ABI/testing/sysfs-bus-event_source-devices-format */
	/* the format is something like config1:1,6-10,44 */

	i=0;
	while(1) {
		if (i >= BUFSIZ - 1) {
			format_string[i]=0;
			break;
		}
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

		/*
		 * The bit position is fed straight into a 64-bit shift below,
		 * so a sysfs descriptor with a position > 63 (or one whose
		 * digit accumulator overflowed signed int into negatives) would
		 * invoke shift UB.  Reject before we touch the shift.
		 */
		if (firstnum < 0 || firstnum > 63) {
			outputerr("PMU format start bit out of range: %d\n",
				firstnum);
			return -1;
		}

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
			if (secondnum < firstnum || secondnum > 63) {
				outputerr("PMU format end bit out of range: %d-%d\n",
					firstnum, secondnum);
				return -1;
			}
			bits=(secondnum-firstnum)+1;
		}

		/*
		 * bits feeds (1ULL << bits) below; shifts by >=64 (or negative)
		 * are UB in C.  64 is the special-cased all-ones path.
		 */
		if (bits <= 0 || bits > 64) {
			outputerr("PMU format bit count out of range: %d\n",
				bits);
			return -1;
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
			if (i >= BUFSIZ - 1) {
				field[i]=0;
				break;
			}
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


/*
 * Raw open/read/close one-shot reader.  Replaces the fopen/fscanf/fclose
 * sites below: avoids stdio's per-call FILE struct + IO buffer malloc and
 * its internal locking, matching the project convention for procfs/sysfs
 * oracle reads.  Returns the number of bytes read into @buf (NUL-terminator
 * always appended on success), or -1 on open / read failure.  Caller does
 * its own parsing via sscanf().
 */
static ssize_t read_sysfs_value(const char *path, char *buf, size_t bufsz)
{
	ssize_t n;
	int fd;

	if (bufsz == 0)
		return -1;
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	n = read(fd, buf, bufsz - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = '\0';
	return n;
}

/*
 * Tear down a partially-built pmus[] array.  Called from the
 * mid-loop early-return paths in init_pmus (when a formats[] or
 * generic_events[] calloc fails after one or more prior PMU slots
 * have already been populated) and from the final failure-exit too.
 * Frees in the inverse order of construction; each member is
 * NULL-safe so partial-loop states (name set but formats not yet
 * allocated) are handled.  *p is reset to NULL on return so the
 * caller's stored handle doesn't dangle.
 */
static void free_pmus(struct pmu_type **p, int n)
{
	struct pmu_type *arr = *p;
	int i, j;

	if (arr == NULL)
		return;

	for (i = 0; i < n; i++) {
		if (arr[i].formats != NULL) {
			for (j = 0; j < arr[i].num_formats; j++) {
				free((char *) arr[i].formats[j].name);
				free((char *) arr[i].formats[j].value);
			}
			free(arr[i].formats);
		}
		if (arr[i].generic_events != NULL) {
			for (j = 0; j < arr[i].num_generic_events; j++) {
				free((char *) arr[i].generic_events[j].name);
				free((char *) arr[i].generic_events[j].value);
			}
			free(arr[i].generic_events);
		}
		free((char *) arr[i].name);
	}
	free(arr);
	*p = NULL;
}

static int scan_pmu_formats(int pmu_num, const char *dir_name)
{
	DIR *format_dir;
	struct dirent *format_entry;
	char format_name[BUFSIZ+7] = "";
	/* +1 so sscanf's %BUFSIZ width can write BUFSIZ chars + NUL */
	char format_value[BUFSIZ+1] = "";
	char temp_name[BUFSIZ*2] = "";
	char read_buf[BUFSIZ] = "";
	int format_num = 0;
	int result;

	snprintf(format_name, sizeof(format_name), "%s/format", dir_name);
	format_dir = opendir(format_name);
	if (format_dir == NULL) {
		/* Can be normal to have no format strings */
		return 0;
	}

	/* Count format strings */
	while (1) {
		format_entry = readdir(format_dir);
		if (format_entry == NULL) break;
		if (!strcmp(".", format_entry->d_name)) continue;
		if (!strcmp("..", format_entry->d_name)) continue;
		pmus[pmu_num].num_formats++;
	}

	/* Allocate format structure */
	pmus[pmu_num].formats = calloc(pmus[pmu_num].num_formats,
					sizeof(struct format_type));
	if (pmus[pmu_num].formats == NULL) {
		pmus[pmu_num].num_formats = 0;
		closedir(format_dir);
		return -1;
	}

	/* Read format string info */
	rewinddir(format_dir);
	format_num = 0;
	while (1) {
		format_entry = readdir(format_dir);

		if (format_entry == NULL) break;
		if (!strcmp(".", format_entry->d_name)) continue;
		if (!strcmp("..", format_entry->d_name)) continue;

		if (format_num >= pmus[pmu_num].num_formats)
			break;

		pmus[pmu_num].formats[format_num].name =
			strdup(format_entry->d_name);
		if (!pmus[pmu_num].formats[format_num].name)
			continue;
		/*
		 * Clear per entry: the buffer is reused across the dir scan
		 * and would otherwise carry the prior entry's token if the
		 * sysfs read or sscanf parse below fails on a malformed /
		 * empty / whitespace-only descriptor file, causing parse_format
		 * to operate on a stale value strdup'd into the WRONG slot.
		 */
		format_value[0] = '\0';
		snprintf(temp_name, sizeof(temp_name), "%s/format/%s",
			dir_name, format_entry->d_name);
		if (read_sysfs_value(temp_name, read_buf,
				     sizeof(read_buf)) < 0)
			goto drop_format;
		result = sscanf(read_buf, "%" __stringify(BUFSIZ) "s",
			format_value);
		if (result != 1)
			goto drop_format;
		pmus[pmu_num].formats[format_num].value =
			strdup(format_value);
		if (!pmus[pmu_num].formats[format_num].value)
			goto drop_format;

		parse_format(format_value,
			&pmus[pmu_num].formats[format_num].field,
			&pmus[pmu_num].formats[format_num].mask);
		format_num++;
		continue;
drop_format:
		free((char *) pmus[pmu_num].formats[format_num].name);
		pmus[pmu_num].formats[format_num].name = NULL;
		free((char *) pmus[pmu_num].formats[format_num].value);
		pmus[pmu_num].formats[format_num].value = NULL;
	}
	closedir(format_dir);
	/*
	 * Clamp to slots actually populated -- random_sysfs_config()
	 * picks an index in [0, num_formats), and free_pmus() walks the
	 * same range, so a stale upper count would surface zeroed slots
	 * to the fuzzer and skip nothing on teardown.
	 */
	pmus[pmu_num].num_formats = format_num;
	return 0;
}

static int scan_pmu_generic_events(int pmu_num, const char *dir_name)
{
	DIR *event_dir;
	struct dirent *event_entry;
	char event_name[BUFSIZ+7] = "";
	/* +1 so sscanf's %BUFSIZ width can write BUFSIZ chars + NUL */
	char event_value[BUFSIZ+1] = "";
	char temp_name[BUFSIZ*2] = "";
	char read_buf[BUFSIZ] = "";
	int generic_num = 0;
	int result;

	snprintf(event_name, sizeof(event_name), "%s/events", dir_name);
	event_dir = opendir(event_name);
	if (event_dir == NULL) {
		/* It's sometimes normal to have no generic events */
		return 0;
	}

	/* Count generic events */
	while (1) {
		event_entry = readdir(event_dir);
		if (event_entry == NULL) break;
		if (!strcmp(".", event_entry->d_name)) continue;
		if (!strcmp("..", event_entry->d_name)) continue;
		pmus[pmu_num].num_generic_events++;
	}

	/* Allocate generic events */
	pmus[pmu_num].generic_events = calloc(
		pmus[pmu_num].num_generic_events,
		sizeof(struct generic_event_type));
	if (pmus[pmu_num].generic_events == NULL) {
		pmus[pmu_num].num_generic_events = 0;
		closedir(event_dir);
		return -1;
	}

	/* Read in generic events */
	rewinddir(event_dir);
	generic_num = 0;
	while (1) {
		event_entry = readdir(event_dir);
		if (event_entry == NULL) break;
		if (!strcmp(".", event_entry->d_name)) continue;
		if (!strcmp("..", event_entry->d_name)) continue;

		if (generic_num >= pmus[pmu_num].num_generic_events)
			break;

		pmus[pmu_num].generic_events[generic_num].name =
			strdup(event_entry->d_name);
		if (!pmus[pmu_num].generic_events[generic_num].name)
			continue;
		/*
		 * Clear per entry: the buffer is reused across the dir scan
		 * and would otherwise carry the prior entry's token if the
		 * sysfs read or sscanf parse below fails, causing parse_generic
		 * to operate on a stale value strdup'd into the WRONG slot.
		 */
		event_value[0] = '\0';
		snprintf(temp_name, sizeof(temp_name), "%s/events/%s",
			dir_name, event_entry->d_name);
		if (read_sysfs_value(temp_name, read_buf,
				     sizeof(read_buf)) < 0)
			goto drop_generic;
		result = sscanf(read_buf, "%" __stringify(BUFSIZ) "s",
			event_value);
		if (result != 1)
			goto drop_generic;
		pmus[pmu_num].generic_events[generic_num].value =
			strdup(event_value);
		if (!pmus[pmu_num].generic_events[generic_num].value)
			goto drop_generic;

		parse_generic(pmu_num, event_value,
				&pmus[pmu_num].generic_events[generic_num].config,
				&pmus[pmu_num].generic_events[generic_num].config1,
				&pmus[pmu_num].generic_events[generic_num].config2);
		generic_num++;
		continue;
drop_generic:
		free((char *) pmus[pmu_num].generic_events[generic_num].name);
		pmus[pmu_num].generic_events[generic_num].name = NULL;
		free((char *) pmus[pmu_num].generic_events[generic_num].value);
		pmus[pmu_num].generic_events[generic_num].value = NULL;
	}
	closedir(event_dir);
	/*
	 * Clamp to slots actually populated -- random_sysfs_config()
	 * picks an index in [0, num_generic_events) and free_pmus()
	 * walks the same range, so a stale upper count would expose
	 * zeroed slots to the fuzzer and skip nothing on teardown.
	 */
	pmus[pmu_num].num_generic_events = generic_num;
	return 0;
}

/*
 * Populate a single pmus[] slot from one /sys/bus/event_source/devices
 * entry.  Owns the PMU-dir setup -- name strdup, dir_name format, type
 * read -- then dispatches to scan_pmu_formats() and
 * scan_pmu_generic_events() for the two inner subdirectory walks.
 *
 * Returns 0 on success.  Returns 1 when the name strdup fails: the
 * original outer loop treated that as a soft stop (break, finish with
 * the PMUs gathered so far, init_pmus returns success), so callers
 * should break out of the readdir loop without doing pmu_num++ and
 * proceed to the success path.  Returns -1 when an inner scan helper
 * hits a calloc failure; callers reproduce the original bypass
 * cleanup (closedir outer dir, free_pmus, num_pmus=0, return -1).
 */
static int iter_pmu_dir(struct dirent *entry, int pmu_num)
{
	char dir_name[BUFSIZ] = "";
	char temp_name[BUFSIZ*2] = "";
	char read_buf[BUFSIZ] = "";
	int type;
	int result;

	/* read name */
	pmus[pmu_num].name = strdup(entry->d_name);
	if (!pmus[pmu_num].name)
		return 1;
	snprintf(dir_name, sizeof(dir_name), SYSFS"/%s",
		entry->d_name);

	/* read type */
	snprintf(temp_name, sizeof(temp_name), "%s/type", dir_name);
	if (read_sysfs_value(temp_name, read_buf, sizeof(read_buf)) >= 0) {
		result = sscanf(read_buf, "%d", &type);
		if (result == 1) pmus[pmu_num].type = type;
	}

	/***********************/
	/* Scan format strings */
	/***********************/
	if (scan_pmu_formats(pmu_num, dir_name) < 0)
		return -1;

	/***********************/
	/* Scan generic events */
	/***********************/
	if (scan_pmu_generic_events(pmu_num, dir_name) < 0)
		return -1;

	return 0;
}

/* Forward decl: the definition lives later in the file alongside the rest
 * of the tracepoint-pool helpers (random_tracepoint_config et al.) so the
 * pool, its scanner, and its picker stay co-located. */
static void init_tracepoint_ids(void);

int init_pmus(void)
{
	DIR *dir;
	struct dirent *entry;
	int pmu_num = 0;
	int result = -1;
	int rc;

	/* Seed the live tracepoint id pool used by random_tracepoint_config().
	 * Independent of PMU enumeration: a failure here (no tracefs mounted,
	 * empty events tree) is silently fine -- the pool stays empty and the
	 * picker drops to its random fallback. */
	init_tracepoint_ids();

	/* Count number of PMUs */
	/* This may break if PMUs are ever added/removed on the fly? */

	dir = opendir(SYSFS);
	if (dir == NULL) {
		return -1;
	}

	while (1) {
		entry = readdir(dir);
		if (entry == NULL) break;
		if (!strcmp(".", entry->d_name)) continue;
		if (!strcmp("..", entry->d_name)) continue;
		num_pmus++;
	}

	if (num_pmus < 1)
		goto out;

	pmus = calloc(num_pmus, sizeof(struct pmu_type));
	if (pmus == NULL)
		goto out;

	/****************/
	/* Add each PMU */
	/****************/

	rewinddir(dir);

	while (1) {
		entry = readdir(dir);
		if (entry == NULL) break;
		if (!strcmp(".", entry->d_name)) continue;
		if (!strcmp("..", entry->d_name)) continue;

		if (pmu_num >= num_pmus)
			break;

		rc = iter_pmu_dir(entry, pmu_num);
		if (rc < 0) {
			/*
			 * iter_pmu_dir owns the current slot's name strdup
			 * (always done first) and may have allocated formats[]
			 * with partial entries before the failing inner scan.
			 * Free pmu_num+1 so the partial slot doesn't leak.
			 */
			closedir(dir);
			free_pmus(&pmus, pmu_num + 1);
			num_pmus = 0;
			return -1;
		}
		if (rc > 0)
			break;
		pmu_num++;
	}

	/*
	 * num_pmus was the directory-entry count from the sizing pass; if a
	 * name strdup failed mid-population we broke early and trailing slots
	 * are zeroed placeholders.  random_sysfs_config() picks by num_pmus,
	 * so clamp it to what actually populated to keep the selector off the
	 * zeroed tail.
	 */
	num_pmus = pmu_num;

	result = 0;

out:
	if (dir != NULL)
		closedir(dir);
	if (result != 0) {
		free_pmus(&pmus, pmu_num);
		num_pmus = 0;
	}

	return result;
}

/*
 * Live tracepoint id pool, populated once at init time by walking
 * /sys/kernel/tracing/events (or the legacy /sys/kernel/debug/tracing
 * mount) and recording the integer in each event's "id" file.  The
 * random_event_config(PERF_TYPE_TRACEPOINT) path used to roll
 * rnd_u32() & 0xfff, which virtually never names a live tracepoint --
 * perf_tracepoint_event_init() bounces every random id with -ENOENT
 * before perf_trace_event_init() does anything interesting, so the
 * deep tracepoint init / perf_trace_buf_alloc / kprobe / uprobe paths
 * never see fuzz traffic.  Seeding from the live id pool lets
 * ~7/8 of TRACEPOINT picks resolve to a real event id; the remaining
 * 1/8 falls back to the random roll so the EINVAL/ENOENT validator
 * arms still get exercised.
 */
#define TRACEPOINT_POOL_CAP 4096

static unsigned int tracepoint_ids[TRACEPOINT_POOL_CAP];
static unsigned int num_tracepoint_ids;

static const char * const tracefs_roots[] = {
	"/sys/kernel/tracing/events",
	"/sys/kernel/debug/tracing/events",
};

static void scan_tracepoint_subsystem(const char *root, const char *subsys)
{
	char subsys_path[BUFSIZ];
	/* BUFSIZ*2: subsys_path (up to BUFSIZ) + "/" + d_name (up to NAME_MAX
	 * = 255) + "/id" + NUL fits comfortably; sized to match the rest of
	 * this file's path-building scratch buffers and silence FORTIFY's
	 * -Wformat-truncation on the snprintf below. */
	char id_path[BUFSIZ * 2];
	char read_buf[BUFSIZ];
	DIR *event_dir;
	struct dirent *event_entry;
	int id;

	snprintf(subsys_path, sizeof(subsys_path), "%s/%s", root, subsys);
	event_dir = opendir(subsys_path);
	if (event_dir == NULL)
		return;

	while (num_tracepoint_ids < TRACEPOINT_POOL_CAP) {
		event_entry = readdir(event_dir);
		if (event_entry == NULL)
			break;
		if (!strcmp(".", event_entry->d_name))
			continue;
		if (!strcmp("..", event_entry->d_name))
			continue;

		snprintf(id_path, sizeof(id_path), "%s/%s/id",
			subsys_path, event_entry->d_name);
		if (read_sysfs_value(id_path, read_buf, sizeof(read_buf)) < 0)
			continue;
		if (sscanf(read_buf, "%d", &id) != 1)
			continue;
		/* Tracepoint ids are small positive ints; the kernel rejects
		 * negative/huge values upstream, no point planting them. */
		if (id <= 0)
			continue;
		tracepoint_ids[num_tracepoint_ids++] = (unsigned int) id;
	}
	closedir(event_dir);
}

static void init_tracepoint_ids(void)
{
	DIR *root_dir;
	struct dirent *entry;
	size_t r;

	for (r = 0; r < ARRAY_SIZE(tracefs_roots); r++) {
		root_dir = opendir(tracefs_roots[r]);
		if (root_dir == NULL)
			continue;

		while (num_tracepoint_ids < TRACEPOINT_POOL_CAP) {
			entry = readdir(root_dir);
			if (entry == NULL)
				break;
			if (!strcmp(".", entry->d_name))
				continue;
			if (!strcmp("..", entry->d_name))
				continue;
			scan_tracepoint_subsystem(tracefs_roots[r], entry->d_name);
		}
		closedir(root_dir);
		/* Found a tracefs mount and walked it -- no need to walk the
		 * legacy debugfs path too (they expose the same id space). */
		if (num_tracepoint_ids > 0)
			return;
	}
}

unsigned long long random_tracepoint_config(void)
{
	/* ~7/8 from the live pool when populated.  Empty pool (no tracefs,
	 * no CONFIG_TRACING, or the walk found zero events) drops straight
	 * through to the random fallback so this stays usable everywhere
	 * -- the structured perf_event_attr fill's TRACEPOINT variant
	 * plants this as an FT_PICKER, so a wedged picker would freeze the
	 * config slot to whatever the prior pass wrote. */
	if (num_tracepoint_ids > 0 && rnd_modulo_u32(8) != 0)
		return tracepoint_ids[rnd_modulo_u32(num_tracepoint_ids)];

	if (RAND_BOOL())
		return rnd_u32() & 0xfff;
	return rand64();
}
