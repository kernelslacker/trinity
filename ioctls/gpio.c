/* /dev/gpiochipN GPIO character device ioctl fuzzing.
 *
 * Sanitisers cover both the v2 line API (line_request, line_config,
 * line_attribute, line_values) and the deprecated v1 handle/event API
 * still exported by every in-tree driver.
 *
 * Gated by fd_test on /dev/gpiochip* — driving these blind on
 * board-management hosts is a brick risk.
 */

#include <linux/gpio.h>
#include <linux/ioctl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ioctls.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

/*
 * Keep these in sync with <linux/gpio.h>.  We mask user-supplied flag
 * values against these so the kernel rejects on the requested behaviour
 * rather than on EINVAL from a stray reserved bit.  Recomputing them
 * here is preferable to pulling random bits from rand64(): it keeps the
 * fuzz pressure on legal flag combinations where most of the parsing
 * complexity lives.
 */
#define GPIO_V2_LINE_VALID_FLAGS_MASK	0x1fffULL	/* bits 0..12 */
#define GPIOHANDLE_VALID_FLAGS_MASK	0xffUL		/* bits 0..7  */
#define GPIOEVENT_VALID_FLAGS_MASK	0x3UL		/* bits 0..1  */

static int gpio_fd_test(int fd, const struct stat *st)
{
	char path[64];
	char target[64];
	ssize_t n;

	if (!S_ISCHR(st->st_mode))
		return -1;

	(void) snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
	n = readlink(path, target, sizeof(target) - 1);
	if (n < 0)
		return -1;
	target[n] = '\0';

	if (strncmp(target, "/dev/gpiochip", 13) != 0)
		return -1;
	return 0;
}

static void sanitise_chipinfo(struct syscallrecord *rec)
{
	struct gpiochip_info *c;

	c = (struct gpiochip_info *) get_writable_struct(sizeof(*c));
	if (!c)
		return;
	memset(c, 0, sizeof(*c));
	rec->a3 = (unsigned long) c;
}

static void sanitise_lineinfo_unwatch(struct syscallrecord *rec)
{
	__u32 *off;

	off = (__u32 *) get_writable_struct(sizeof(*off));
	if (!off)
		return;
	*off = rand() % 256;
	rec->a3 = (unsigned long) off;
}

#ifdef GPIO_V2_GET_LINEINFO_IOCTL
static void fill_v2_line_attr(struct gpio_v2_line_attribute *a)
{
	a->id = (rand() % 3) + 1;	/* FLAGS, OUTPUT_VALUES, DEBOUNCE */
	a->padding = 0;

	switch (a->id) {
	case GPIO_V2_LINE_ATTR_ID_FLAGS:
		a->flags = rand64() & GPIO_V2_LINE_VALID_FLAGS_MASK;
		break;
	case GPIO_V2_LINE_ATTR_ID_OUTPUT_VALUES:
		a->values = rand64();
		break;
	case GPIO_V2_LINE_ATTR_ID_DEBOUNCE:
		a->debounce_period_us = rand();
		break;
	}
}

static void fill_v2_line_config(struct gpio_v2_line_config *c)
{
	unsigned int i;

	memset(c, 0, sizeof(*c));
	c->flags = rand64() & GPIO_V2_LINE_VALID_FLAGS_MASK;
	c->num_attrs = rand() % (GPIO_V2_LINE_NUM_ATTRS_MAX + 1);
	for (i = 0; i < c->num_attrs; i++) {
		fill_v2_line_attr(&c->attrs[i].attr);
		c->attrs[i].mask = rand64();
	}
}

static void sanitise_v2_lineinfo(struct syscallrecord *rec)
{
	struct gpio_v2_line_info *info;

	info = (struct gpio_v2_line_info *) get_writable_struct(sizeof(*info));
	if (!info)
		return;
	memset(info, 0, sizeof(*info));
	info->offset = rand() % 256;
	rec->a3 = (unsigned long) info;
}

static void sanitise_v2_line_request(struct syscallrecord *rec)
{
	struct gpio_v2_line_request *r;
	unsigned int i;

	r = (struct gpio_v2_line_request *) get_writable_struct(sizeof(*r));
	if (!r)
		return;
	memset(r, 0, sizeof(*r));
	r->num_lines = (rand() % GPIO_V2_LINES_MAX) + 1;
	for (i = 0; i < r->num_lines; i++)
		r->offsets[i] = rand() % 256;
	r->event_buffer_size = rand() % 4096;
	fill_v2_line_config(&r->config);
	r->fd = -1;
	rec->a3 = (unsigned long) r;
}

static void sanitise_v2_line_config(struct syscallrecord *rec)
{
	struct gpio_v2_line_config *c;

	c = (struct gpio_v2_line_config *) get_writable_struct(sizeof(*c));
	if (!c)
		return;
	fill_v2_line_config(c);
	rec->a3 = (unsigned long) c;
}

static void sanitise_v2_line_values(struct syscallrecord *rec)
{
	struct gpio_v2_line_values *v;

	v = (struct gpio_v2_line_values *) get_writable_struct(sizeof(*v));
	if (!v)
		return;
	v->bits = rand64();
	v->mask = rand64();
	rec->a3 = (unsigned long) v;
}
#endif /* GPIO_V2_GET_LINEINFO_IOCTL */

#ifdef GPIO_GET_LINEINFO_IOCTL
static void sanitise_v1_lineinfo(struct syscallrecord *rec)
{
	struct gpioline_info *info;

	info = (struct gpioline_info *) get_writable_struct(sizeof(*info));
	if (!info)
		return;
	memset(info, 0, sizeof(*info));
	info->line_offset = rand() % 256;
	rec->a3 = (unsigned long) info;
}
#endif

#ifdef GPIO_GET_LINEHANDLE_IOCTL
static void sanitise_v1_handle_request(struct syscallrecord *rec)
{
	struct gpiohandle_request *r;
	unsigned int i;

	r = (struct gpiohandle_request *) get_writable_struct(sizeof(*r));
	if (!r)
		return;
	memset(r, 0, sizeof(*r));
	r->lines = (rand() % GPIOHANDLES_MAX) + 1;
	for (i = 0; i < r->lines; i++) {
		r->lineoffsets[i] = rand() % 256;
		r->default_values[i] = RAND_BOOL();
	}
	r->flags = rand() & GPIOHANDLE_VALID_FLAGS_MASK;
	r->fd = -1;
	rec->a3 = (unsigned long) r;
}
#endif

#ifdef GPIO_GET_LINEEVENT_IOCTL
static void sanitise_v1_event_request(struct syscallrecord *rec)
{
	struct gpioevent_request *r;

	r = (struct gpioevent_request *) get_writable_struct(sizeof(*r));
	if (!r)
		return;
	memset(r, 0, sizeof(*r));
	r->lineoffset = rand() % 256;
	r->handleflags = rand() & GPIOHANDLE_VALID_FLAGS_MASK;
	r->eventflags = rand() & GPIOEVENT_VALID_FLAGS_MASK;
	r->fd = -1;
	rec->a3 = (unsigned long) r;
}
#endif

#ifdef GPIOHANDLE_GET_LINE_VALUES_IOCTL
static void sanitise_v1_handle_data(struct syscallrecord *rec)
{
	struct gpiohandle_data *d;
	unsigned int i;

	d = (struct gpiohandle_data *) get_writable_struct(sizeof(*d));
	if (!d)
		return;
	for (i = 0; i < GPIOHANDLES_MAX; i++)
		d->values[i] = RAND_BOOL();
	rec->a3 = (unsigned long) d;
}
#endif

#ifdef GPIOHANDLE_SET_CONFIG_IOCTL
static void sanitise_v1_handle_config(struct syscallrecord *rec)
{
	struct gpiohandle_config *c;
	unsigned int i;

	c = (struct gpiohandle_config *) get_writable_struct(sizeof(*c));
	if (!c)
		return;
	memset(c, 0, sizeof(*c));
	c->flags = rand() & GPIOHANDLE_VALID_FLAGS_MASK;
	for (i = 0; i < GPIOHANDLES_MAX; i++)
		c->default_values[i] = RAND_BOOL();
	rec->a3 = (unsigned long) c;
}
#endif

static void gpio_sanitise(const struct ioctl_group *grp,
			  struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case GPIO_GET_CHIPINFO_IOCTL:
		sanitise_chipinfo(rec);
		break;

	case GPIO_GET_LINEINFO_UNWATCH_IOCTL:
		sanitise_lineinfo_unwatch(rec);
		break;

#ifdef GPIO_V2_GET_LINEINFO_IOCTL
	case GPIO_V2_GET_LINEINFO_IOCTL:
	case GPIO_V2_GET_LINEINFO_WATCH_IOCTL:
		sanitise_v2_lineinfo(rec);
		break;

	case GPIO_V2_GET_LINE_IOCTL:
		sanitise_v2_line_request(rec);
		break;

	case GPIO_V2_LINE_SET_CONFIG_IOCTL:
		sanitise_v2_line_config(rec);
		break;

	case GPIO_V2_LINE_GET_VALUES_IOCTL:
	case GPIO_V2_LINE_SET_VALUES_IOCTL:
		sanitise_v2_line_values(rec);
		break;
#endif

#ifdef GPIO_GET_LINEINFO_IOCTL
	case GPIO_GET_LINEINFO_IOCTL:
	case GPIO_GET_LINEINFO_WATCH_IOCTL:
		sanitise_v1_lineinfo(rec);
		break;
#endif

#ifdef GPIO_GET_LINEHANDLE_IOCTL
	case GPIO_GET_LINEHANDLE_IOCTL:
		sanitise_v1_handle_request(rec);
		break;
#endif

#ifdef GPIO_GET_LINEEVENT_IOCTL
	case GPIO_GET_LINEEVENT_IOCTL:
		sanitise_v1_event_request(rec);
		break;
#endif

#ifdef GPIOHANDLE_GET_LINE_VALUES_IOCTL
	case GPIOHANDLE_GET_LINE_VALUES_IOCTL:
	case GPIOHANDLE_SET_LINE_VALUES_IOCTL:
		sanitise_v1_handle_data(rec);
		break;
#endif

#ifdef GPIOHANDLE_SET_CONFIG_IOCTL
	case GPIOHANDLE_SET_CONFIG_IOCTL:
		sanitise_v1_handle_config(rec);
		break;
#endif

	default:
		break;
	}
}

static const struct ioctl gpio_ioctls[] = {
	IOCTL(GPIO_GET_CHIPINFO_IOCTL),
	IOCTL(GPIO_GET_LINEINFO_UNWATCH_IOCTL),
#ifdef GPIO_V2_GET_LINEINFO_IOCTL
	IOCTL(GPIO_V2_GET_LINEINFO_IOCTL),
	IOCTL(GPIO_V2_GET_LINEINFO_WATCH_IOCTL),
	IOCTL(GPIO_V2_GET_LINE_IOCTL),
	IOCTL(GPIO_V2_LINE_SET_CONFIG_IOCTL),
	IOCTL(GPIO_V2_LINE_GET_VALUES_IOCTL),
	IOCTL(GPIO_V2_LINE_SET_VALUES_IOCTL),
#endif
#ifdef GPIO_GET_LINEINFO_IOCTL
	IOCTL(GPIO_GET_LINEINFO_IOCTL),
	IOCTL(GPIO_GET_LINEINFO_WATCH_IOCTL),
#endif
#ifdef GPIO_GET_LINEHANDLE_IOCTL
	IOCTL(GPIO_GET_LINEHANDLE_IOCTL),
#endif
#ifdef GPIO_GET_LINEEVENT_IOCTL
	IOCTL(GPIO_GET_LINEEVENT_IOCTL),
#endif
#ifdef GPIOHANDLE_GET_LINE_VALUES_IOCTL
	IOCTL(GPIOHANDLE_GET_LINE_VALUES_IOCTL),
	IOCTL(GPIOHANDLE_SET_LINE_VALUES_IOCTL),
#endif
#ifdef GPIOHANDLE_SET_CONFIG_IOCTL
	IOCTL(GPIOHANDLE_SET_CONFIG_IOCTL),
#endif
};

static const struct ioctl_group gpio_grp = {
	.name = "gpio",
	.devtype = DEV_CHAR,
	.fd_test = gpio_fd_test,
	.sanitise = gpio_sanitise,
	.ioctls = gpio_ioctls,
	.ioctls_cnt = ARRAY_SIZE(gpio_ioctls),
};

REG_IOCTL_GROUP(gpio_grp)
