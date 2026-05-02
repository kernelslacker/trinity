/* /dev/i2c-* (i2c-dev) ioctl fuzzing.
 *
 * uapi reference:
 *   include/uapi/linux/i2c-dev.h
 *   include/uapi/linux/i2c.h
 *
 * The i2c-dev driver registers itself in /proc/devices as "i2c", so the
 * standard DEV_CHAR + devs[] match path applies; no fd_test needed.
 */

#include <linux/ioctl.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>

#include "ioctls.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "utils.h"

static const struct ioctl i2cdev_ioctls[] = {
	IOCTL(I2C_RETRIES),
	IOCTL(I2C_TIMEOUT),
	IOCTL(I2C_SLAVE),
	IOCTL(I2C_SLAVE_FORCE),
	IOCTL(I2C_TENBIT),
	IOCTL(I2C_FUNCS),
	IOCTL(I2C_RDWR),
	IOCTL(I2C_PEC),
	IOCTL(I2C_SMBUS),
};

static const char *const i2cdev_devs[] = {
	"i2c",
};

static const unsigned short i2c_msg_flag_bits[] = {
	I2C_M_RD,
	I2C_M_TEN,
	I2C_M_RECV_LEN,
	I2C_M_NOSTART,
	I2C_M_REV_DIR_ADDR,
	I2C_M_NO_RD_ACK,
	I2C_M_IGNORE_NAK,
	I2C_M_STOP,
};

/*
 * I2C_RDWR: build a small i2c_rdwr_ioctl_data with 1..4 i2c_msg entries.
 * Each msg gets a random buffer pointer (from get_address()), a length
 * bounded to <= 256 bytes, and a random subset of the I2C_M_* flag bits.
 */
static void build_rdwr(struct syscallrecord *rec)
{
	struct i2c_rdwr_ioctl_data *d;
	struct i2c_msg *msgs;
	unsigned int n, i;

	d = (struct i2c_rdwr_ioctl_data *) rec->a3;
	if (!d)
		return;

	msgs = (struct i2c_msg *) get_address();
	if (!msgs) {
		d->msgs = NULL;
		d->nmsgs = 0;
		return;
	}

	n = (rand() % 4) + 1;
	d->msgs = msgs;
	d->nmsgs = n;

	for (i = 0; i < n; i++) {
		unsigned short flags = 0;
		unsigned int j, k;

		k = rand() % ARRAY_SIZE(i2c_msg_flag_bits);
		for (j = 0; j <= k; j++)
			flags |= i2c_msg_flag_bits[rand() % ARRAY_SIZE(i2c_msg_flag_bits)];

		msgs[i].addr = rand() & 0x7f;
		msgs[i].flags = flags;
		msgs[i].len = rand() % 257;
		msgs[i].buf = get_address();
	}
}

/*
 * I2C_SMBUS: build an i2c_smbus_ioctl_data with a random walk over the
 * SMBus size enum (0..8) and a 32B-ish union i2c_smbus_data payload.
 */
static void build_smbus(struct syscallrecord *rec)
{
	struct i2c_smbus_ioctl_data *s;
	union i2c_smbus_data *data;

	s = (struct i2c_smbus_ioctl_data *) rec->a3;
	if (!s)
		return;

	s->read_write = RAND_BOOL() ? I2C_SMBUS_READ : I2C_SMBUS_WRITE;
	s->command = rand() & 0xff;
	s->size = rand() % (I2C_SMBUS_I2C_BLOCK_DATA + 1);

	data = (union i2c_smbus_data *) get_address();
	s->data = data;
	if (data) {
		unsigned int i;

		/* Randomise the whole union including the trailing
		 * block[I2C_SMBUS_BLOCK_MAX + 2] payload. */
		for (i = 0; i < sizeof(*data); i++)
			((unsigned char *) data)[i] = rand();
	}
}

static void i2cdev_sanitise(const struct ioctl_group *grp,
			    struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case I2C_SLAVE:
	case I2C_SLAVE_FORCE:
		/* 7-bit address by default; occasionally widen into the
		 * 10-bit range so we do hit the >0x7f path without
		 * spamming -EINVAL beyond 0x3ff. */
		if (RAND_BOOL())
			rec->a3 = rand() & 0x7f;
		else
			rec->a3 = rand() & 0x3ff;
		break;

	case I2C_TENBIT:
	case I2C_PEC:
		rec->a3 = RAND_BOOL();
		break;

	case I2C_RETRIES:
		rec->a3 = rand() & 0xff;
		break;

	case I2C_TIMEOUT:
		/* Units of 10ms. Keep it modest. */
		rec->a3 = rand() & 0xff;
		break;

	case I2C_FUNCS:
		/* Output: pointer to unsigned long. */
		rec->a3 = (unsigned long) get_address();
		break;

	case I2C_RDWR:
		rec->a3 = (unsigned long) get_address();
		build_rdwr(rec);
		break;

	case I2C_SMBUS:
		rec->a3 = (unsigned long) get_address();
		build_smbus(rec);
		break;

	default:
		break;
	}
}

static const struct ioctl_group i2cdev_grp = {
	.name = "i2c-dev",
	.devtype = DEV_CHAR,
	.devs = i2cdev_devs,
	.devs_cnt = ARRAY_SIZE(i2cdev_devs),
	.sanitise = i2cdev_sanitise,
	.ioctls = i2cdev_ioctls,
	.ioctls_cnt = ARRAY_SIZE(i2cdev_ioctls),
};

REG_IOCTL_GROUP(i2cdev_grp)
