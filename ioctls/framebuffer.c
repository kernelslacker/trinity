#include <linux/ioctl.h>
#include <linux/fb.h>
#ifdef __has_include
# if __has_include(<linux/arcfb.h>)
#  include <linux/arcfb.h>
# endif
# if __has_include(<linux/radeonfb.h>)
#  include <linux/radeonfb.h>
# endif
#endif

#include "ioctls.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

static void sanitise_fb_var_screeninfo(struct syscallrecord *rec)
{
	struct fb_var_screeninfo *var;

	var = (struct fb_var_screeninfo *) get_writable_struct(sizeof(*var));
	if (!var)
		return;
	var->xres = rand() % 1920 + 1;
	var->yres = rand() % 1080 + 1;
	var->xres_virtual = var->xres + rand() % 64;
	var->yres_virtual = var->yres + rand() % 64;
	var->xoffset = rand() % var->xres;
	var->yoffset = rand() % var->yres;
	var->bits_per_pixel = 1 << (rand() % 5);	/* 1, 2, 4, 8, 16 */
	var->grayscale = RAND_BOOL() ? 0 : 1;
	var->red.offset = rand() % 32;
	var->red.length = rand() % 8 + 1;
	var->green.offset = rand() % 32;
	var->green.length = rand() % 8 + 1;
	var->blue.offset = rand() % 32;
	var->blue.length = rand() % 8 + 1;
	var->activate = rand() & FB_ACTIVATE_MASK;
	var->pixclock = rand() % 100000 + 1000;
	var->vmode = rand() % 3;
	rec->a3 = (unsigned long) var;
}

static void sanitise_fb_cmap(struct syscallrecord *rec)
{
	struct fb_cmap *cmap;
	unsigned int len;

	cmap = (struct fb_cmap *) get_writable_struct(sizeof(*cmap));
	if (!cmap)
		return;
	cmap->start = rand() % 256;
	len = rand() % 16 + 1;
	cmap->len = len;
	cmap->red = (unsigned short *) get_writable_struct(len * sizeof(__u16));
	cmap->green = (unsigned short *) get_writable_struct(len * sizeof(__u16));
	cmap->blue = (unsigned short *) get_writable_struct(len * sizeof(__u16));
	if (RAND_BOOL())
		cmap->transp = (unsigned short *) get_writable_struct(len * sizeof(__u16));
	rec->a3 = (unsigned long) cmap;
}

static void sanitise_fb_cursor(struct syscallrecord *rec)
{
	struct fb_cursor *cur;
	unsigned int w, h, mapsize;

	cur = (struct fb_cursor *) get_writable_struct(sizeof(*cur));
	if (!cur)
		return;
	cur->set = rand() & FB_CUR_SETALL;
	cur->enable = RAND_BOOL();
	cur->rop = rand() & 1;
	cur->hot.x = rand() % 64;
	cur->hot.y = rand() % 64;
	w = rand() % 32 + 1;
	h = rand() % 32 + 1;
	cur->image.dx = rand() % 1024;
	cur->image.dy = rand() % 768;
	cur->image.width = w;
	cur->image.height = h;
	cur->image.depth = 1;
	cur->image.fg_color = rand32();
	cur->image.bg_color = rand32();
	mapsize = (w * h + 7) / 8 + 8;
	cur->mask = (const char *) get_writable_struct(mapsize);
	cur->image.data = (const char *) get_writable_struct(mapsize);
	rec->a3 = (unsigned long) cur;
}

static void sanitise_fb_con2fbmap(struct syscallrecord *rec)
{
	struct fb_con2fbmap *map;

	map = (struct fb_con2fbmap *) get_writable_struct(sizeof(*map));
	if (!map)
		return;
	map->console = rand() % 64;
	map->framebuffer = rand() % 8;
	rec->a3 = (unsigned long) map;
}

static void fb_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case FBIOGET_VSCREENINFO:
	case FBIOPUT_VSCREENINFO:
	case FBIOPAN_DISPLAY:
		sanitise_fb_var_screeninfo(rec);
		break;

	case FBIOGET_FSCREENINFO: {
		struct fb_fix_screeninfo *fix = get_writable_struct(sizeof(*fix));
		if (fix)
			rec->a3 = (unsigned long) fix;
		break;
	}

	case FBIOGETCMAP:
	case FBIOPUTCMAP:
		sanitise_fb_cmap(rec);
		break;

	case FBIO_CURSOR:
		sanitise_fb_cursor(rec);
		break;

	case FBIOGET_CON2FBMAP:
	case FBIOPUT_CON2FBMAP:
		sanitise_fb_con2fbmap(rec);
		break;

	case FBIOBLANK:
		/* arg is a blank level, not a pointer */
		rec->a3 = rand() % 5;
		break;

	case FBIOGET_VBLANK: {
		struct fb_vblank *vbl = get_writable_struct(sizeof(*vbl));
		if (vbl)
			rec->a3 = (unsigned long) vbl;
		break;
	}

#ifdef FBIO_WAITFORVSYNC
	case FBIO_WAITFORVSYNC: {
		__u32 *frame = (__u32 *) get_writable_struct(sizeof(__u32));
		if (frame) {
			*frame = rand32();
			rec->a3 = (unsigned long) frame;
		}
		break;
	}
#endif

	case FBIO_ALLOC:
	case FBIO_FREE:
	case FBIOGET_GLYPH:
	case FBIOGET_HWCINFO:
	case FBIOPUT_MODEINFO:
	case FBIOGET_DISPINFO: {
		void *buf = get_writable_struct(256);
		if (buf)
			rec->a3 = (unsigned long) buf;
		break;
	}

	default:
		break;
	}
}

static const struct ioctl fb_ioctls[] = {
	IOCTL(FBIOGET_VSCREENINFO),
	IOCTL(FBIOPUT_VSCREENINFO),
	IOCTL(FBIOGET_FSCREENINFO),
	IOCTL(FBIOGETCMAP),
	IOCTL(FBIOPUTCMAP),
	IOCTL(FBIOPAN_DISPLAY),
	IOCTL(FBIO_CURSOR),
	IOCTL(FBIOGET_CON2FBMAP),
	IOCTL(FBIOPUT_CON2FBMAP),
	IOCTL(FBIOBLANK),
	IOCTL(FBIOGET_VBLANK),
	IOCTL(FBIO_ALLOC),
	IOCTL(FBIO_FREE),
	IOCTL(FBIOGET_GLYPH),
	IOCTL(FBIOGET_HWCINFO),
	IOCTL(FBIOPUT_MODEINFO),
	IOCTL(FBIOGET_DISPINFO),
#ifdef FBIO_WAITFORVSYNC
	IOCTL(FBIO_WAITFORVSYNC),
#endif
#ifdef FBIO_WAITEVENT
	IOCTL(FBIO_WAITEVENT),
#endif
#ifdef FBIO_GETCONTROL2
	IOCTL(FBIO_GETCONTROL2),
#endif
#ifdef FBIO_RADEON_GET_MIRROR
	IOCTL(FBIO_RADEON_GET_MIRROR),
#endif
#ifdef FBIO_RADEON_SET_MIRROR
	IOCTL(FBIO_RADEON_SET_MIRROR),
#endif
};

static const char *const fb_chardevs[] = {
	"fb",
};

static const struct ioctl_group fb_grp = {
	.devtype = DEV_CHAR,
	.devs = fb_chardevs,
	.devs_cnt = ARRAY_SIZE(fb_chardevs),
	.sanitise = fb_sanitise,
	.ioctls = fb_ioctls,
	.ioctls_cnt = ARRAY_SIZE(fb_ioctls),
};

REG_IOCTL_GROUP(fb_grp)
