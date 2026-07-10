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
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

/*
 * Compile-time: the two fixed-shape framebuffer commands this file
 * fills -- FBIO_CURSOR (struct fb_cursor) and FBIOGET_VBLANK
 * (struct fb_vblank) -- must have sizeof(struct) matching the
 * _IOC_SIZE the request bits encode.  A <linux/fb.h> refactor that
 * grows or shrinks either struct otherwise silently has the kernel
 * copy a different number of bytes than the sanitiser prepared.
 * Both commands are #ifdef-gated by the same uapi symbol they
 * define, so each assert lives inside the matching guard so builds
 * against older uapi headers still compile.
 *
 * FBIOGET_VSCREENINFO / FBIOPUT_VSCREENINFO / FBIOPAN_DISPLAY
 * (struct fb_var_screeninfo), FBIOGET_FSCREENINFO
 * (struct fb_fix_screeninfo), FBIOGETCMAP / FBIOPUTCMAP
 * (struct fb_cmap) and FBIOGET_CON2FBMAP / FBIOPUT_CON2FBMAP
 * (struct fb_con2fbmap) all carry fixed-shape structs too, but
 * these commands are historically _IO() with a hardcoded numeric
 * type argument, not _IOR/_IOW parameterised on the struct, so
 * _IOC_SIZE(cmd) is zero and there is no size pairing to assert.
 * FBIOBLANK passes an integer level, not a pointer.  FBIO_ALLOC /
 * FBIO_FREE / FBIOGET_GLYPH / FBIOGET_HWCINFO / FBIOPUT_MODEINFO /
 * FBIOGET_DISPINFO are driver-private and take opaque buffers.
 * FBIO_WAITFORVSYNC takes a bare __u32.  All are intentionally
 * absent for that reason.
 */
#ifdef FBIO_CURSOR
_Static_assert(sizeof(struct fb_cursor) ==
	       _IOC_SIZE(FBIO_CURSOR),
	       "fb_cursor size vs _IOC_SIZE mismatch");
#endif
#ifdef FBIOGET_VBLANK
_Static_assert(sizeof(struct fb_vblank) ==
	       _IOC_SIZE(FBIOGET_VBLANK),
	       "fb_vblank size vs _IOC_SIZE mismatch");
#endif

static void sanitise_fb_var_screeninfo(struct syscallrecord *rec)
{
	struct fb_var_screeninfo *var;

	var = (struct fb_var_screeninfo *) get_writable_struct(sizeof(*var));
	if (!var)
		return;
	memset(var, 0, sizeof(*var));
	var->xres = rnd_modulo_u32(1920) + 1;
	var->yres = rnd_modulo_u32(1080) + 1;
	var->xres_virtual = var->xres + rnd_modulo_u32(64);
	var->yres_virtual = var->yres + rnd_modulo_u32(64);
	var->xoffset = rnd_modulo_u32(var->xres);
	var->yoffset = rnd_modulo_u32(var->yres);
	var->bits_per_pixel = 1 << (rnd_modulo_u32(5));	/* 1, 2, 4, 8, 16 */
	var->grayscale = RAND_BOOL() ? 0 : 1;
	var->red.offset = rnd_modulo_u32(32);
	var->red.length = rnd_modulo_u32(8) + 1;
	var->green.offset = rnd_modulo_u32(32);
	var->green.length = rnd_modulo_u32(8) + 1;
	var->blue.offset = rnd_modulo_u32(32);
	var->blue.length = rnd_modulo_u32(8) + 1;
	var->activate = rnd_u32() & FB_ACTIVATE_MASK;
	var->pixclock = rnd_modulo_u32(100000) + 1000;
	var->vmode = rnd_modulo_u32(3);
	rec->a3 = (unsigned long) var;
}

static void sanitise_fb_cmap(struct syscallrecord *rec)
{
	struct fb_cmap *cmap;
	unsigned short *red, *green, *blue;
	unsigned int len;

	cmap = (struct fb_cmap *) get_writable_struct(sizeof(*cmap));
	if (!cmap)
		return;
	memset(cmap, 0, sizeof(*cmap));
	len = rnd_modulo_u32(16) + 1;
	red = get_writable_struct(len * sizeof(__u16));
	green = get_writable_struct(len * sizeof(__u16));
	blue = get_writable_struct(len * sizeof(__u16));
	if (!red || !green || !blue)
		return;
	cmap->start = rnd_modulo_u32(256);
	cmap->len = len;
	cmap->red = red;
	cmap->green = green;
	cmap->blue = blue;
	if (RAND_BOOL()) {
		unsigned short *transp = get_writable_struct(len * sizeof(__u16));
		if (transp)
			cmap->transp = transp;
	}
	rec->a3 = (unsigned long) cmap;
}

static void sanitise_fb_cursor(struct syscallrecord *rec)
{
	struct fb_cursor *cur;
	const char *mask, *data;
	unsigned int w, h, mapsize;

	cur = (struct fb_cursor *) get_writable_struct(sizeof(*cur));
	if (!cur)
		return;
	memset(cur, 0, sizeof(*cur));
	w = rnd_modulo_u32(32) + 1;
	h = rnd_modulo_u32(32) + 1;
	mapsize = (w * h + 7) / 8 + 8;
	mask = get_writable_struct(mapsize);
	data = get_writable_struct(mapsize);
	if (!mask || !data)
		return;
	cur->set = rnd_u32() & FB_CUR_SETALL;
	cur->enable = RAND_BOOL();
	cur->rop = rnd_u32() & 1;
	cur->hot.x = rnd_modulo_u32(64);
	cur->hot.y = rnd_modulo_u32(64);
	cur->image.dx = rnd_modulo_u32(1024);
	cur->image.dy = rnd_modulo_u32(768);
	cur->image.width = w;
	cur->image.height = h;
	cur->image.depth = 1;
	cur->image.fg_color = rand32();
	cur->image.bg_color = rand32();
	cur->mask = mask;
	cur->image.data = data;
	rec->a3 = (unsigned long) cur;
}

static void sanitise_fb_con2fbmap(struct syscallrecord *rec)
{
	struct fb_con2fbmap *map;

	map = (struct fb_con2fbmap *) get_writable_struct(sizeof(*map));
	if (!map)
		return;
	memset(map, 0, sizeof(*map));
	map->console = rnd_modulo_u32(64);
	map->framebuffer = rnd_modulo_u32(8);
	rec->a3 = (unsigned long) map;
}

static void fb_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
#ifdef FBIOGET_VSCREENINFO
	case FBIOGET_VSCREENINFO:
#endif
#ifdef FBIOPUT_VSCREENINFO
	case FBIOPUT_VSCREENINFO:
#endif
#ifdef FBIOPAN_DISPLAY
	case FBIOPAN_DISPLAY:
#endif
		sanitise_fb_var_screeninfo(rec);
		break;

#ifdef FBIOGET_FSCREENINFO
	case FBIOGET_FSCREENINFO: {
		struct fb_fix_screeninfo *fix = get_writable_struct(sizeof(*fix));
		if (fix) {
			memset(fix, 0, sizeof(*fix));
			rec->a3 = (unsigned long) fix;
		}
		break;
	}
#endif

#ifdef FBIOGETCMAP
	case FBIOGETCMAP:
#endif
#ifdef FBIOPUTCMAP
	case FBIOPUTCMAP:
#endif
		sanitise_fb_cmap(rec);
		break;

#ifdef FBIO_CURSOR
	case FBIO_CURSOR:
		sanitise_fb_cursor(rec);
		break;
#endif

#ifdef FBIOGET_CON2FBMAP
	case FBIOGET_CON2FBMAP:
#endif
#ifdef FBIOPUT_CON2FBMAP
	case FBIOPUT_CON2FBMAP:
#endif
		sanitise_fb_con2fbmap(rec);
		break;

#ifdef FBIOBLANK
	case FBIOBLANK:
		/* arg is a blank level, not a pointer */
		rec->a3 = rnd_modulo_u32(5);
		break;
#endif

#ifdef FBIOGET_VBLANK
	case FBIOGET_VBLANK: {
		struct fb_vblank *vbl = get_writable_struct(sizeof(*vbl));
		if (vbl) {
			memset(vbl, 0, sizeof(*vbl));
			rec->a3 = (unsigned long) vbl;
		}
		break;
	}
#endif

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

#ifdef FBIO_ALLOC
	case FBIO_ALLOC:
#endif
#ifdef FBIO_FREE
	case FBIO_FREE:
#endif
#ifdef FBIOGET_GLYPH
	case FBIOGET_GLYPH:
#endif
#ifdef FBIOGET_HWCINFO
	case FBIOGET_HWCINFO:
#endif
#ifdef FBIOPUT_MODEINFO
	case FBIOPUT_MODEINFO:
#endif
#ifdef FBIOGET_DISPINFO
	case FBIOGET_DISPINFO:
#endif
	{
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
#ifdef FBIOGET_VSCREENINFO
	IOCTL(FBIOGET_VSCREENINFO),
#endif
#ifdef FBIOPUT_VSCREENINFO
	IOCTL(FBIOPUT_VSCREENINFO),
#endif
#ifdef FBIOGET_FSCREENINFO
	IOCTL(FBIOGET_FSCREENINFO),
#endif
#ifdef FBIOGETCMAP
	IOCTL(FBIOGETCMAP),
#endif
#ifdef FBIOPUTCMAP
	IOCTL(FBIOPUTCMAP),
#endif
#ifdef FBIOPAN_DISPLAY
	IOCTL(FBIOPAN_DISPLAY),
#endif
#ifdef FBIO_CURSOR
	IOCTL(FBIO_CURSOR),
#endif
#ifdef FBIOGET_CON2FBMAP
	IOCTL(FBIOGET_CON2FBMAP),
#endif
#ifdef FBIOPUT_CON2FBMAP
	IOCTL(FBIOPUT_CON2FBMAP),
#endif
#ifdef FBIOBLANK
	IOCTL(FBIOBLANK),
#endif
#ifdef FBIOGET_VBLANK
	IOCTL(FBIOGET_VBLANK),
#endif
#ifdef FBIO_ALLOC
	IOCTL(FBIO_ALLOC),
#endif
#ifdef FBIO_FREE
	IOCTL(FBIO_FREE),
#endif
#ifdef FBIOGET_GLYPH
	IOCTL(FBIOGET_GLYPH),
#endif
#ifdef FBIOGET_HWCINFO
	IOCTL(FBIOGET_HWCINFO),
#endif
#ifdef FBIOPUT_MODEINFO
	IOCTL(FBIOPUT_MODEINFO),
#endif
#ifdef FBIOGET_DISPINFO
	IOCTL(FBIOGET_DISPINFO),
#endif
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
	.name = "fb",
	.devtype = DEV_CHAR,
	.devs = fb_chardevs,
	.devs_cnt = ARRAY_SIZE(fb_chardevs),
	.sanitise = fb_sanitise,
	.ioctls = fb_ioctls,
	.ioctls_cnt = ARRAY_SIZE(fb_ioctls),
};

REG_IOCTL_GROUP(fb_grp)
