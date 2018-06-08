#include <linux/module.h>
#include <linux/slab.h>
#include <asm/page.h>

static char *p = NULL;
static char *vp = NULL;

static int init_dummy(void)
{
    p = (char*)__get_free_pages(GFP_KERNEL, 2);
    *(long*)p = 0xBADBEAF;

    pr_info("debug: alloc_page_addr=%p\n", p);
    pr_info("debug: (%p): %lx\n", p, *(long*)p);

    vp = vmalloc(8192);
    *(long*)vp= 0xFAEBDAB;

    pr_info("debug: vmalloc_addr=%p\n", vp);
    pr_info("debug: (%p): %lx\n", vp, *(long*)vp);
    return !p;
}

static void exit_dummy(void)
{
    pr_info("debug: free_page=%p, vfree=%p\n", p, vp);
    free_pages((unsigned long)p, 2);
    vfree(vp);
}

module_init(init_dummy);
module_exit(exit_dummy);

MODULE_LICENSE("GPL");
