#include <linux/module.h>
#include <linux/slab.h>
#include <asm/page.h>

static char *p = NULL;

static int init_dummy(void)
{
    p = (char*)__get_free_pages(GFP_KERNEL, 2);
    pr_info("chuhu: alloc_page_addr=%p\n", p);
    return !p;
}

static void exit_dummy(void)
{
    free_pages((unsigned long)p, 2);
    pr_info("chuhu: free_page_addr=%p\n", p);
}

module_init(init_dummy);
module_exit(exit_dummy);

MODULE_LICENSE("GPL");
