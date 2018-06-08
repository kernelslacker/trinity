#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

static int dummy_arg = 0;

void dummy_greetings(void)
{
        printk("This module has loaded.\n");
        if (dummy_arg)
                printk("And dummy_arg is %d.\n", dummy_arg);
}

static int init_dummy(void)
{
        dummy_greetings();
        WARN(1, "hello! Welcome you with a warning...");
        return 0;
}

static void cleanup_dummy(void)
{
        printk("unloading module\n");
}

module_init(init_dummy);
module_exit(cleanup_dummy);

MODULE_LICENSE("GPL"); // avoid GPL issues

module_param(dummy_arg, int, 0444);
MODULE_PARM_DESC(dummy_arg, "An argument for this module");
