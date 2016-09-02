#include <linux/printk.h>
#include <linux/types.h>
#include <linux/module.h>

extern unsigned long long test_dump_tasklist(int number, pid_t pid);
static int dummy = 0;

void clobber_dump_task_list(void)
{
        unsigned long long res = test_dump_tasklist(100, 0);
        pr_info("func return: %lld", res);
}

int init_clobber(void)
{
        pr_info("Start clobber base_lib");
        clobber_dump_task_list();
        return 0;
}

void exit_clobber(void)
{
        pr_info("Exit clobber base_lib");
}

module_init(init_clobber);
module_exit(exit_clobber);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chunyu Hu <chuhu@redhat.com>");
module_param(dummy, int, 0444);
MODULE_PARM_DESC(dummy, "How long will the hung task block.");

