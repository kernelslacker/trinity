#include <linux/kernel.h>
#include <linux/module.h>

extern long test_dump_cpulist(int node, int cpu);

int kinfo_init(void)
{
    long res;

    pr_info("init kinfo kmod");
    res = test_dump_cpulist(0, 0);

    return !res;
}

void kinfo_exit(void)
{
    pr_info("exit kinfo kmod..");
}

module_init(kinfo_init);
module_exit(kinfo_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rayne");
