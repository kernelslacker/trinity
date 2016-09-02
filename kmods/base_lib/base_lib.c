#include <linux/export.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/rcupdate.h>

static int dummy = 0;
extern struct list_head tasks;

unsigned long long test_dump_tasklist(int number, pid_t pid)
{
        struct task_struct *task;

        /* Protect the task struct during the iter */
	    rcu_read_lock();

        for_each_process(task)
        {
                printk("%s [%d], threads %d\n",task->comm , task->pid,
                        get_nr_threads(task));
                if (!number--) 
                        break;
        }

	    rcu_read_unlock();

        return number;
}

EXPORT_SYMBOL(test_dump_tasklist);

long test_dump_cpulist(const char *cp, char **endp, unsigned int base)
{
        return 0xff;
}
EXPORT_SYMBOL(test_dump_cpulist);

long test_dump_nodelist(void *p, unsigned int count, int fd)
{
        return 0xff;
}
EXPORT_SYMBOL(test_dump_nodelist);

int init_lib(void)
{
    return 0;
}

void exit_lib(void)
{
    return;
}

module_init(init_lib);
module_exit(exit_lib);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chunyu Hu <chuhu@redhat.com>");
module_param(dummy, int, 0444);
MODULE_PARM_DESC(dummy, "How long will the hung task block.");

