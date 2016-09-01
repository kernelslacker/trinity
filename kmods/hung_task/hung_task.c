#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/sched.h>

static int dummy_arg = 0;

static struct test_hung_task_data {
        struct mutex dead_lock;
        struct hrtimer hrtimer_release_mutex;
} test_data;

struct work_struct work;

static enum hrtimer_restart test_hrtimer_free_mutex_func(struct hrtimer* hr)
{       
        struct test_hung_task_data *td = container_of(hr,
                struct test_hung_task_data, hrtimer_release_mutex);
        pr_info("alarm ... ... ...");
        pr_info("release the mutex");
        mutex_unlock(&td->dead_lock); 
        return HRTIMER_NORESTART;  
}

static int init_hung_task_test(void)
{
        ktime_t ktime;  
        ktime = ktime_set(100, 0);   //  10* 1000 ms  

        pr_info("loading module");

        pr_info("Init and take the mutex in init.");

        mutex_init(&test_data.dead_lock);
		mutex_lock(&test_data.dead_lock);

        pr_info("Start a alarm for 100s");

		hrtimer_init(&test_data.hrtimer_release_mutex, CLOCK_MONOTONIC,
                        HRTIMER_MODE_REL);
		test_data.hrtimer_release_mutex.function = test_hrtimer_free_mutex_func;
        hrtimer_start(&test_data.hrtimer_release_mutex, ktime,
                        HRTIMER_MODE_REL);

        return 0;
}

static void exit_hung_task_test(void)
{
        ktime_t rem;
        while (hrtimer_active(&test_data.hrtimer_release_mutex)) {
                rem = hrtimer_get_remaining(&test_data.hrtimer_release_mutex);
                printk("hrtimer is active, remaining %lld secs",
                        rem.tv64 / NSEC_PER_SEC);
        }
        pr_info("hrtimer has been done...");
        printk("unloading module\n");
}

module_init(init_hung_task_test);
module_exit(exit_hung_task_test);

MODULE_LICENSE("GPL");
module_param(dummy_arg, int, 0444);
MODULE_PARM_DESC(dummy_arg, "Test parameter...");

