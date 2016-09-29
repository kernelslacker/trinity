#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/debugfs.h>

#define CREATE_TRACE_POINTS
#include "trace.h"

static struct dentry *d_pita;
static struct dentry *d_test;
/*
 * We pretend to depend on this var in another kmod or kernel.
 * then we can forcely load this kmod. Then see if the event
 * is added.
 */
extern int depends;

static int test_open(struct inode *inode, struct file *filp)
{
	depends = 0;
	return 0;
}

static ssize_t test_read(struct file *filp, char __user *ubuf,
			 size_t cnt, loff_t *ppos)
{
	return 0;
}

static ssize_t test_write(struct file *filp, const char __user *ubuf,
			  size_t cnt, loff_t *ppos)
{
	int pita = 0;

	if (kstrtoint_from_user(ubuf, cnt, 10, &pita))
		return -EINVAL;

	printk("pita: tracing\n");
	trace_pita(pita);
	return cnt;
}

static const struct file_operations test_fops = {
	.open		= test_open,
	.read		= test_read,
	.write		= test_write,
	.llseek		= default_llseek,
};

static int __init pita_init(void)
{
	d_pita = debugfs_create_dir("pita", NULL);
	if (WARN_ON(!d_pita))
		return -1;

	d_test = debugfs_create_file("test", 0644, d_pita, NULL, &test_fops);
	if (WARN_ON(!d_test)) {
		debugfs_remove(d_pita);
		return -1;
	}

	printk("pita initialized\n");
	return 0;
}

static void __exit pita_exit(void)
{
	debugfs_remove_recursive(d_pita);
	printk("pita unloaded\n");
}

module_init(pita_init);
module_exit(pita_exit);
MODULE_LICENSE("GPL");
