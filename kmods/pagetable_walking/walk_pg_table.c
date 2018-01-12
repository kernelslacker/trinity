#include <linux/module.h>
#include <linux/slab.h>
#include <asm/page.h>
#include <linux/sched.h>

static unsigned long vaddr;
static unsigned long pid = 1;
static struct task_struct *systemd;

static bool inline is_huge_entry(long attr)
{
	return attr & (0x1 << 7UL);
}

static int init_dummy(void)
{
	unsigned long pgd_index, pud_index, pmd_index, pte_index, offset;
	unsigned long *pgd_table, *pud_table, *pmd_table, *pte_table;
	long *page_address, *page_address_pfn;
	unsigned short attribute[4] = {0};
	unsigned short page_shift = 12;

	systemd = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
	pgd_table = (long *)systemd->mm->pgd;

	pr_info("debug: Try to walk page table for virtual address %lx", vaddr);
	pr_info("debug: Find pgd table address for pid 1: %p", pgd_table);
	pr_info("debug: __PAGE_OFFSET(physical addr direct mapping start): %lx", page_offset_base);

	pgd_index = (vaddr >> 39) & 0x1ff;
	pud_index = (vaddr >> 30) & 0x1ff;
	pmd_index = (vaddr >> 21) & 0x1ff;
	pte_index = (vaddr >> 12) & 0x1ff;
	offset = vaddr & 0xfff;

	pr_info("debug: pgd_table = %lx", (long)pgd_table);
	pr_info("debug: pgd_index = %lx", (long)pgd_index);
	
	/* physical address, covert to direct mapping for access.*/
	pud_table = page_offset_base + ((*(pgd_table + pgd_index)) & 0xffffffffff000);
	attribute[0] = (*(pgd_table + pgd_index)) & 0xfff;
	pr_info("debug: pud_table = %lx", (long)pud_table);
	pr_info("debug: pud_index = %lx", (long)pud_index);

	pmd_table = page_offset_base + ((*(pud_table + pud_index)) & 0xffffffffff000);
	attribute[1] = (*(pud_table + pud_index)) & 0xfff;
	pr_info("debug: pmd_table = %lx", (long)pmd_table);
	pr_info("debug: pmd_index = %lx", (long)pmd_index);

	pte_table = page_offset_base + ((*(pmd_table + pmd_index)) & 0xffffffffff000);
	attribute[2] = (*(pmd_table + pmd_index)) & 0xfff;
	pr_info("debug: pte_table = %lx", (long)pte_table);
	pr_info("debug: pte_index = %lx", (long)pte_index);

	if (is_huge_entry(attribute[2])) {
		page_shift = 21;
		pr_info("debug: 2M page entry!");
		page_address_pfn = ((*(pmd_table + pmd_index)) >> 12) & 0xffffffffff;
		page_address = page_offset_base + ((*(pmd_table + pmd_index)) & 0xffffffffff000);

		pr_info("debug: page_address_pfn = %p", page_address_pfn);
		pr_info("debug: page_address = %p", page_address);

		pr_info("debug: offset = %lx", vaddr & 0x1fffff);
		pr_info("debug: content = %lx\n", *(page_address+offset));
		return 0;
	}


	page_address = page_offset_base + ((*(pte_table + pte_index)) & 0xffffffffff000);
	attribute[3] = (*(pte_table + pte_index)) & 0xfff;
	page_address_pfn = ((*(pte_table + pte_index)) >> 12) & 0xffffffffff;
	pr_info("debug: page_address_pfn = %p", page_address_pfn);
	pr_info("debug: page_address = %p", page_address);

	pr_info("debug: offset = %lx", offset);
	pr_info("debug: content = %lx\n", *(page_address+offset));

	return 0;
}

static void exit_dummy(void) { }

module_init(init_dummy);
module_exit(exit_dummy);

MODULE_LICENSE("GPL");
module_param(vaddr, ulong, 0444);
module_param(pid, ulong, 0444);
MODULE_PARM_DESC(vaddr, "Virtual address");

