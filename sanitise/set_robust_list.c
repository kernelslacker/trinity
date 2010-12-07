#include <linux/futex.h>
#include "scrashme.h"

/*
 * asmlinkage long sys_set_robust_list(struct robust_list_head __user *head,
 *           size_t len)
*/

void sanitise_set_robust_list(
	__unused__ unsigned long *a1,
	unsigned long *len,
	__unused__ unsigned long *a3,
	__unused__ unsigned long *a4,
	__unused__ unsigned long *a5,
	__unused__ unsigned long *a6)
{
	*len = sizeof(struct robust_list_head);
}
