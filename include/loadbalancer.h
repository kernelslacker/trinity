#pragma once

/*
 * Load balancer: dynamically adjust max_children based on /proc/meminfo
 * and /proc/loadavg so Trinity doesn't overwhelm the system.
 */

void lb_init(void);
void lb_tick(void);
