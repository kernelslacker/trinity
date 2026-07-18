#ifndef _TRINITY_STATS_SUBSYS_PCI_BIND_H
#define _TRINITY_STATS_SUBSYS_PCI_BIND_H

struct pci_bind_stats {
	/* pci_bind childop counters */
	unsigned long runs;			/* total pci_bind invocations (incl. no-op latched / no-device) */
	unsigned long drivers_available;	/* set once at probe: count of allowlist drivers found in /sys/bus/pci/drivers/ */
	unsigned long no_devices;		/* picked driver had no currently-bound BDFs (per-invocation no-op) */
	unsigned long unbind_ok;		/* unbind write returned >=0 (kernel accepted detach) */
	unsigned long unbind_enodev;		/* unbind write returned EINVAL/ENODEV (handler ran, BDF already detached / not bound) */
	unsigned long unbind_failed;		/* unbind open failed (EACCES / ENOENT / non-root) */
	unsigned long bind_ok;			/* bind write returned >=0 (kernel re-attached) */
	unsigned long bind_enodev;		/* bind write returned EINVAL/ENODEV (handler ran, BDF not present / matched another driver) */
	unsigned long bind_failed;		/* bind open failed (EACCES / ENOENT / non-root) */
};

#endif /* _TRINITY_STATS_SUBSYS_PCI_BIND_H */
