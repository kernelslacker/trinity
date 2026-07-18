#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field pci_bind_fields[] = {
	STAT_FIELD_SUB(pci_bind, runs),
	STAT_FIELD_SUB(pci_bind, drivers_available),
	STAT_FIELD_SUB(pci_bind, no_devices),
	STAT_FIELD_SUB(pci_bind, unbind_ok),
	STAT_FIELD_SUB(pci_bind, unbind_enodev),
	STAT_FIELD_SUB(pci_bind, unbind_failed),
	STAT_FIELD_SUB(pci_bind, bind_ok),
	STAT_FIELD_SUB(pci_bind, bind_enodev),
	STAT_FIELD_SUB(pci_bind, bind_failed),
};

const struct stat_category pci_bind_category =
	STAT_CATEGORY("pci_bind",
	              pci_bind.runs,
	              pci_bind_fields);
