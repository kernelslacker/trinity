/*
 * Self-check for the names of a child's local map pool entries.
 * map_destructor() (mm/maps-lifecycle.c, linked as a parent TU) must clear
 * a name and must not free one it cannot prove it owns.
 * Entry point: maps_name_self_check().
 */

#include <string.h>

#include "debug.h"		/* BUG */
#include "maps.h"
#include "objects.h"

/*
 * Run the OBJ_LOCAL destructor on a pool entry whose only live field is the
 * name.  owns_vma stays false, as for a borrowed clone, so no munmap runs.
 */
static void destroy_with_name(char *name)
{
	struct object obj;

	memset(&obj, 0, sizeof(obj));
	obj.map.name = name;
	map_destructor(&obj);
	if (obj.map.name != NULL)
		BUG("map name: map_destructor() left the name pointer set");
}

/* A name on the stack is no allocation: a free of it would abort. */
static void destructor_clears_the_name(void)
{
	char name[] = "anon(PROT_READ)";

	destroy_with_name(name);
	if (strcmp(name, "anon(PROT_READ)") != 0)
		BUG("map name: map_destructor() wrote through the name");
}

void maps_name_self_check(void);
void maps_name_self_check(void)
{
	destructor_clears_the_name();
}
