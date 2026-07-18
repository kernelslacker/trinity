/*
 * JSON mechanics shared across the stats/json/ cluster: string escape
 * and the descriptor-driven stat_category renderer.  Kept out of the
 * public stats-internal.h so non-JSON callers do not accidentally
 * grow a JSON output path.
 */

#include <stdio.h>
#include <stddef.h>
#include "stats-internal.h"
#include "stats/json/internal.h"

/*
 * JSON helpers for --stats-json. Emit straight to stdout (no [main] prefix
 * from output()), so post-run scripts can redirect stdout and parse the
 * result with jq / json.loads / serde_json without stripping anything.
 */
void json_emit_string(const char *s)
{
	putchar('"');
	if (s != NULL) {
		for (; *s != '\0'; s++) {
			unsigned char c = (unsigned char)*s;

			switch (c) {
			case '"':  fputs("\\\"", stdout); break;
			case '\\': fputs("\\\\", stdout); break;
			case '\b': fputs("\\b", stdout);  break;
			case '\f': fputs("\\f", stdout);  break;
			case '\n': fputs("\\n", stdout);  break;
			case '\r': fputs("\\r", stdout);  break;
			case '\t': fputs("\\t", stdout);  break;
			default:
				if (c < 0x20)
					printf("\\u%04x", c);
				else
					putchar(c);
			}
		}
	}
	putchar('"');
}

/*
 * Emit one category as a JSON object: "name":{"field":N,"field":N,...}.
 * Caller is responsible for the surrounding comma separator.
 */
void stat_category_emit_json(const struct stat_category *cat)
{
	size_t i;

	printf("\"%s\":{", cat->name);
	for (i = 0; i < cat->n_fields; i++) {
		const struct stat_field *f = &cat->fields[i];
		const char *key = f->json_key ? f->json_key : f->name;

		printf("%s\"%s\":%lu",
		       i ? "," : "",
		       key,
		       stat_field_load(f));
	}
	putchar('}');
}
