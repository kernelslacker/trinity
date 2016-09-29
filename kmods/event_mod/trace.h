#if !defined(_TRACE_PITA_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_PITA_H

#include <linux/tracepoint.h>

#undef  TRACE_SYSTEM
#define TRACE_SYSTEM pita

/*
 * Tracepoint for guest mode entry.
 */
TRACE_EVENT(pita,
	TP_PROTO(unsigned int pita),
	TP_ARGS(pita),

	TP_STRUCT__entry(
		__field(	unsigned int,   pita	)
	),

	TP_fast_assign(
		__entry->pita = pita;
	),

	TP_printk("pita %u", __entry->pita)
);

#endif /* _TRACE_PITA_H */

/* this part has to be here */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .

#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace

#include <trace/define_trace.h>
