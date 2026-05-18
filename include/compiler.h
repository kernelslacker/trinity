#ifndef _TRINITY_COMPILER_H
#define _TRINITY_COMPILER_H

/* Force callers to check the return value or get a compile-time warning. */
#if defined(__GNUC__) || defined(__clang__)
# define __must_check __attribute__((warn_unused_result))
#else
# define __must_check
#endif

#endif /* _TRINITY_COMPILER_H */
