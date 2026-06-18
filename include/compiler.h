#ifndef _TRINITY_COMPILER_H
#define _TRINITY_COMPILER_H

/* Force callers to check the return value or get a compile-time warning. */
#if defined(__GNUC__) || defined(__clang__)
# define __must_check __attribute__((warn_unused_result))
#else
# define __must_check
#endif

/* Mark functions as unlikely to be called.  The compiler partitions them
 * into a cold text section away from hot code, and optimises for size
 * rather than speed.  Use for diagnostic dumps, post-mortem builders,
 * and end-of-run reporters -- never on the syscall hot path. */
#if defined(__GNUC__) || defined(__clang__)
# define __cold __attribute__((cold))
#else
# define __cold
#endif

#endif /* _TRINITY_COMPILER_H */
