#pragma once

/*
 * Shared signal vocabulary for the kill / tgkill / rt_sigqueueinfo /
 * pidfd_send_signal sanitisers.  Defined once in signals-safelist.c so
 * the four delivery-syscall safe-lists cannot drift apart from -- or
 * from -- the policy mask_signals_child() actually installs.
 *
 * child_safe_signals[]
 *   Delivery to a fuzz child is a no-op (SIG_IGN, flag-setting handler,
 *   or kernel default of Ignore/Continue).  Biasing toward this set is
 *   what keeps the sanitisers from quietly tearing down healthy fuzz
 *   children via the catch-all sighandler -> SIG_DFL -> raise default-
 *   action path.  Derivation lives next to the definition.
 *
 * child_fatal_signals[]
 *   Catch-all sighandler restores SIG_DFL and re-raises -- kernel
 *   default is Term/Core -- so picking one for self/sibling delivery
 *   WILL tear a child down.  Picked at a small fixed rate by the
 *   delivery sanitisers so the kernel-side signal-delivery /
 *   permission / group-leader paths still see traffic for these
 *   signals, without dominating the run with teardowns.
 *
 * Realtime signals (SIGRTMIN..SIGRTMAX) are SIG_IGN'd by
 * mask_signals_child() and are picked separately by sanitise_rt_sigqueueinfo
 * via its RT branch; they are not duplicated here.  SIGRTMIN/SIGRTMAX
 * are runtime values rather than compile-time constants in glibc and
 * cannot live in a static array initializer regardless.
 */
extern const unsigned long child_safe_signals[];
extern const unsigned int child_safe_signals_count;
extern const unsigned long child_fatal_signals[];
extern const unsigned int child_fatal_signals_count;
