#pragma once

// FIXME: Keep all this here until glibc supports it.
#ifndef SYS_userfaultfd
#ifdef __x86_64__
#define SYS_userfaultfd 323
#endif
#endif
