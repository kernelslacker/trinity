#pragma once

#ifndef HW_BREAKPOINT_LEN_1
#define HW_BREAKPOINT_LEN_1 1
#endif
#ifndef HW_BREAKPOINT_LEN_2
#define HW_BREAKPOINT_LEN_2 2
#endif
#ifndef HW_BREAKPOINT_LEN_3
#define HW_BREAKPOINT_LEN_3 3
#endif
#ifndef HW_BREAKPOINT_LEN_4
#define HW_BREAKPOINT_LEN_4 4
#endif
#ifndef HW_BREAKPOINT_LEN_5
#define HW_BREAKPOINT_LEN_5 5
#endif
#ifndef HW_BREAKPOINT_LEN_6
#define HW_BREAKPOINT_LEN_6 6
#endif
#ifndef HW_BREAKPOINT_LEN_7
#define HW_BREAKPOINT_LEN_7 7
#endif
#ifndef HW_BREAKPOINT_LEN_8
#define HW_BREAKPOINT_LEN_8 8
#endif

#ifndef _LINUX_HW_BREAKPOINT_H
enum {
        HW_BREAKPOINT_EMPTY     = 0,
        HW_BREAKPOINT_R         = 1,
        HW_BREAKPOINT_W         = 2,
        HW_BREAKPOINT_RW        = HW_BREAKPOINT_R | HW_BREAKPOINT_W,
        HW_BREAKPOINT_X         = 4,
        HW_BREAKPOINT_INVALID   = HW_BREAKPOINT_RW | HW_BREAKPOINT_X,
};
#endif
