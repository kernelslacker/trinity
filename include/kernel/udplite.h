#pragma once

#if __has_include(<netinet/udplite.h>)
#include <netinet/udplite.h>
#endif

#ifndef UDPLITE_SEND_CSCOV
#define UDPLITE_SEND_CSCOV   10
#define UDPLITE_RECV_CSCOV   11
#endif
