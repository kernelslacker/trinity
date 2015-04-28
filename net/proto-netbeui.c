#include "net.h"

void netbeui_setsockopt(struct sockopt *so)
{
	so->level = SOL_NETBEUI;
}
