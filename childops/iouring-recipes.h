#pragma once
/*
 * iouring-recipes -- structured submission sequences.  Ring lifecycle
 * lives in childops/iouring-ring.{c,h}; this header used to carry a
 * private copy of the ring struct + setup/teardown decls, but every
 * caller has moved to the shared helper.
 */

#include "childops/iouring-ring.h"
