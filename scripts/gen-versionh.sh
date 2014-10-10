#!/bin/bash

HEADER="include/version.h"

hdr()
{
 echo "#pragma once" > $HEADER
 echo "/* This file is auto-generated */" >> $HEADER
}

# FIXME: remove one day (post 1.5?)
rm -f version.h

if [ -f $HEADER ]; then
  OLD=$(grep VERSION $HEADER | head -n1 | sed 's/"//g' | awk '{ print $3 }')
else
  OLD=""
fi

DEVEL=$(grep VERSION Makefile | head -n1 | grep pre | wc -l)

# if we don't have git installed, or we're a release version
# get the version number from the makefile.
makefilever()
{
  VER=$(grep VERSION= Makefile | sed -re '1 s/.*=.*"(.*)".*/\1/')
  if [ "$OLD" != "$VER" ]; then
    hdr
    echo "#define VERSION \""$VER\" >> $HEADER
  fi
}

GIT=`which git 2>/dev/null`
if [ "$DEVEL" == "1" ]; then
  if [ ! -z ${GIT} -a -f ${GIT} -a -d ${0%/*}/../.git ]; then
    VER=$(${GIT} describe --always)
    if [ "$OLD" != "$VER" ]; then
      hdr
      echo "#define VERSION \""$VER\" >> $HEADER
    fi
  else
    makefilever
  fi
else
  makefilever
fi

# FIXME: Delete this after 1.5
C=$(grep VERSION config.h | wc -l)
if [ "$C" != 0 ]; then
  sed -i '/VERSION/d' config.h
fi
