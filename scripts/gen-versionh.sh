#!/bin/sh

DEVEL=$(grep VERSION Makefile | head -n1 | grep pre | wc -l)

echo "#pragma once" > version.h
echo "/* This file is auto-generated */" >> version.h

if [ "$DEVEL" == "1" ]; then
  if [ ! -f /usr/bin/git ]; then
    echo -n "#define " >> version.h
    grep VERSION= Makefile | sed 's/=/ /' >> version.h
  else
    VER=$(git describe --always)
    echo "#define VERSION \""$VER\" >> version.h
  fi
else
  echo -n "#define " >> version.h
  grep VERSION= Makefile | sed 's/=/ /' >> version.h
fi

