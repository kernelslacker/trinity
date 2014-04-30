#!/bin/sh

if [ $(/usr/bin/id -u) -eq 0 ] ; then
  DROPPRIVS=--dropprivs
else
  DROPPRIVS=""
fi
