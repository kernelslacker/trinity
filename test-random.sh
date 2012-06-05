#!/bin/bash

if [ ! -d tmp ]; then
  mkdir tmp
fi
chmod 755 tmp
cd tmp

NR_CPUS=`grep ^processor /proc/cpuinfo | /usr/bin/wc -l`
NR_PROCESSES=$(($NR_CPUS * 2))

while [ 1 ];
do
  RND=$RANDOM
  mkdir tmp.$RND
  cd tmp.$RND
  for i in `seq 1 $NR_PROCESSES`
  do
	MALLOC_CHECK_=2 ../../trinity -q -l off -x lgetxattr -x fgetxattr -x getxattr &
  done
  wait
  cd ..
  chmod 755 ../tmp
  rm -rf tmp.$RND
done
