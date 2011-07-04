#!/bin/bash

if [ ! -d logs ]; then
  mkdir logs
fi

if [ ! -d tmp ]; then
  mkdir tmp
fi
chmod 755 tmp
cd tmp

while [ 1 ];
do
  RND=$RANDOM
  mkdir tmp.$RND
  cd tmp.$RND

  ../../trinity --mode=rotate --logfile=../../logs/trinity-z.log -z -i
  ../../trinity --mode=rotate --logfile=../../logs/trinity-k.log -k -i
  ../../trinity --mode=rotate --logfile=../../logs/trinity-u.log -u -i
  ../../trinity --mode=rotate --logfile=../../logs/trinity-z32.log -z -i --32bit
  ../../trinity --mode=rotate --logfile=../../logs/trinity-k32.log -k -i --32bit
  ../../trinity --mode=rotate --logfile=../../logs/trinity-u32.log -u -i --32bit

  cd ..
  rm -rf tmp.$RND
done

