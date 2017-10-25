# http://wiki.osdev.org/Building_GCC
# https://gcc.gnu.org/install/configure.html

export PATH=$PATH
export LIBRARY_PATH=/usr/lib/:/usr/lib64:/usr/libexec:/usr/local/lib
BINUTILS=binutils-2.25.1-22.base.el7.x86_64

# For gcc 7.2.0, export mpc and other libs.
# export LD_LIBRARY_PATH=/home/chuhu/opt/gcc-6.2.0/lib:/home/chuhu/opt/gcc-6.2.0/lib64:/home/chuhu/opt/gcc-6.2.0/libexec:/home/chuhu/opt/isl-0.16.1/lib/:/home/chuhu/opt/mpc-0.8.1/lib:/home/chuhu/opt/gmp-4.3.2/lib:/home/chuhu/opt/mpfr-2.4.2/lib:

# Finally, after gcc is installed, env:
# /home/chuhu/opt/gcc-7.2.0/bin:/home/chuhu/opt/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/root/bin:.
# LD_LIBRARY_PATH=/home/chuhu/opt/gcc-7.2.0/lib:/home/chuhu/opt/gcc-7.2.0/lib64:/home/chuhu/opt/gcc-7.2.0/libexec:/home/chuhu/opt/isl-0.16.1/lib/:/home/chuhu/opt/mpc-0.8.1/lib:/home/chuhu/opt/gmp-4.3.2/lib:/home/chuhu/opt/mpfr-2.4.2/lib:



yum install glibc-static libstdc++-static gcc-c++ -y
yum -y install glibc-devel.i686 libgcc.i686 glibc.i686

export PREFIX="/home/chuhu/opt/gcc-5.1.0"

# To the source dir, execute below to download required packages, eg. mpc,mpfr,isl
contrib/download_prerequisites

# To the obj/build dir
#../gcc-4.9.4/configure --prefix="$PREFIX" --disable-nls --enable-languages=c --disable-multilib
#../gcc-5.1.0/configure --prefix="$PREFIX" --disable-nls --enable-languages=c,c++

../gcc-6.2.0/configure --prefix="$PREFIX" --disable-nls --enable-languages=c,c++

# gmp -> mpfr -> mpc -> isl

# mpfr
# ../mpfr-2.4.2/configure --prefix /home/chuhu/opt/mpfr-2.4.2 --with-gmp=/home/chuhu/opt/gmp-4.3.2/
# mpc
# ../mpc-0.8.1/configure --prefix /home/chuhu/opt/mpc-0.8.1 --with-gmp=/home/chuhu/opt/gmp-4.3.2/ --with-mpfr=/home/chuhu/opt/mpfr-2.4.2/
# isl
# ../isl-0.14/configure --prefix /home/chuhu/opt/mpc-0.8.1 --with-gmp-prefix=/home/chuhu/opt/gmp-4.3.2/ --with-mpfr=/home/chuhu/opt/mpfr-2.4.2/

# isl-0.14

 ../gcc-5.4.0/configure --prefix=/home/chuhu/opt/gcc-5.4.0 --disable-nls --enable-languages=c,c++ --with-gmp=/home/chuhu/opt/gmp-4.3.2/ --with-mpfr=/home/chuhu/opt/mpfr-2.4.2 --with-gmp=/home/chuhu/opt/gmp-4.3.2/ --with-isl=/home/chuhu/opt/isl-0.14 --with-mpc=/home/chuhu/opt/mpc-0.8.1/
