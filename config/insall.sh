# Graphical
yum -y instalol xorg-x11-*
yum -y install gnome*
startx 

yum -y install ibus-libpinyin
yum -y install libpinyin.x86_64


# Setup timezone
timedatectl  list-timezones
timedatectl  set-timezone Asia/Shanghai

yum -y install vim
yum -y install emacs

yum -y install openssl-devel-1.0.1e-42.el7_1.9.x86_64
yum -y install openssl-devel-1.0.1e-51.el7_2.4.x86_64
yum -y install kernel-devel kernel-header
yum -y install xchat
yum -y install wget curl

yum -y install dracut
yum -y install rpm
yum -y install rpm-build
yum -y install yum-utils
yum -y install trace-cmd perf crash

yum -y install rhts-devel
yum -y install beakerlib-redhat

yum -y install krb5-workstation.x86_64
cp /root/krb5.conf  /etc/

yum -y install beaker-client
[ -f /etc/yum.repos.d/rhel7-eng-rhel-7.repo ] || wget -P /etc/yum.repos.d http://yum.devel.redhat.com/pub/yum/repo_files/rhel7-eng-rhel-7.repo
yum -y --enablerepo=eng-rhel-7 install conserver-client
wget -O /etc/yum.repos.d/qa-tools.repo http://liver.brq.redhat.com/repo/qa-tools.repo
yum -y install qa-tools-workstation


yum-builddep -y rpmbuild/SPECS/kernel.spec 

cd linux-stable/
cp /boot/config-3.10.0-357.el7.x86_64  ./.config
make olddefconfig
make prepare modules_prepare
make all -j 48 && make install modules_install -j 48
dracut --kver 4.5.0-rc7+ --force

kinit 
systemctl start sshd
patch -p1 < ../0001-Linux-4.5-rc7.patch 

# Git 
git clone git+ssh://chuhu@code.engineering.redhat.com/kernel-general
git clone https://github.com/linux-test-project/ltp
git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
git clone ssh://chuhu@pkgs.devel.redhat.com/tests/kernel

cat  > ~/.consolerc <<EOF
config * {
	username chuhu@redhat.com;
}
EOF

# Proxy for firefox/chrom
http://file.nay.redhat.com/lilu/proxy.pac

# For conclient, please put it to ~/.barhrc
function console()
{

local OPT=$(shopt -p -o nounset)
set -o nounset

         # Treat unset variables as an error

local HOST=$1

local CONSERVER

case ${HOST} in

    *bne*) CONSERVER="conserver-01.app.eng.bne.redhat.com";;

    *rdu*) CONSERVER="conserver-01.app.eng.rdu.redhat.com";;

    *bos*) CONSERVER="conserver-02.eng.bos.redhat.com";;

    *brq*) CONSERVER="conserver.englab.brq.redhat.com";;

    *nay*) CONSERVER="console.lab.eng.nay.redhat.com";;

    *)     CONSERVER="conserver-01.eng.bos.redhat.com";;

esac

/usr/bin/console -M ${CONSERVER} ${HOST}

eval ${OPT}

}

