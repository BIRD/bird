Summary: BIRD Internet Routing Daemon
Name: bird
Version: 1.6.2
Release: 1
Copyright: GPL
Group: Networking/Daemons
Source: ftp://bird.network.cz/pub/bird/bird-%{version}.tar.gz
Source1: bird.init
Source2: birdc6
Buildroot: /var/tmp/bird-root
Url: http://bird.network.cz
Prereq: /sbin/chkconfig
BuildRequires: flex bison readline-devel ncurses-devel

%description
BIRD is dynamic routing daemon supporting IPv4 and IPv6 versions of routing
protocols BGP, RIP and OSPF.

%prep
%setup -n bird-%{version}

%build
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --enable-ipv6
make
mv bird bird6
make clean
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var
make


%install
rm -rf $RPM_BUILD_ROOT/*
make install prefix=$RPM_BUILD_ROOT/usr sysconfdir=$RPM_BUILD_ROOT/etc localstatedir=$RPM_BUILD_ROOT/var
install bird6 $RPM_BUILD_ROOT/usr/sbin

cd $RPM_BUILD_ROOT
install -d etc/rc.d/init.d
install $RPM_SOURCE_DIR/bird.init etc/rc.d/init.d/bird
install $RPM_SOURCE_DIR/birdc6 usr/sbin/birdc6

%post
/sbin/ldconfig
/sbin/chkconfig --add bird

%preun
if [ $1 = 0 ] ; then
        /sbin/chkconfig --del bird
fi

%files
%attr(755,root,root) /usr/sbin/bird
%attr(755,root,root) /usr/sbin/bird6
%attr(755,root,root) /usr/sbin/birdc
%attr(755,root,root) /usr/sbin/birdc6
%attr(755,root,root) /etc/rc.d/init.d/bird
