Summary: An FTP daemon originally developed by Washington University.
Name: wu-ftpd

%define ver 2.6.1

Version: %{ver}
Release: 1
Copyright: BSD
Group: System Environment/Daemons
Source: ftp://ftp.wu-ftpd.org/pub/wu-ftpd/wu-ftpd-%{ver}.tar.gz
Requires: pam >= 0.59
Provides: ftpserver
Prereq: fileutils
Buildroot: /var/tmp/wu-ftpd-root

%description
The wu-ftpd package contains the wu-ftpd FTP (File Transfer Protocol)
server daemon.  The FTP protocol is a method of transferring files
between machines on a network and/or over the Internet.  Wu-ftpd's
features include logging of transfers, logging of commands, on the fly
compression and archiving, classification of users' type and location,
per class limits, per directory upload permissions, restricted guest
accounts, system wide and per directory messages, directory alias,
cdpath, filename filter and virtual host support.

Install the wu-ftpd package if you need to provide FTP service to remote
users.

%prep
%setup -q -n wu-ftpd-%{ver}

%build
CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=/usr --enable-badclients
make

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/etc $RPM_BUILD_ROOT/usr/sbin \
	 $RPM_BUILD_ROOT/usr/man/man{1,5,8}
make install prefix=$RPM_BUILD_ROOT/usr
install -m755 util/xferstats $RPM_BUILD_ROOT/usr/sbin
cd doc/examples
install -m 600 ftpusers ftphosts ftpgroups $RPM_BUILD_ROOT/etc
install -m 644 ftpaccess ftpconversions $RPM_BUILD_ROOT/etc
strip $RPM_BUILD_ROOT/usr/sbin/* || :
ln -sf in.ftpd $RPM_BUILD_ROOT/usr/sbin/wu.ftpd
ln -sf in.ftpd $RPM_BUILD_ROOT/usr/sbin/in.wuftpd
mkdir -p $RPM_BUILD_ROOT/etc/pam.d
cat > $RPM_BUILD_ROOT/etc/pam.d/ftp <<EOF
#%PAM-1.0
auth    required pam_listfile.so item=user sense=deny file=/etc/ftpusers onerr=succeed
auth    required pam_pwdb.so shadow nullok
auth    required pam_shells.so
account required pam_pwdb.so
session required pam_pwdb.so
EOF
mkdir -p $RPM_BUILD_ROOT/etc/logrotate.d
cat > $RPM_BUILD_ROOT/etc/logrotate.d/ftpd <<EOF
/var/log/xferlog {
    # ftpd doesn't handle SIGHUP properly
    nocompress
}
EOF
chmod 644 $RPM_BUILD_ROOT/etc/logrotate.d/ftpd
chmod 644 $RPM_BUILD_ROOT/etc/pam.d/ftp

%clean
rm -rf $RPM_BUILD_ROOT

%post
if [ ! -f /var/log/xferlog ]; then
    touch /var/log/xferlog
    chmod 600 /var/log/xferlog
fi

%files
%defattr(-,root,root)
%doc README CHANGES ERRATA VIRTUAL.FTP.SUPPORT CONTRIBUTORS
%doc doc/misc doc/examples
/usr/sbin/*
/usr/bin/*
/usr/man/*/*
%config /etc/ftp*
%config /etc/pam.d/ftp
%config /etc/logrotate.d/ftpd

%changelog
* Sat Sep 18 1999 Bernhard Rosenkraenzer <bero@linux-mandrake.com>
- adations to 2.6.0
- switch to autoconfed build (RPMs are Linux, autoconf works on Linux)
- enable support for broken clients to spare distributors the support
  questions ;)

* Fri Apr 16 1999 Cristian Gafton <gafton@redhat.com>
- crafted the "general use" spec file for automatically building rpms
