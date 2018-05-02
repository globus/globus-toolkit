# Do we want SELinux & Audit
%global WITH_SELINUX 1

# Build position-independent executables (requires toolchain support)?
%global pie 0

# Do we want kerberos5 support (1=yes 0=no)
# It is not possible to support kerberos5 and GSI at the same time
%global kerberos5 0

# Do we want GSI support (1=yes 0=no)
%global gsi 1

# Do we want libedit support
%global libedit 1

# Do we want NSS tokens support
#NSS support is broken from 5.4p1
%global nss 0

# Whether or not /sbin/nologin exists.
%global nologin 1

%if %{?fedora}%{!?fedora:0} >= 28
%global tcpd 0
%else
%global tcpd 1
%endif

%global gsi_openssh_rel 2
%global openssh_ver     7.5p1
%global gsi_openssh_ver %{openssh_ver}b

Summary: An implementation of the SSH protocol with GSI authentication
Name: gsi-openssh
Version: %{gsi_openssh_ver}
Release: %{gsi_openssh_rel}%{?dist}
URL: http://www.openssh.com/portable.html
Source0: http://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-7.5p1.tar.gz
#Source2: gsisshd.pam
#Source3: gsisshd.init
#
#Patch0: https://github.com/rapier1/openssh-portable/compare/V_7_5_P1...hpn-7_5_P1
#Patch0: https://sourceforge.net/projects/hpnssh/files/HPN-SSH%2014v13%207.5p1/openssh-7_5_P1-hpn-14.13.diff
Patch0: https://github.com/globus/gsi-openssh/releases/download/%{version}/openssh-7_5_P1-hpn-14.13.diff
##Patch0 is the HPN-SSH patch to Portable OpenSSH and is constructed as follows if the patch isn't readily available at the above link.
## git clone git@github.com:rapier1/openssh-portable.git
## cd openssh-portable
## git remote add portable https://github.com/openssh/openssh-portable.git
## git fetch portable
## git merge-base hpn-7_5_P1 V_7_5_P1 > common_ancestor
## git diff `cat common_ancestor` hpn-7_5_P1 > ../openssh-7_5_P1-hpn-14.13.diff

##Patch1 is the iSSHD patch to HPN-SSH and is constructed as follows:
## git clone git@github.com:set-element/openssh-hpn-isshd.git
## cd openssh-hpn-isshd
## git remote add hpn https://github.com/rapier1/openssh-portable.git
## git fetch hpn
## git merge-base 72a443b8fe6c23b748d21e5f4a4c97c6bc0ab39c hpn-7_5_P1 > common_ancestor
## git diff `cat common_ancestor` 72a443b8fe6c23b748d21e5f4a4c97c6bc0ab39c > ../hpn-14.13-isshd.v3.19.1.patch
Patch1: https://github.com/globus/gsi-openssh/releases/download/%{version}/hpn-14.13-isshd.v3.19.1.patch
##Patch2 is the GSI patch to be applied on top of the iSSHD patch and is constructed as follows:
## tar xvf openssh-7.5p1.tar.gz
## cd openssh-7.5p1
## patch -p1 --no-backup-if-mismatch < ../openssh-7_5_P1-hpn-14.13.diff
## patch -p1 --no-backup-if-mismatch < ../hpn-14.13-isshd.v3.19.1.patch
## grep "^commit " ChangeLog | tail -1 | cut -d' ' -f2 > ../changelog_last_commit
## cd ..
## git clone https://github.com/globus/gsi-openssh.git
## cd gsi-openssh
## git checkout tags/GSI-7.5p1b
## git log `cat ../changelog_last_commit`^... > ChangeLog
## make -f Makefile.in MANFMT="/usr/bin/nroff -mandoc" SHELL=$SHELL distprep
## rm -fr .git
## cd ..
## diff -Naur openssh-7.5p1 gsi-openssh > hpn_isshd-gsi.7.5p1b.patch
Patch2: https://github.com/globus/gsi-openssh/releases/download/%{version}/hpn_isshd-gsi.7.5p1b.patch
##Patch3 is the OpenSSL 1.1 patch to be applied on top of the GSI patch and is constructed as follows:
## rm -fr gsi-openssh
## git clone https://github.com/globus/gsi-openssh.git
## cd gsi-openssh
## git checkout tags/7.5p1b
## git diff tags/GSI-7.5p1b > ../hpn_isshd-gsi_ossl.7.5p1b.patch
Patch3: https://github.com/globus/gsi-openssh/releases/download/%{version}/hpn_isshd-gsi_ossl.%{version}.patch

License: BSD
Group: Applications/Internet
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
%if %{nologin}
Requires: /sbin/nologin
%endif

%if 0%{?suse_version} == 0
Requires: initscripts >= 5.20
%else
Requires:       sysconfig
Requires:       insserv
Requires(post): %insserv_prereq  %fillup_prereq
BuildRequires:  insserv
%endif

%if 0%{?suse_version} > 0
BuildRequires: openldap2-devel
%else
BuildRequires: openldap-devel
%endif
BuildRequires: autoconf, automake, perl, zlib-devel
%if 0%{?suse_version} > 0
BuildRequires: audit-devel
%else
BuildRequires: audit-libs-devel
%endif
BuildRequires: util-linux, groff
BuildRequires: pam-devel
%if 0%{?suse_version} > 0
BuildRequires: tcpd-devel
BuildRequires: libopenssl-devel
%else
%if %{?fedora}%{!?fedora:0} < 28
# RHEL or Fedora < 28 which deprecates tcpwrappers in place of a real firewall
BuildRequires: tcp_wrappers-devel
%endif
BuildRequires: openssl-devel >= 0.9.8j
%endif

%if %{kerberos5}
BuildRequires: krb5-devel
%endif

%if %{gsi}
BuildRequires: globus-gss-assist-devel >= 8
BuildRequires: globus-usage-devel >= 3
BuildRequires: globus-common-progs >= 14
BuildRequires: globus-gssapi-gsi-devel >= 12.12
BuildRequires:  pkgconfig
Requires: globus-gssapi-gsi >= 12.12
%if 0%{?suse_version} > 0
BuildRequires: libtool
%else
BuildRequires: libtool-ltdl-devel
%endif
%endif

%if %{libedit}
BuildRequires: libedit-devel ncurses-devel
%endif

%if %{nss}
BuildRequires: nss-devel
%endif

%if %{WITH_SELINUX}
%if 0%{?suse_version} > 0
Requires: libselinux1 >= 1.27.7
%else
Requires: libselinux >= 1.27.7
%endif
BuildRequires: libselinux-devel >= 1.27.7
Requires: audit-libs >= 1.0.8
BuildRequires: audit-libs >= 1.0.8
%endif

%if 0%{?suse_version} > 0
BuildRequires: xorg-x11-xauth
%else
BuildRequires: xauth
%endif

%package clients
Summary: SSH client applications with GSI authentication
Requires: %{name} = %{version}-%{release}
Group: Applications/Internet

%package server
Summary: SSH server daemon with GSI authentication
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
%if 0%{?suse_version} == 0
Requires(post): chkconfig >= 0.9, /sbin/service
%else
BuildRequires:  shadow
Requires(pre):  shadow
Requires(post): aaa_base
%endif
Requires(pre): /usr/sbin/useradd
%if 0%{?rhel} == 05
Requires: pam >= 0.99.6-2
%else
%if 0%{?rhel} == 04
Requires: pam >= 0.77
%else
Requires: pam >= 1.0.1-3
%endif
%endif

%description
SSH (Secure SHell) is a program for logging into and executing
commands on a remote machine. SSH is intended to replace rlogin and
rsh, and to provide secure encrypted communications between two
untrusted hosts over an insecure network. X11 connections and
arbitrary TCP/IP ports can also be forwarded over the secure channel.

OpenSSH is OpenBSD's version of the last free version of SSH, bringing
it up to date in terms of security and features. This version of OpenSSH
has been modified to support GSI authentication.

This package includes the core files necessary for both the gsissh
client and server. To make this package useful, you should also
install gsissh-clients, gsissh-server, or both.

%description clients
OpenSSH is a free version of SSH (Secure SHell), a program for logging
into and executing commands on a remote machine. This package includes
the clients necessary to make encrypted connections to SSH servers.

This version of OpenSSH has been modified to support GSI authentication.

%description server
OpenSSH is a free version of SSH (Secure SHell), a program for logging
into and executing commands on a remote machine. This package contains
the secure shell daemon (sshd). The sshd daemon allows SSH clients to
securely connect to your SSH server.

This version of OpenSSH has been modified to support GSI authentication.

%prep
%setup -q -n openssh-%{openssh_ver}
%patch0 -p1
%patch1 -p1 -F 2
%patch2 -p1
%patch3 -p1

sed 's/sshd.pid/gsisshd.pid/' -i pathnames.h
sed 's!$(piddir)/sshd.pid!$(piddir)/gsisshd.pid!' -i Makefile.in

autoreconf

%build

%if %{?rhel}%{!?rhel:0} == 5
export CFLAGS="$RPM_OPT_FLAGS"
export OPENSSL_CFLAGS="$(pkg-config openssl101e --cflags)";
export OPENSSL_LIBS="$(pkg-config openssl101e --libs)";
sed -e 's/0\.22/0\.21/' < configure  > configure.new
mv configure.new configure
chmod a+x configure
%else
CFLAGS="$RPM_OPT_FLAGS"; export CFLAGS
LIBS="-lcrypto"; export LIBS
%endif
%if %{pie}
%ifarch s390 s390x sparc sparcv9 sparc64
CFLAGS="$CFLAGS -fPIC"
%else
CFLAGS="$CFLAGS -fpic"
%endif
export CFLAGS
SAVE_LDFLAGS="$LDFLAGS"
LDFLAGS="$LDFLAGS -pie -z relro -z now"; export LDFLAGS
%endif

%configure \
	--sysconfdir=%{_sysconfdir}/gsissh \
	--libexecdir=%{_libexecdir}/gsissh \
	--datadir=%{_datadir}/gsissh \
%if %{tcpd}
	--with-tcp-wrappers \
%endif
	--with-default-path=/usr/local/bin:/bin:/usr/bin \
	--with-superuser-path=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin \
	--with-privsep-path=%{_var}/empty/gsisshd \
	--with-privsep-user=gsisshd \
	--enable-vendor-patchlevel="GT6-%{version}-%{release}" \
	--disable-strip \
	--without-zlib-version-check \
	--with-ssl-engine \
	--with-authorized-keys-command \
	--with-nerscmod \
%if %{nss}
	--with-nss \
%endif
	--with-pam \
%if %{WITH_SELINUX}
	--with-selinux --with-linux-audit \
%endif
%if %{kerberos5}
	--with-kerberos5${krb5_prefix:+=${krb5_prefix}} \
%else
	--without-kerberos5 \
%endif
%if %{gsi}
	--with-gsi=/usr \
%else
	--without-gsi \
%endif
%if %{libedit}
	--with-libedit
%else
	--without-libedit
%endif

make SSH_PROGRAM=%{_bindir}/gsissh \
     ASKPASS_PROGRAM=%{_libexecdir}/openssh/ssh-askpass \
     top_builddir="$PWD"

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p -m755 $RPM_BUILD_ROOT%{_sysconfdir}/gsissh
mkdir -p -m755 $RPM_BUILD_ROOT%{_libexecdir}/gsissh
mkdir -p -m755 $RPM_BUILD_ROOT%{_var}/empty/gsisshd
make install sysconfdir=%{_sysconfdir}/gsissh \
     bindir=%{_bindir} DESTDIR=$RPM_BUILD_ROOT \
     top_builddir="$PWD"

install -d $RPM_BUILD_ROOT/etc/pam.d/
%if 0%{?suse_version} == 0
install -d $RPM_BUILD_ROOT/etc/rc.d/init.d
install -m755 $RPM_BUILD_DIR/openssh-%{openssh_ver}/contrib/redhat/gsisshd.init $RPM_BUILD_ROOT/etc/rc.d/init.d/gsisshd
%else
install -d $RPM_BUILD_ROOT/etc/init.d
install -m755 $RPM_BUILD_DIR/openssh-%{openssh_ver}/contrib/redhat/gsisshd.init $RPM_BUILD_ROOT/etc/init.d/gsi-openssh-server
%endif
install -d $RPM_BUILD_ROOT%{_libexecdir}/gsissh
install -m644 $RPM_BUILD_DIR/openssh-%{openssh_ver}/contrib/redhat/gsisshd.pam $RPM_BUILD_ROOT/etc/pam.d/gsisshd

rm $RPM_BUILD_ROOT%{_bindir}/gsissh-add
rm $RPM_BUILD_ROOT%{_bindir}/gsissh-agent
rm $RPM_BUILD_ROOT%{_bindir}/gsissh-keyscan
rm $RPM_BUILD_ROOT%{_libexecdir}/gsissh/ssh-pkcs11-helper
rm $RPM_BUILD_ROOT%{_mandir}/man1/gsissh-add.1*
rm $RPM_BUILD_ROOT%{_mandir}/man1/gsissh-agent.1*
rm $RPM_BUILD_ROOT%{_mandir}/man1/gsissh-keyscan.1*
rm $RPM_BUILD_ROOT%{_mandir}/man8/gsissh-pkcs11-helper.8*

perl -pi -e "s|$RPM_BUILD_ROOT||g" $RPM_BUILD_ROOT%{_mandir}/man*/*

rm -f README.nss.nss-keys
%if ! %{nss}
rm -f README.nss
%endif

%clean
rm -rf $RPM_BUILD_ROOT

%pre server
getent group gsisshd >/dev/null || groupadd -r gsisshd || :
%if %{nologin}
getent passwd gsisshd >/dev/null || \
  useradd -c "Privilege-separated GSISSH" -g gsisshd \
  -s /sbin/nologin -r -d /var/empty/gsisshd gsisshd 2> /dev/null || :
%else
getent passwd gsisshd >/dev/null || \
  useradd -c "Privilege-separated GSISSH" -g gsisshd \
  -s /dev/null -r -d /var/empty/gsisshd gsisshd 2> /dev/null || :
%endif

%if %{?suse_version}%{!?suse_version:0} >= 1315
%post
chmod 4755 %{_libexecdir}/gsissh/ssh-keysign
%endif

%post server
%if %{?suse_version}%{!?suse_version:0} >= 1315
%fillup_and_insserv gsi-openssh-server
%else
/sbin/chkconfig --add gsisshd
%endif
if [ -f /etc/ssh/ssh_host_dsa_key ]
then
	ln -sf  /etc/ssh/ssh_host_dsa_key /etc/gsissh/ssh_host_dsa_key
fi
if [ -f /etc/ssh/ssh_host_dsa_key.pub ]
then
	/bin/ln -sf  /etc/ssh/ssh_host_dsa_key.pub /etc/gsissh/ssh_host_dsa_key.pub
fi
if [ -f /etc/ssh/ssh_host_rsa_key ]
then
	/bin/ln -sf  /etc/ssh/ssh_host_rsa_key /etc/gsissh/ssh_host_rsa_key
fi
if [ -f /etc/ssh/ssh_host_rsa_key.pub ]
then
	/bin/ln -sf /etc/ssh/ssh_host_rsa_key.pub /etc/gsissh/ssh_host_rsa_key.pub
fi
if [ -f /etc/ssh/ssh_host_ecdsa_key ]
then
	/bin/ln -sf  /etc/ssh/ssh_host_ecdsa_key /etc/gsissh/ssh_host_ecdsa_key
fi
if [ -f /etc/ssh/ssh_host_ecdsa_key.pub ]
then
	/bin/ln -sf /etc/ssh/ssh_host_ecdsa_key.pub /etc/gsissh/ssh_host_ecdsa_key.pub
fi
if [ -f /etc/ssh/ssh_host_ed25519_key ]
then
	/bin/ln -sf  /etc/ssh/ssh_host_ed25519_key /etc/gsissh/ssh_host_ed25519_key
fi
if [ -f /etc/ssh/ssh_host_ed25519_key.pub ]
then
	/bin/ln -sf /etc/ssh/ssh_host_ed25519_key.pub /etc/gsissh/ssh_host_ed25519_key.pub
fi

%postun server
%if %{?suse_version}%{!?suse_version:0} >= 1315
%restart_on_update service
%insserv_cleanup
%else
/sbin/service gsisshd condrestart > /dev/null 2>&1 || :
%endif

%preun server
if [ "$1" = 0 ]
then
%if %{?suse_version}%{!?suse_version:0} >= 1315
%stop_on_removal service
%else
	/sbin/service gsisshd stop > /dev/null 2>&1 || :
	/sbin/chkconfig --del gsisshd
%endif
	/bin/rm -f /etc/gsissh/ssh_host_dsa_key
	/bin/rm -f /etc/gsissh/ssh_host_dsa_key.pub
	/bin/rm -f /etc/gsissh/ssh_host_rsa_key
	/bin/rm -f /etc/gsissh/ssh_host_rsa_key.pub
	/bin/rm -f /etc/gsissh/ssh_host_ecdsa_key
	/bin/rm -f /etc/gsissh/ssh_host_ecdsa_key.pub
	/bin/rm -f /etc/gsissh/ssh_host_ed25519_key
	/bin/rm -f /etc/gsissh/ssh_host_ed25519_key.pub
fi

%files
%defattr(-,root,root)
%doc CREDITS ChangeLog INSTALL LICENCE LICENSE.globus_usage OVERVIEW PROTOCOL* README README.platform README.privsep README.tun README.dns TODO ChangeLog.gssapi HPN-README
%attr(0755,root,root) %dir %{_sysconfdir}/gsissh
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/gsissh/moduli
%attr(0755,root,root) %{_bindir}/gsissh-keygen
%attr(0644,root,root) %{_mandir}/man1/gsissh-keygen.1*
%attr(0755,root,root) %dir %{_libexecdir}/gsissh
%if %{?suse_version}%{!?suse_version:0} >= 1315
%attr(0755,root,root) %{_libexecdir}/gsissh/ssh-keysign
%else
%attr(4755,root,root) %{_libexecdir}/gsissh/ssh-keysign
%endif
%attr(0644,root,root) %{_mandir}/man8/gsissh-keysign.8*

%files clients
%defattr(-,root,root)
%attr(0755,root,root) %{_bindir}/gsissh
%attr(0644,root,root) %{_mandir}/man1/gsissh.1*
%attr(0755,root,root) %{_bindir}/gsiscp
%attr(0644,root,root) %{_mandir}/man1/gsiscp.1*
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/gsissh/ssh_config
%attr(0644,root,root) %{_mandir}/man5/gsissh_config.5*
%attr(0755,root,root) %{_bindir}/gsisftp
%attr(0644,root,root) %{_mandir}/man1/gsisftp.1*

%files server
%defattr(-,root,root)
%if 0%{?suse_version} > 0
%dir %attr(0711,root,root) %{_var}/empty
%endif
%dir %attr(0711,root,root) %{_var}/empty/gsisshd
%attr(0755,root,root) %{_sbindir}/gsisshd
%attr(0755,root,root) %{_libexecdir}/gsissh/sftp-server
%attr(0644,root,root) %{_mandir}/man5/gsisshd_config.5*
%attr(0644,root,root) %{_mandir}/man5/gsimoduli.5*
%attr(0644,root,root) %{_mandir}/man8/gsisshd.8*
%attr(0644,root,root) %{_mandir}/man8/gsisftp-server.8*
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/gsissh/sshd_config
%attr(0644,root,root) %config(noreplace) /etc/pam.d/gsisshd
%if 0%{?suse_version} == 0
%attr(0755,root,root) /etc/rc.d/init.d/gsisshd
%else
%attr(0755,root,root) /etc/init.d/gsi-openssh-server
%endif

%changelog
* Wed May  2 2018 Globus Toolkit <support@globus.org> - 7.5p1b-2
- Remove deprecated dependency on tcp_wrappers-devel for Fedora 28

* Tue Jun 27 2017 Globus Toolkit <support@globus.org> - 7.5p1b-1
- Update to GSI-OpenSSH 7.5p1b

* Mon Apr 17 2017 Globus Toolkit <support@globus.org> - 7.3p1c-1
- Update to GSI-OpenSSH 7.3p1c

* Mon Apr  3 2017 Globus Toolkit <support@globus.org> - 7.3p1b-1
- Update to GSI-OpenSSH 7.3p1b

* Fri Mar 24 2017 Globus Toolkit <support@globus.org> - 7.3p1a-1
- Update to GSI-OpenSSH 7.3p1a

* Tue Dec 13 2016 Globus Toolkit <support@globus.org> - 7.1p2g-2
- Only create /var/empty for SLES

* Tue Aug 30 2016 Globus Toolkit <support@globus.org> - 7.1p2f-4
- Updates for SLES 12
- Updates for el.5 with openssl101e

* Tue Jun  7 2016 Globus Toolkit <support@globus.org> - 7.1p2f-1
- Fix to use sshd_config from installed location for installations from the
  source and binary tarballs.
- DisableUsageStats now defaults to Yes in code (already defaults to Yes in the
  supplied sshd_config). Also moved the DisableUsageStats directive to be ahead
  of the Match directives in sshd_config.

* Thu May 12 2016 Globus Toolkit <support@globus.org> - 7.1p2e-1
- default iSSHD auditing to disabled

* Mon Apr 25 2016 Globus Toolkit <support@globus.org> - 7.1p2c-2
- Change source URL
- Create symlinks only to system-standard ssh host keys that are present

* Fri Mar 11 2016 Globus Toolkit <support@globus.org> - 7.1p2c-1
- Fixes for Globus Toolkit builds: Skip probing for specific globus funcs
- Fixes for building kerberos/mechglue without GSI.

* Fri Mar  4 2016 Globus Toolkit <support@globus.org> - 7.1p2-1b
- Update to 7.1p2b

* Tue Feb  9 2016 Globus Toolkit <support@globus.org> - 7.1p2-1a
- Update to 7.1p2a

* Mon Nov 11 2013 Globus Toolkit <support@globus.org> - 5.7-1
- Update to 5.7

* Tue Apr 02 2013 Globus Toolkit <support@globus.org> - 5.6-1
- Update to 5.6

* Mon Mar 11 2013 Joseph Bester <bester@mcs.anl.gov> - 5.5-2
- Update dependencies

* Tue Jun 26 2012 Joseph Bester <bester@mcs.anl.gov> - 5.5-1
- Update to the 5.5 release

* Wed May 23 2012 Joseph Bester <bester@mcs.anl.gov> - 5.4-4
- Reduce pam required version for CentOS 4

* Tue May 15 2012 Joseph Bester <bester@mcs.anl.gov> - 5.4-3
- Adjust requirements for SUSE
- Fix path to init script for SUSE

* Thu Sep 01 2011 Joseph Bester <bester@mcs.anl.gov> - 5.4-2
- Update to GT 5.1.2

* Wed Mar 02 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.5p1-1
- Initial packaging
- Based on openssh-5.5p1-24.fc14.2

