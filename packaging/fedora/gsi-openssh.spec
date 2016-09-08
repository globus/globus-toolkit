# Do we want SELinux & Audit
%if "%{?rhel}" == "4"
%global WITH_SELINUX 0
%else
%global WITH_SELINUX 1
%endif

# Build position-independent executables (requires toolchain support)?
%global pie 0

# Do we want kerberos5 support (1=yes 0=no)
# It is not possible to support kerberos5 and GSI at the same time
%global kerberos5 0

# Do we want GSI support (1=yes 0=no)
%global gsi 1

# Do we want libedit support
%if "%{?rhel}" == "4" || "%{?rhel}" == "5"
%global libedit 0
%else
%global libedit 1
%endif

# Do we want NSS tokens support
#NSS support is broken from 5.4p1
%global nss 0

# Whether or not /sbin/nologin exists.
%global nologin 1

%global gsi_openssh_rel 2
%global gsi_openssh_ver 7.1p2f

Summary: An implementation of the SSH protocol with GSI authentication
Name: gsi-openssh
Version: %{gsi_openssh_ver}
Release: %{gsi_openssh_rel}%{?dist}
URL: http://www.openssh.com/portable.html
Source0: http://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-7.1p2.tar.gz
#Source2: gsisshd.pam
#Source3: gsisshd.init
#
#Patch0: http://sourceforge.net/projects/hpnssh/files/HPN-SSH%2014v10%207.1p2/openssh-7_1_P2-hpn-14.10.diff
Patch0: https://github.com/globus/gsi-openssh/releases/download/%{version}/openssh-7_1_P2-hpn-14.10.diff
##Patch0 is the HPN-SSH patch to Portable OpenSSH and is constructed as follows if the patch isn't readily available at the above link.
## git clone git@github.com:rapier1/openssh-portable.git
## cd openssh-portable
## git remote add portable https://github.com/openssh/openssh-portable.git
## git fetch portable
## git merge-base hpn-7_1_P2 V_7_1_P2 > common_ancestor
## git diff `cat common_ancestor` hpn-7_1_P2 > openssh-7_1_P2-hpn-14.10.diff

##Patch1 is the iSSHD patch to HPN-SSH and is constructed as follows:
## git clone git@github.com:set-element/openssh-hpn-isshd.git
## cd openssh-hpn-isshd
## git remote add hpn https://github.com/rapier1/openssh-portable.git
## git fetch hpn
## git merge-base v3.19.1 hpn-7_1_P2 > common_ancestor
## git diff `cat common_ancestor` v3.19.1 > hpn-isshd.v3.19.1.patch
Patch1: https://github.com/globus/gsi-openssh/releases/download/%{version}/hpn-isshd.v3.19.1.patch
##Patch2 is the GSI patch to be applied on top of the iSSHD patch and is constructed as follows:
## tar xvf openssh-7.1p2.tar.gz
## cd openssh-7.1p2
## patch -p1 --no-backup-if-mismatch < openssh-7_1_P2-hpn-14.10.diff
## patch -p1 --no-backup-if-mismatch < hpn-isshd.v3.19.1.patch
## grep "^commit " ChangeLog | tail -1 | cut -d' ' -f2 > ../changelog_last_commit
## cd ..
## git clone https://github.com/globus/gsi-openssh.git
## cd gsi-openssh
## git checkout tags/7.1p2f
## git log `cat ../changelog_last_commit`^... > ChangeLog
## make -f Makefile.in MANFMT="/usr/bin/nroff -mandoc" SHELL=$SHELL distprep
## rm -fr .git
## cd ..
## diff -Naur openssh-7.1p2 gsi-openssh > hpn_isshd-gsi.7.1p2f.patch
Patch2: https://github.com/globus/gsi-openssh/releases/download/%{version}/hpn_isshd-gsi.%{version}.patch

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
%if "%{?rhel}" == "5"
BuildRequires: tcp_wrappers
BuildRequires: openssl101e-devel
BuildConflicts: openssl-devel
%else
%if "%{?rhel}" == "4"
BuildRequires: openssl-devel
%else
BuildRequires: tcp_wrappers-devel
BuildRequires: openssl-devel >= 0.9.8j
%endif
%endif
%endif

%if %{kerberos5}
BuildRequires: krb5-devel
%endif

%if %{gsi}
BuildRequires: globus-gss-assist-devel >= 8
BuildRequires: globus-usage-devel >= 3
BuildRequires: globus-common-progs >= 14
BuildRequires: globus-gssapi-gsi-devel
BuildRequires:  pkgconfig
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
%setup -q -n openssh-7.1p2
%patch0 -p1
%patch1 -p1 -F 2
%patch2 -p1

sed 's/sshd.pid/gsisshd.pid/' -i pathnames.h
sed 's!$(piddir)/sshd.pid!$(piddir)/gsisshd.pid!' -i Makefile.in

autoreconf

%build
CFLAGS="$RPM_OPT_FLAGS"; export CFLAGS
LIBS="-lcrypto"; export LIBS
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
	--with-tcp-wrappers \
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
     ASKPASS_PROGRAM=%{_libexecdir}/openssh/ssh-askpass

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p -m755 $RPM_BUILD_ROOT%{_sysconfdir}/gsissh
mkdir -p -m755 $RPM_BUILD_ROOT%{_libexecdir}/gsissh
mkdir -p -m755 $RPM_BUILD_ROOT%{_var}/empty/gsisshd
make install sysconfdir=%{_sysconfdir}/gsissh \
     bindir=%{_bindir} DESTDIR=$RPM_BUILD_ROOT

install -d $RPM_BUILD_ROOT/etc/pam.d/
%if 0%{?suse_version} == 0
install -d $RPM_BUILD_ROOT/etc/rc.d/init.d
install -m755 $RPM_BUILD_DIR/openssh-7.1p2/contrib/redhat/gsisshd.init $RPM_BUILD_ROOT/etc/rc.d/init.d/gsisshd
%else
install -d $RPM_BUILD_ROOT/etc/init.d
install -m755 $RPM_BUILD_DIR/openssh-7.1p2/contrib/redhat/gsisshd.init $RPM_BUILD_ROOT/etc/init.d/gsi-openssh-server
%endif
install -d $RPM_BUILD_ROOT%{_libexecdir}/gsissh
install -m644 $RPM_BUILD_DIR/openssh-7.1p2/contrib/redhat/gsisshd.pam $RPM_BUILD_ROOT/etc/pam.d/gsisshd

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
%attr(0755,root,root) %{_bindir}/gsislogin
%attr(0644,root,root) %{_mandir}/man1/gsislogin.1*
%attr(0644,root,root) %{_mandir}/man5/gsissh_config.5*
%attr(0755,root,root) %{_bindir}/gsisftp
%attr(0644,root,root) %{_mandir}/man1/gsisftp.1*

%files server
%defattr(-,root,root)
%dir %attr(0711,root,root) %{_var}/empty
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
* Tue Aug 30 2016 Globus Toolkit <support@globus.org> - 7.1p2f-2
- Updates for SLES 12

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

