# Do we want SELinux & Audit
%if "%{?rhel}" == "4"
%global WITH_SELINUX 0
%else
%global WITH_SELINUX 1
%endif

# OpenSSH privilege separation requires a user & group ID
# Will let the system choose the UID/GID for the gsisshd user/group; see later
#%global sshd_uid    74
#%global sshd_gid    74

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

%global gsi_openssh_rel 3
%global gsi_openssh_ver 5.4

%ifarch alpha ia64 ppc64 s390x sparc64 x86_64
%global flavor gcc64
%else
%global flavor gcc32
%endif


Summary: An implementation of the SSH protocol with GSI authentication
Name: gsi-openssh
Version: %{gsi_openssh_ver}
Release: %{gsi_openssh_rel}%{?dist}
URL: http://www.openssh.com/portable.html
#Source0: ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-%{version}.tar.gz
#Source1: ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-%{version}.tar.gz.asc
# This package differs from the upstream OpenSSH tarball in that
# the ACSS cipher is removed by running openssh-nukeacss.sh in
# the unpacked source directory.
Source0: http://downloads.sourceforge.net/cilogon/gsi_openssh-%{version}-src.tar.gz
#Source1: openssh-nukeacss.sh
#Source2: gsisshd.pam
#Source3: gsisshd.init
#
#Patch0: openssh-5.4p1-redhat.patch
##https://bugzilla.mindrot.org/show_bug.cgi?id=1638
#Patch2: openssh-5.3p1-skip-initial.patch
##https://bugzilla.mindrot.org/show_bug.cgi?id=1640
#Patch4: openssh-5.2p1-vendor.patch
##https://bugzilla.mindrot.org/show_bug.cgi?id=1641
#Patch12: openssh-5.4p1-selinux.patch
#Patch13: openssh-5.5p1-mls.patch
##https://bugzilla.mindrot.org/show_bug.cgi?id=1402
#Patch16: openssh-5.3p1-audit.patch
#Patch18: openssh-5.4p1-pam_selinux.patch
##https://bugzilla.mindrot.org/show_bug.cgi?id=1663
#Patch20: openssh-5.5p1-authorized-keys-command.patch
#Patch21: openssh-5.5p1-ldap.patch
##https://bugzilla.mindrot.org/show_bug.cgi?id=1668
#Patch23: openssh-5.5p1-keygen.patch
#Patch24: openssh-4.3p1-fromto-remote.patch
##https://bugzilla.mindrot.org/show_bug.cgi?id=1636
#Patch27: openssh-5.1p1-log-in-chroot.patch
#Patch30: openssh-4.0p1-exit-deadlock.patch
#Patch35: openssh-5.1p1-askpass-progress.patch
#Patch38: openssh-4.3p2-askpass-grab-info.patch
##https://bugzilla.mindrot.org/show_bug.cgi?id=1644
#Patch44: openssh-5.2p1-allow-ip-opts.patch
#Patch49: openssh-4.3p2-gssapi-canohost.patch
#Patch62: openssh-5.1p1-scp-manpage.patch
#Patch65: openssh-5.5p1-fips.patch
##https://bugzilla.mindrot.org/show_bug.cgi?id=1614
#Patch69: openssh-5.3p1-selabel.patch
#Patch71: openssh-5.2p1-edns.patch
#Patch73: openssh-5.5p1-gsskex.patch
##https://bugzilla.mindrot.org/show_bug.cgi?id=1701
#Patch74: openssh-5.3p1-randclean.patch
##https://bugzilla.mindrot.org/show_bug.cgi?id=1740
#Patch76: openssh-5.5p1-staterr.patch
##https://bugzilla.mindrot.org/show_bug.cgi?id=1750
#Patch77: openssh-5.5p1-stderr.patch
##https://bugzilla.mindrot.org/show_bug.cgi?id=1780
#Patch78: openssh-5.5p1-kuserok.patch
#Patch79: openssh-5.5p1-x11.patch
##https://bugzilla.mindrot.org/show_bug.cgi?id=1842
#Patch81: openssh-5.5p1-clientloop.patch
#
## This is the patch that adds GSI support
## Based on http://grid.ncsa.illinois.edu/ssh/dl/patch/openssh-5.5p1.patch
#Patch99: openssh-5.5p1-gsissh.patch

License: BSD
Group: Applications/Internet
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
%if %{nologin}
Requires: /sbin/nologin
%endif

%if 0%{?suse_version} == 0
Requires: initscripts >= 5.20
%else
Requires: sysconfig
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
BuildRequires: openssl-devel >= 0.9.8e
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
BuildRequires: grid-packaging-tools >= 3.4
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
Requires(post): aaa_base
%endif
Requires(pre): /usr/sbin/useradd
%if "%{?rhel}" == "5"
Requires: pam >= 0.99.6-2
%else
Requires: pam >= 1.0.1-3
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
%setup -q -n gsi_openssh-%{version}-src
#%setup -q
#%patch0 -p1 -b .redhat
#%patch2 -p1 -b .skip-initial
#%patch4 -p1 -b .vendor
#
#%if %{WITH_SELINUX}
##SELinux
#%patch12 -p1 -b .selinux
#%patch13 -p1 -b .mls
#%patch16 -p1 -b .audit
#%patch18 -p1 -b .pam_selinux
#%endif
#
#%patch20 -p1 -b .akc
#%patch21 -p1 -b .ldap
#%patch23 -p1 -b .keygen
#%patch24 -p1 -b .fromto-remote
#%patch27 -p1 -b .log-chroot
#%patch30 -p1 -b .exit-deadlock
#%patch35 -p1 -b .progress
#%patch38 -p1 -b .grab-info
#%patch44 -p1 -b .ip-opts
#%patch49 -p1 -b .canohost
#%patch62 -p1 -b .manpage
#%patch65 -p1 -b .fips
#%patch69 -p1 -b .selabel
#%patch71 -p1 -b .edns
#%patch73 -p1 -b .gsskex
#%patch74 -p1 -b .randclean
#%patch76 -p1 -b .staterr
#%patch77 -p1 -b .stderr
#%patch78 -p1 -b .kuserok
#%patch79 -p1 -b .x11
#%patch81 -p1 -b .clientloop
#%patch99 -p1 -b .gsi

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
%if %{kerberos5}
if test -r /etc/profile.d/krb5-devel.sh ; then
	source /etc/profile.d/krb5-devel.sh
fi
krb5_prefix=`krb5-config --prefix`
if test "$krb5_prefix" != "%{_prefix}" ; then
	CPPFLAGS="$CPPFLAGS -I${krb5_prefix}/include -I${krb5_prefix}/include/gssapi"; export CPPFLAGS
	CFLAGS="$CFLAGS -I${krb5_prefix}/include -I${krb5_prefix}/include/gssapi"
	LDFLAGS="$LDFLAGS -L${krb5_prefix}/%{_lib}"; export LDFLAGS
else
	krb5_prefix=
	CPPFLAGS="-I%{_includedir}/gssapi"; export CPPFLAGS
	CFLAGS="$CFLAGS -I%{_includedir}/gssapi"
fi
%endif

LOOK_FOR_FC_GLOBUS_INCLUDE="yes"; export LOOK_FOR_FC_GLOBUS_INCLUDE

%configure \
	--sysconfdir=%{_sysconfdir}/gsissh \
	--libexecdir=%{_libexecdir}/gsissh \
	--datadir=%{_datadir}/gsissh \
	--with-tcp-wrappers \
	--with-default-path=/usr/local/bin:/bin:/usr/bin \
	--with-superuser-path=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin \
	--with-privsep-path=%{_var}/empty/gsisshd \
	--with-privsep-user=gsisshd \
	--enable-vendor-patchlevel="FC-%{version}-%{release}" \
	--disable-strip \
	--without-zlib-version-check \
	--with-ssl-engine \
	--with-authorized-keys-command \
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
	--with-globus-flavor=%{flavor} \
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
install -m755 gsisshd.init $RPM_BUILD_ROOT/etc/rc.d/init.d/gsisshd
%else
install -d $RPM_BUILD_ROOT/etc/init.d
install -m755 gsisshd.init $RPM_BUILD_ROOT/etc/init.d/gsisshd
%endif
install -d $RPM_BUILD_ROOT%{_libexecdir}/gsissh
install -m644 gsisshd.pam $RPM_BUILD_ROOT/etc/pam.d/gsisshd

#rm $RPM_BUILD_ROOT%{_bindir}/gsiscp
#rm $RPM_BUILD_ROOT%{_bindir}/gsisftp
#rm $RPM_BUILD_ROOT%{_bindir}/gsissh
rm $RPM_BUILD_ROOT%{_bindir}/ssh-add
rm $RPM_BUILD_ROOT%{_bindir}/ssh-agent
rm $RPM_BUILD_ROOT%{_bindir}/ssh-keyscan
#rm $RPM_BUILD_ROOT%{_sysconfdir}/gsissh/ldap.conf
#rm $RPM_BUILD_ROOT%{_libexecdir}/gsissh/ssh-ldap-helper
rm $RPM_BUILD_ROOT%{_libexecdir}/gsissh/ssh-pkcs11-helper
rm $RPM_BUILD_ROOT%{_mandir}/man1/ssh-add.1*
rm $RPM_BUILD_ROOT%{_mandir}/man1/ssh-agent.1*
rm $RPM_BUILD_ROOT%{_mandir}/man1/ssh-keyscan.1*
#rm $RPM_BUILD_ROOT%{_mandir}/man1/gsiscp.1*
#rm $RPM_BUILD_ROOT%{_mandir}/man1/gsisftp.1*
#rm $RPM_BUILD_ROOT%{_mandir}/man1/gsissh.1*
#rm $RPM_BUILD_ROOT%{_mandir}/man5/ssh-ldap.conf.5*
#rm $RPM_BUILD_ROOT%{_mandir}/man8/ssh-ldap-helper.8*
rm $RPM_BUILD_ROOT%{_mandir}/man8/ssh-pkcs11-helper.8*

for f in $RPM_BUILD_ROOT%{_bindir}/* \
	 $RPM_BUILD_ROOT%{_sbindir}/* \
	 $RPM_BUILD_ROOT%{_mandir}/man*/* ; do
    mv $f `dirname $f`/gsi`basename $f`
done
ln -sf gsissh $RPM_BUILD_ROOT%{_bindir}/gsislogin
ln -sf gsissh.1 $RPM_BUILD_ROOT%{_mandir}/man1/gsislogin.1

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

%post server
/sbin/chkconfig --add gsisshd

%postun server
/sbin/service gsisshd condrestart > /dev/null 2>&1 || :

%preun server
if [ "$1" = 0 ]
then
	/sbin/service gsisshd stop > /dev/null 2>&1 || :
	/sbin/chkconfig --del gsisshd
fi

%files
%defattr(-,root,root)
%doc CREDITS ChangeLog INSTALL LICENCE LICENSE.globus_usage OVERVIEW PROTOCOL* README README.platform README.privsep README.tun README.dns TODO ChangeLog.gssapi HPN-README
%attr(0755,root,root) %dir %{_sysconfdir}/gsissh
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/gsissh/moduli
%attr(0755,root,root) %{_bindir}/gsissh-keygen
%attr(0644,root,root) %{_mandir}/man1/gsissh-keygen.1*
%attr(0755,root,root) %dir %{_libexecdir}/gsissh
%attr(4755,root,root) %{_libexecdir}/gsissh/ssh-keysign
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
%attr(0755,root,root) /etc/init.d/gsisshd
%endif

%changelog
* Tue May 15 2012 Joseph Bester <bester@mcs.anl.gov> - 5.4-3
- Adjust requirements for SUSE
- Fix path to init script for SUSE

* Thu Sep 01 2011 Joseph Bester <bester@mcs.anl.gov> - 5.4-2
- Update to GT 5.1.2

* Wed Mar 02 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.5p1-1
- Initial packaging
- Based on openssh-5.5p1-24.fc14.2

