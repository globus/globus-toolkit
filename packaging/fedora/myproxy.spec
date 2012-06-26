%{!?_initddir: %global _initddir %{_initrddir}}

%ifarch alpha ia64 ppc64 s390x sparc64 x86_64
%global flavor gcc64
%else
%global flavor gcc32
%endif

Name:           myproxy
Version:	5.8
Release:	1%{?dist}
Summary:        Manage X.509 Public Key Infrastructure (PKI) security credentials

Group:          System Environment/Daemons
License:        NCSA and BSD and ASL 2.0
URL:            http://grid.ncsa.illinois.edu/myproxy/
Source0:        http://downloads.sourceforge.net/cilogon/myproxy-%{version}.tar.gz

#Source1:        myproxy.init
#Source2:        myproxy.sysconfig
#Source3:        README.Fedora

#VOMS has two alternate APIs which are the "same". vomsapi is the
#newer though not that new. myproxy is the last software in
#EPEL using the old vomsc.
#Patch to go upstream myproxy though they are aware.
#Patch0:         myproxy-vomsc-vomsapi.patch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  globus-gss-assist-devel >= 8
BuildRequires:  globus-usage-devel >= 3
BuildRequires:  pam-devel
BuildRequires:  graphviz
%if 0%{?suse_version} == 0
BuildRequires:  voms-devel >= 1.9.12.1
%endif
BuildRequires:  cyrus-sasl-devel
%if "%{?rhel}" != "4"
BuildRequires:  openldap-devel >= 2.3
%endif
BuildRequires:  grid-packaging-tools  >= 3.4
BuildRequires:  doxygen

%if "%{?rhel}" == "5"
BuildRequires: graphviz-gd
%endif

%if %{?fedora}%{!?fedora:0} >= 9 || %{?rhel}%{!?rhel:0} >= 6
BuildRequires:  tex(latex)
%else
%if 0%{?suse_version} > 0
BuildRequires:  texlive-latex
%else
BuildRequires:  tetex-latex
%endif
%endif

Requires:      myproxy-libs = %{version}-%{release}
Requires:      globus-proxy-utils >= 5
%if 0%{?suse_version} == 0
Requires:      voms-clients
%endif

Obsoletes:     myproxy-client < 5.1-3
Provides:      myproxy-client = %{version}-%{release}

%description
MyProxy is open source software for managing X.509 Public Key Infrastructure 
(PKI) security credentials (certificates and private keys). MyProxy 
combines an online credential repository with an online certificate 
authority to allow users to securely obtain credentials when and where needed.
Users run myproxy-logon to authenticate and obtain credentials, including 
trusted CA certificates and Certificate Revocation Lists (CRLs). 

%package libs
Summary:       Manage X.509 Public Key Infrastructure (PKI) security credentials 
Group:         System Environment/Daemons
Obsoletes:     myproxy < 5.1-3

%description libs
MyProxy is open source software for managing X.509 Public Key Infrastructure 
(PKI) security credentials (certificates and private keys). MyProxy 
combines an online credential repository with an online certificate 
authority to allow users to securely obtain credentials when and where needed.
Users run myproxy-logon to authenticate and obtain credentials, including 
trusted CA certificates and Certificate Revocation Lists (CRLs). 

Package %{name}-libs contains runtime libs for MyProxy.

%package devel
Requires:      myproxy-libs = %{version}-%{release}
# in .el5 and 4 this dependency is not picked up
# automatically via pkgconfig
%if  0%{?el4}%{?el5}
Requires:      globus-gss-assist-devel > 8
Requires:      globus-usage-devel >= 3
%endif

Summary:       Develop X.509 Public Key Infrastructure (PKI) security credentials 
Group:         System Environment/Daemons

%description devel
MyProxy is open source software for managing X.509 Public Key Infrastructure 
(PKI) security credentials (certificates and private keys). MyProxy 
combines an online credential repository with an online certificate 
authority to allow users to securely obtain credentials when and where needed.
Users run myproxy-logon to authenticate and obtain credentials, including 
trusted CA certificates and Certificate Revocation Lists (CRLs). 

Package %{name}-devel contains development files for MyProxy.

%package server
Requires(pre):    shadow-utils
Requires(post):   chkconfig
Requires(preun):  chkconfig
%if 0%{?suse_version} == 0
Requires(preun):  initscripts
Requires(postun): initscripts
%else
Requires(preun):  sysconfig
Requires(preun):  aaa_base
Requires(postun): sysconfig
Requires(postun): aaa_base
%endif
Requires:         myproxy-libs = %{version}-%{release}
Summary:          Server for X.509 Public Key Infrastructure (PKI) security credentials 
Group:            System Environment/Daemons

%description server
MyProxy is open source software for managing X.509 Public Key Infrastructure 
(PKI) security credentials (certificates and private keys). MyProxy 
combines an online credential repository with an online certificate 
authority to allow users to securely obtain credentials when and where needed.
Users run myproxy-logon to authenticate and obtain credentials, including 
trusted CA certificates and Certificate Revocation Lists (CRLs). 

Package %{name}-server contains the MyProxy server.

# Create a sepeate admin clients package since they
# not needed for normal operation and pull in
# a load of perl dependencies.
%package       admin
Requires:      myproxy-server = %{version}-%{release}
Requires:      myproxy-libs   = %{version}-%{release}
Requires:      myproxy = %{version}-%{release}
Requires:      globus-gsi-cert-utils-progs >= 8
Summary:       Server for X.509 Public Key Infrastructure (PKI) security credentials 
Group:         System Environment/Daemons

%description admin
MyProxy is open source software for managing X.509 Public Key Infrastructure 
(PKI) security credentials (certificates and private keys). MyProxy 
combines an online credential repository with an online certificate 
authority to allow users to securely obtain credentials when and where needed.
Users run myproxy-logon to authenticate and obtain credentials, including 
trusted CA certificates and Certificate Revocation Lists (CRLs). 

Package %{name}-admin contains the MyProxy server admin commands.



%package doc
Requires:      myproxy = %{version}-%{release}
Summary:       Documentation for X.509 Public Key Infrastructure (PKI) security credentials 
Group:         Documentation

%description doc
MyProxy is open source software for managing X.509 Public Key Infrastructure 
(PKI) security credentials (certificates and private keys). MyProxy 
combines an online credential repository with an online certificate 
authority to allow users to securely obtain credentials when and where needed.
Users run myproxy-logon to authenticate and obtain credentials, including 
trusted CA certificates and Certificate Revocation Lists (CRLs). 

Package %{name}-doc contains the MyProxy documentation.


%prep
%setup -q
#%patch0 -p1
#cp -p %{SOURCE1} .
#cp -p %{SOURCE2} .
#cp -p %{SOURCE3} .


%build
rm -f doxygen/Doxyfile*
rm -f doxygen/Makefile.am
rm -f pkgdata/Makefile.am
rm -f globus_automake*

for f in `find . -name Makefile.am` ; do
  sed -e 's!^flavorinclude_HEADERS!include_HEADERS!' \
      -e 's!\(lib[a-zA-Z_]*\)_$(GLOBUS_FLAVOR_NAME)\.la!\1.la!g' \
      -e 's!^\(lib[a-zA-Z_]*\)___GLOBUS_FLAVOR_NAME__la_!\1_la_!' -i $f
done

%{_datadir}/globus/globus-bootstrap.sh

%if "%{?rhel}" == "4"
%configure --with-flavor=%{flavor}  --enable-doxygen \
                                    --with-voms=%{_usr} --without-openldap \
                                    --with-kerberos5=%{_usr} --with-sasl2=%{_usr}
%else
%if 0%{?suse_version} > 0
%configure --with-flavor=%{flavor}  --enable-doxygen --with-openldap=%{_usr} \
                                    --without-voms \
                                    --with-kerberos5=%{_usr} --with-sasl2=%{_usr}
%else
%configure --with-flavor=%{flavor}  --enable-doxygen --with-openldap=%{_usr} \
                                    --with-voms=%{_usr} \
                                    --with-kerberos5=%{_usr} --with-sasl2=%{_usr}
%endif
%endif
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

GLOBUSPACKAGEDIR=$RPM_BUILD_ROOT%{_datadir}/globus/packages

find $RPM_BUILD_ROOT%{_libdir} -name 'lib*.la' -exec rm -v '{}' \;
sed '/lib.*\.la$/d' -i $GLOBUSPACKAGEDIR/%{name}/%{flavor}_dev.filelist

# Remove static libraries (.a files)
find $RPM_BUILD_ROOT%{_libdir} -name 'lib*.a' -exec rm -v '{}' \;
sed '/lib.*\.a$/d' -i $GLOBUSPACKAGEDIR/%{name}/%{flavor}_dev.filelist

# No need for myproxy-server-setup since the rpm will perform
# the needed setup
rm $RPM_BUILD_ROOT%{_sbindir}/myproxy-server-setup
sed '/myproxy-server-setup$/d' -i $GLOBUSPACKAGEDIR/%{name}/%{flavor}_pgm.filelist

# Put documentation in Fedora defaults and alter GPT package lists.
mkdir -p $RPM_BUILD_ROOT%{_defaultdocdir}/%{name}-doc-%{version}/extras
%if 0%{?suse_version} == 0
mv $RPM_BUILD_ROOT%{_defaultdocdir}/%{name}/{refman.pdf,html} \
    $RPM_BUILD_ROOT%{_defaultdocdir}/%{name}-doc-%{version}/.
sed -i "s!/share/doc/%{name}/html/!/share/doc/%{name}-doc-%{version}/html/!" $GLOBUSPACKAGEDIR/%{name}/noflavor_doc.filelist
sed -i "s!/share/doc/%{name}/refman.pdf!/share/doc/%{name}-doc-%{version}/refman.pdf!" $GLOBUSPACKAGEDIR/%{name}/noflavor_doc.filelist

%else
mv $RPM_BUILD_ROOT/%{_datadir}/doc/%{name}/{refman.pdf,html} \
    $RPM_BUILD_ROOT%{_defaultdocdir}/%{name}-doc-%{version}/.
sed -i "s!/share/doc/%{name}/html/!/share/doc/packages/%{name}-doc-%{version}/html/!" $GLOBUSPACKAGEDIR/%{name}/noflavor_doc.filelist
sed -i "s!/share/doc/%{name}/refman.pdf!/share/doc/packages/%{name}-doc-%{version}/refman.pdf!" $GLOBUSPACKAGEDIR/%{name}/noflavor_doc.filelist

%endif


# We are going to zip the man pages later in the package so we need to
# correct the gpt data in anticipation.
sed -i "s!\(/share/man/.*\)!\1.gz!" $GLOBUSPACKAGEDIR/%{name}/noflavor_doc.filelist


for FILE in login.html myproxy-accepted-credentials-mapapp myproxy-cert-checker myproxy-certificate-mapapp \
             myproxy-certreq-checker myproxy-crl.cron myproxy.cron myproxy-get-delegation.cgi \
             myproxy-get-trustroots.cron myproxy-passphrase-policy myproxy-revoke 
do
%if 0%{?suse_version} == 0
   mv $RPM_BUILD_ROOT%{_usr}/share/%{name}/$FILE \
      $RPM_BUILD_ROOT%{_defaultdocdir}/%{name}-doc-%{version}/extras/.
   sed -i "s!%{name}/${FILE}!doc/%{name}-doc-%{version}/extras/${FILE}!" $GLOBUSPACKAGEDIR/%{name}/noflavor_data.filelist
%else
   mv $RPM_BUILD_ROOT%{_usr}/share/%{name}/$FILE \
      $RPM_BUILD_ROOT%{_defaultdocdir}/%{name}-doc-%{version}/extras/.
   sed -i "s!%{name}/${FILE}!doc/packages/%{name}-doc-%{version}/extras/${FILE}!" $GLOBUSPACKAGEDIR/%{name}/noflavor_data.filelist
%endif
done

mkdir -p $RPM_BUILD_ROOT%{_defaultdocdir}/%{name}-%{version}
for FILE in INSTALL LICENSE LICENSE.* PROTOCOL README VERSION
do 
%if 0%{?suse_version} == 0
  mv  $RPM_BUILD_ROOT%{_usr}/share/%{name}/$FILE \
      $RPM_BUILD_ROOT%{_defaultdocdir}/%{name}-%{version}/.
  sed -i "s!%{name}/${FILE}!doc/%{name}-%{version}/${FILE}!" $GLOBUSPACKAGEDIR/%{name}/noflavor_data.filelist
%else
  mv  $RPM_BUILD_ROOT%{_usr}/share/%{name}/$FILE \
      $RPM_BUILD_ROOT%{_defaultdocdir}/%{name}-%{version}/.
  sed -i "s!%{name}/${FILE}!doc/packages/%{name}-%{version}/${FILE}!" $GLOBUSPACKAGEDIR/%{name}/noflavor_data.filelist
%endif
done

# Remove irrelavent example configuration files.
for FILE in etc.inetd.conf.modifications etc.init.d.myproxy.nonroot etc.services.modifications  \
            etc.xinetd.myproxy etc.init.d.myproxy
do
  rm $RPM_BUILD_ROOT%{_usr}/share/%{name}/$FILE
  sed -i "/share\/%{name}\/$FILE/d" $GLOBUSPACKAGEDIR/%{name}/noflavor_data.filelist
done

# Generate pkg-config file from GPT metadata
# FIXME: This seems to already be generated by configure and
# globus-gpt2pkg-config is not (yet?) available GT5.2 Alpha globus-core. Investigate!
#mkdir -p $RPM_BUILD_ROOT%{_libdir}/pkgconfig
#%{_datadir}/globus/globus-gpt2pkg-config pkgdata/pkg_data_%{flavor}_dev.gpt > \
#  $RPM_BUILD_ROOT%{_libdir}/pkgconfig/%{name}.pc


# Move example configuration file into place.
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}
mv $RPM_BUILD_ROOT%{_datadir}/%{name}/myproxy-server.config \
   $RPM_BUILD_ROOT%{_sysconfdir}
sed -i "/share\/%{name}\/myproxy-server.config/d" $GLOBUSPACKAGEDIR/%{name}/noflavor_data.filelist


mkdir -p $RPM_BUILD_ROOT%{_initddir}
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig
install  -m 755 myproxy.init $RPM_BUILD_ROOT%{_initddir}/myproxy-server
install  -m 644 myproxy.sysconfig $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig/myproxy-server
mkdir -p $RPM_BUILD_ROOT%{_var}/lib/myproxy

# Create a directory to hold myproxy owned host certificates.
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/grid-security/myproxy

%clean
rm -rf $RPM_BUILD_ROOT


%check 
# Check that the entries in gpt filelists are all present.
GLOBUSPACKAGEDIR=$RPM_BUILD_ROOT%{_datadir}/globus/packages
for LIST in $GLOBUSPACKAGEDIR/%{name}/*.filelist
do
   for FILE in $(cat $LIST)
   do
      if [ ! -r $RPM_BUILD_ROOT%{_usr}$FILE ] ; then
        echo "Check failed:"
        echo "Filelist $LIST contains:"
        echo "$FILE"
        echo "which is not present at:"
        echo $RPM_BUILD_ROOT%{_usr}$FILE 
        exit 1
      fi
   done
done

PATH=.:$PATH ./myproxy-test -startserver -generatecerts



%post libs -p /sbin/ldconfig
%postun libs -p /sbin/ldconfig

%pre server
getent group myproxy >/dev/null || groupadd -r myproxy
getent passwd myproxy >/dev/null || \
useradd -r -g myproxy -d %{_var}/lib/myproxy -s /sbin/nologin \
   -c "User to run the MyProxy service" myproxy
exit 0

%post server
/sbin/chkconfig --add myproxy-server

%preun server
if [ $1 = 0 ] ; then
    /sbin/service myproxy-server stop >/dev/null 2>&1
    /sbin/chkconfig --del myproxy-server
fi

%postun server
if [ "$1" -eq "1" ] ; then
    /sbin/service myproxy-server condrestart >/dev/null 2>&1 || :
fi

%files
%defattr(-,root,root,-)
%{_bindir}/myproxy-change-pass-phrase
%{_bindir}/myproxy-destroy
%{_bindir}/myproxy-get-delegation
%{_bindir}/myproxy-get-trustroots
%{_bindir}/myproxy-info
%{_bindir}/myproxy-init
%{_bindir}/myproxy-logon
%{_bindir}/myproxy-retrieve
%{_bindir}/myproxy-store

%{_mandir}/man1/myproxy-change-pass-phrase.1.gz
%{_mandir}/man1/myproxy-destroy.1.gz
%{_mandir}/man1/myproxy-get-delegation.1.gz
%{_mandir}/man1/myproxy-info.1.gz
%{_mandir}/man1/myproxy-init.1.gz
%{_mandir}/man1/myproxy-logon.1.gz
%{_mandir}/man1/myproxy-retrieve.1.gz
%{_mandir}/man1/myproxy-store.1.gz
%doc %{_defaultdocdir}/%{name}-%{version}

%files libs
%defattr(-,root,root,-)
%{_datadir}/globus/packages/%{name}
%{_libdir}/libmyproxy.so.*

%files server
%defattr(-,root,root,-)
%{_sbindir}/myproxy-server
%{_initddir}/myproxy-server
%config(noreplace)    %{_sysconfdir}/myproxy-server.config
%config(noreplace)    %{_sysconfdir}/sysconfig/myproxy-server
# myproxy-server wants exactly 700 permission on its data 
# which is just fine.
%attr(0700,myproxy,myproxy) %dir %{_var}/lib/myproxy
%dir %{_sysconfdir}/grid-security
%dir %{_sysconfdir}/grid-security/myproxy

%{_mandir}/man8/myproxy-server.8.gz
%{_mandir}/man5/myproxy-server.config.5.gz
%{_datadir}/myproxy/myproxy-server.conf
%{_datadir}/myproxy/myproxy-server.service

%doc README.Fedora

%files admin
%defattr(-,root,root,-)
%{_sbindir}/myproxy-admin-addservice
%{_sbindir}/myproxy-admin-adduser
%{_sbindir}/myproxy-admin-change-pass
%{_sbindir}/myproxy-admin-load-credential
%{_sbindir}/myproxy-admin-query
%{_sbindir}/myproxy-replicate
%{_sbindir}/myproxy-test
%{_sbindir}/myproxy-test-replicate
%{_mandir}/man8/myproxy-admin-addservice.8.gz
%{_mandir}/man8/myproxy-admin-adduser.8.gz
%{_mandir}/man8/myproxy-admin-change-pass.8.gz
%{_mandir}/man8/myproxy-admin-load-credential.8.gz
%{_mandir}/man8/myproxy-admin-query.8.gz
%{_mandir}/man8/myproxy-replicate.8.gz

%files doc
%defattr(-,root,root,-)
%doc %{_defaultdocdir}/%{name}-doc-%{version}

%files devel
%defattr(-,root,root,-)
%{_includedir}/globus/myproxy.h
%{_includedir}/globus/myproxy_authorization.h
%{_includedir}/globus/myproxy_constants.h
%{_includedir}/globus/myproxy_creds.h
%{_includedir}/globus/myproxy_delegation.h
%{_includedir}/globus/myproxy_log.h
%{_includedir}/globus/myproxy_protocol.h
%{_includedir}/globus/myproxy_read_pass.h
%{_includedir}/globus/myproxy_sasl_client.h
%{_includedir}/globus/myproxy_sasl_server.h
%{_includedir}/globus/myproxy_server.h
%{_includedir}/globus/verror.h
%{_libdir}/libmyproxy.so
%{_libdir}/pkgconfig/myproxy.pc

%changelog
* Tue Jun 26 2012 Joseph Bester <bester@mcs.anl.gov> - 5.8-1
- Update to myproxy 5.8 for GT 5.2.2

* Tue May 15 2012 Joseph Bester <bester@mcs.anl.gov> - 5.6-5
- Adjust requirements for SUSE

* Wed May 09 2012 Joseph Bester <bester@mcs.anl.gov> - 5.6-4
- RHEL 4 patches

* Fri May 04 2012 Joseph Bester <bester@mcs.anl.gov> - 5.6-3
- SLES 11 patches

* Wed Mar 16 2012 Joseph Bester <bester@mcs.anl.gov> - 5.6-2
- Package a few files that were not named in server package

* Wed Feb 29 2012 Joseph Bester <bester@mcs.anl.gov> - 5.6-1
- Updated to MyProxy 5.6

* Tue Feb 14 2012 Joseph Bester <bester@mcs.anl.gov> - 5.5-4
- Updated version numbers

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 5.5-3
- Update for 5.2.0 release

* Fri Oct 21 2011 Joseph Bester <bester@mcs.anl.gov> - 5.5-2
- Fix %post* scripts to check for -eq 1
- Add backward-compatibility aging

* Thu Sep 01 2011 Joseph Bester <bester@mcs.anl.gov> - 5.5-1
- Update for 5.1.2 release

* Tue Feb 22 2011 Steve Traylen <steve.traylen@cern.ch> - 5.3-3
- myproxy-vomsc-vomsapi.patch to build against vomsapi rather
  than vomscapi.

* Tue Feb 08 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 5.3-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Tue Jan 18 2011 Steve Traylen <steve.traylen@cern.ch> - 5.3-1
- New upstream 5.3.

* Wed Jun 23 2010 Steve Traylen <steve.traylen@cern.ch> - 5.2-1
- New upstream 5.2.
- Drop blocked-signals-with-pthr.patch patch.
* Sat Jun 12 2010 Steve Traylen <steve.traylen@cern.ch> - 5.1-3
- Add blocked-signals-with-pthr.patch patch, rhbz#602594
- Updated init.d script rhbz#603157
- Add myproxy as requires to myproxy-admin to install clients.
* Sat May 15 2010 Steve Traylen <steve.traylen@cern.ch> - 5.1-2
- rhbz#585189 rearrange packaging.
  clients moved from now obsoleted -client package 
  to main package.
  libs moved from main package to new libs package.
* Tue Mar 9 2010 Steve Traylen <steve.traylen@cern.ch> - 5.1-1
- New upstream 5.1
- Remove globus-globus-usage-location.patch, now incoperated
  upstream.
* Fri Dec 4 2009 Steve Traylen <steve.traylen@cern.ch> - 5.0-1
- Add globus-globus-usage-location.patch
  https://bugzilla.mcs.anl.gov/globus/show_bug.cgi?id=6897
- Addition of globus-usage-devel to BR.
- New upstream 5.0
- Upstream source hosting changed from globus to sourceforge.
* Fri Nov 13 2009 Steve Traylen <steve.traylen@cern.ch> - 4.9-6
- Add requires globus-gsi-cert-utils-progs for grid-proxy-info
  to myproxy-admin package rhbz#536927
- Release bump to F13  so as to be newer than F12.
* Tue Oct 13 2009 Steve Traylen <steve.traylen@cern.ch> - 4.9-3
- Glob on .so.* files to future proof for upgrades.
* Tue Oct 13 2009 Steve Traylen <steve.traylen@cern.ch> - 4.9-1
- New upstream 4.9.
* Tue Oct 13 2009 Steve Traylen <steve.traylen@cern.ch> - 4.8-5
- Disable openldap support for el4 only since openldap to old.
* Wed Oct 7 2009 Steve Traylen <steve.traylen@cern.ch> -  4.8-4
- Add ASL 2.0 license as well.
- Explicitly add /etc/grid-security to files list
- For .el4/5 build only add globus-gss-assist-devel as requirment 
  to myproxy-devel package.
* Thu Oct 1 2009 Steve Traylen <steve.traylen@cern.ch> -  4.8-3
- Set _initddir for .el4 and .el5 building.
* Mon Sep 21 2009 Steve Traylen <steve.traylen@cern.ch> -  4.8-2
- Require version of voms with fixed ABI.
* Sun Sep 10 2009 Steve Traylen <steve.traylen@cern.ch> -  4.8-1
- Increase version to upstream 4.8
- Remove  voms-header-location.patch since fixed upstream now.
- Include directory /etc/grid-security/myproxy
* Mon Jun 22 2009 Steve Traylen <steve.traylen@cern.ch> -  4.7-1
- Initial version.

