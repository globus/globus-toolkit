%if "%{?rhel}" == "4" || "%{?rhel}" == "5"
%global docdiroption "with-docdir"
%else
%global docdiroption "docdir"
%endif
%global flavor "noflavor"


%{!?perl_vendorlib: %global perl_vendorlib %(eval "`perl -V:installvendorlib`"; echo $installvendorlib)}

Name:		globus-simple-ca
%global _name %(tr - _ <<< %{name})
Version:	3.4
Release:	4%{?dist}
Summary:	Globus Toolkit - Simple CA

Group:		System Environment/Libraries
License:	ASL 2.0
URL:		http://www.globus.org/
Source:		http://www.globus.org/ftppub/gt5/5.2/testing/packages/src/%{_name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires:   globus-common
Requires:   globus-common-progs
Requires:   openssl
Requires(post):   openssl
Requires(post):   globus-gsi-cert-utils-progs
BuildRequires:  grid-packaging-tools >= 3.4
BuildRequires:  globus-core >= 7.5
BuildArch:      noarch

%description
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
Globus Simple CA

%prep
%setup -q -n %{_name}-%{version}

%build
%if "%{rhel}" == "5"
export PATH=$PWD/bin:$PATH
%endif

# Remove files that should be replaced during bootstrap
rm -f pkgdata/Makefile.am
rm -f globus_automake*
rm -rf autom4te.cache
unset GLOBUS_LOCATION
unset GPT_LOCATION

%{_datadir}/globus/globus-bootstrap.sh

export GLOBUS_VERSION=5.2.0
%configure --%{docdiroption}=%{_docdir}/%{name}-%{version}

make %{?_smp_mflags}

cd -

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

GLOBUSPACKAGEDIR=$RPM_BUILD_ROOT%{_datadir}/globus/packages

# Generate package filelists
cat $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_rtl.filelist \
  | sed s!^!%{_prefix}! > package.filelist
cat $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_pgm.filelist \
    $GLOBUSPACKAGEDIR/%{_name}/noflavor_data.filelist \
  | sed s!^!%{_prefix}! >> package.filelist
cat $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_dev.filelist \
  | sed s!^!%{_prefix}! >> package.filelist
cat $GLOBUSPACKAGEDIR/%{_name}/noflavor_doc.filelist \
  | grep -v GLOBUS_LICENSE \
  | sed -e 's!^!%doc %{_prefix}!' \
  | sed -e 's!%{_mandir}/man.*!&.gz!' >> package.filelist

%clean
rm -rf $RPM_BUILD_ROOT

%pre
getent group simpleca >/dev/null || groupadd -r simpleca
getent passwd simpleca >/dev/null || \
useradd -r -g simpleca -d %{_localstatedir}/lib/globus/simple_ca \
   -s /sbin/nologin \
   -c "User to run the SimpleCA" simpleca
exit 0

%post
simplecadir=%{_localstatedir}/lib/globus/simple_ca
mkdir -p ${simplecadir}
if [ ! -f ${simplecadir}/cacert.pem ] ; then
    grid-ca-create -noint -nobuild -dir "${simplecadir}"
    (umask 077; echo globus > ${simplecadir}/passwd)
    simplecahash=`openssl x509 -hash -noout -in ${simplecadir}/cacert.pem`
    cd $simplecadir
    grid-ca-package -cadir ${simplecadir}
    tar --strip 1 --no-same-owner -zx --exclude debian -C /etc/grid-security/certificates -f ${simplecadir}/globus_simple_ca_$simplecahash.tar.gz
    chown -R simpleca:simpleca ${simplecadir}
    chmod -R g+rw ${simplecadir}
    find ${simplecadir} -type d -exec chmod g+xs {} \;
    if [ ! -r /etc/grid-security/globus-user-ssl.conf ]; then
        grid-default-ca -ca $simplecahash
    fi
    if [ ! -f /etc/grid-security/hostcert.pem ] && \
       [ ! -f /etc/grid-security/hostcert_request.pem ] && \
       [ ! -f /etc/grid-security/hostkey.pem ]; then
        grid-cert-request -cn `hostname -f` -host `hostname -f`
        su -s /bin/sh simpleca -c "umask 007; grid-ca-sign \
                -in /etc/grid-security/hostcert_request.pem \
                -out ${simplecadir}/hostcert.pem"
        cp "${simplecadir}/hostcert.pem" /etc/grid-security/hostcert.pem 
    fi
    cd -
fi
%files -f package.filelist
%defattr(-,root,root,-)
%dir %{_datadir}/globus
%dir %{_datadir}/globus/packages
%dir %{_datadir}/globus/packages/%{_name}
%dir %{_docdir}/%{name}-%{version}
%{_docdir}/%{name}-%{version}/GLOBUS_LICENSE

%changelog
* Fri sep 13 2013 Globus Toolkit <support@globus.org> - 3.4-4
- Don't die in postinst if domain name is not qualified

* Mon Jul 08 2013 Globus Toolkit <support@globus.org> - 3.4-3
- license is not a dir

* Wed Jun 26 2013 Globus Toolkit <support@globus.org> - 3.4-2
- GT-424: New Fedora Packaging Guideline - no %_isa in BuildRequires

* Fri May 24 2013 Globus Toolkit <support@globus.org> - 3.4-1
- Fix test for absolute path on some versions of expr

* Wed Feb 13 2013 Globus Toolkit <support@globus.org> - 3.3-1
- GT-362: simple ca loses spaces in dn in signing policy

* Mon Nov 26 2012 Globus Toolkit <support@globus.org> - 3.2-2
- 5.2.3

* Mon Oct 29 2012 Joseph Bester <bester@mcs.anl.gov> - 3.2-1
- GT-312: automate native simple_ca package more

* Mon Jul 16 2012 Joseph Bester <bester@mcs.anl.gov> - 3.1-3
- GT 5.2.2 final

* Fri Jun 29 2012 Joseph Bester <bester@mcs.anl.gov> - 3.1-2
- GT 5.2.2 Release

* Tue May 22 2012 Joseph Bester <bester@mcs.anl.gov> - 3.1-1
- GT-151: Build RPMS for SuSE 11

* Wed May 09 2012 Joseph Bester <bester@mcs.anl.gov> - 3.0-7
- RHEL 4 patches

* Tue Feb 14 2012 Joseph Bester <bester@mcs.anl.gov> - 3.0-6
- Updated version numbers

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 3.0-5
- Update for 5.2.0 release

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 3.0-4
- Last sync prior to 5.2.0

* Tue Oct 11 2011 Joseph Bester <bester@mcs.anl.gov> - 3.0-3
- Add explicit dependencies on >= 5.2 libraries

* Thu Sep 01 2011 Joseph Bester <bester@mcs.anl.gov> - 3.0-2
- Update for 5.1.2 release

* Tue Mar 29 2011 - 2.0-1
- Initial version
