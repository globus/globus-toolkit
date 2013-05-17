Name:           globus-connect-multiuser
Version:        2.0.35
Release:        1%{?dist}
Summary:        Globus Connect Multi-User
%global _name %(tr - _ <<< %{name})

%global transferapi_name globusonline-transfer-api-client
%global transferapi_version 0.10.15
Group:          System Environment/Libraries
License:        ASL 2.0
URL:            http://www.globus.org/
Source:         %{_name}-%{version}.tar.gz
Source1:        %{transferapi_name}-%{transferapi_version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:      noarch

%if "%{?rhel}" == "5"
%global python  python26
%else
%global python  python
%endif

Requires:       globus-connect-multiuser-common = %{version}
Requires:       globus-connect-multiuser-io = %{version}
Requires:       globus-connect-multiuser-id = %{version}
Requires:       globus-connect-multiuser-web = %{version}

%description
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
Globus Connect Multi-User

%package common
Requires:	%{python}
Obsoletes:      gcmu
Summary:        Globus Connect Multi-User Common files
Group:          System Environment/Libraries
%description common
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-common package contains:
Globus Connect Multi-User Common Files

%package id
Requires:       myproxy
Requires:       myproxy-server
Requires:       gsi-openssh
Requires:       gsi-openssh-clients
Requires:       globus-gsi-cert-utils-progs
Requires:       globus-simple-ca
Requires:       globus-connect-multiuser-common = %{version}
Summary:        Globus Connect Multi-User ID for MyProxy configuration
Group:          System Environment/Libraries
%description id
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-id package contains:
Globus Connect Multi-User ID

%package io
Requires:       myproxy
Requires:       gsi-openssh
Requires:       gsi-openssh-clients
Requires:       globus-gsi-cert-utils-progs
Requires:       globus-gridftp-server-progs >= 6.24
Requires:       globus-gass-copy-progs
Requires:       globus-gss-assist-progs
Requires:       globus-gridmap-verify-myproxy-callout >= 1.2
Requires:       globus-gridmap-eppn-callout >= 0.4
Requires:       globus-gsi-credential >= 5.5
Requires:       globus-connect-multiuser-common = %{version}
Summary:        Globus Connect Multi-User I/O for GridFTP configuration
Group:          System Environment/Libraries
%description io
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-io package contains:
Globus Connect Multi-User I/O

%package web
Requires:       myproxy
Requires:       myproxy-oauth
Requires:       globus-connect-multiuser-common = %{version}
Summary:        Globus Connect Multi-User Web for MyProxy OAuth configuration
Group:          System Environment/Libraries
%description web
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-web package contains:
Globus Connect Multi-User Web

%prep
%setup -q -n %{_name}-%{version}
%setup -a 1 -D -T -n %{_name}-%{version}

%build
cd %{transferapi_name}-%{transferapi_version}
python setup.py build
cd ..
python_exe="`%{python} -c 'import sys; print sys.executable'`"

for templ in templates/*; do
    sed -e "s|@PYTHON@|$python_exe|g" \
        -e "s|@libdir@|%{_libdir}|g" < "$templ" > `basename "$templ" .in`
done
python setup.py build

%install
rm -rf $RPM_BUILD_ROOT
mkdir $RPM_BUILD_ROOT
cd %{transferapi_name}-%{transferapi_version}
%{python} setup.py install --root $RPM_BUILD_ROOT --install-lib=%{_libdir}/%{name}
cd ..
%{python} setup.py install --root $RPM_BUILD_ROOT --prefix=/usr
%global __os_install_post %(echo '%{__os_install_post}' | sed -e 's!/usr/lib[^[:space:]]*/brp-python-bytecompile[[:space:]].*$!!g')

test -x /usr/lib/rpm/brp-python-bytecompile && \
    /usr/lib/rpm/brp-python-bytecompile "${python_exe}"

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_bindir}/globus-connect-multiuser-setup
%{_bindir}/globus-connect-multiuser-cleanup
%{_mandir}/man8/globus-connect-multiuser-setup*
%{_mandir}/man8/globus-connect-multiuser-cleanup*
%files common
%defattr(-,root,root,-)
/usr/lib*/globus-connect-multiuser/*
/usr/lib*/python*
%config(noreplace) %{_sysconfdir}/%{name}.conf
%files id
%defattr(-,root,root,-)
%{_bindir}/globus-connect-multiuser-id-setup
%{_bindir}/globus-connect-multiuser-id-cleanup
%{_mandir}/man8/globus-connect-multiuser-id-*
%files io
%defattr(-,root,root,-)
%{_bindir}/globus-connect-multiuser-io-setup
%{_bindir}/globus-connect-multiuser-io-cleanup
%{_mandir}/man8/globus-connect-multiuser-io-*
%files web
%defattr(-,root,root,-)
%{_bindir}/globus-connect-multiuser-web-setup
%{_bindir}/globus-connect-multiuser-web-cleanup
%{_mandir}/man8/globus-connect-multiuser-web-*

%changelog
* Fri May 17 2013 Globus Toolkit <support@globus.org> 2.0.34-1
- non-zero exit when setup or cleanup fails
- trap keyboard interrupts and exit more quietly

* Fri May 17 2013 Globus Toolkit <support@globus.org> 2.0.34-1
- Fix replacing server uri on the same host without -s
- Fix runtime error when removing a server from an endpoint

* Fri May 17 2013 Globus Toolkit <support@globus.org> 2.0.33-1
- Update to 2.0.33. New sharing DN

* Fri May 17 2013 Globus Toolkit <support@globus.org> 2.0.32-1
- Update to 2.0.32. Assume non-resolvable name is local

* Thu May 16 2013 Globus Toolkit <support@globus.org> 2.0.31-1
- Fix -s option to reset endpoint gridftp server

* Thu May 16 2013 Globus Toolkit <support@globus.org> 2.0.30-1
- Ignore myproxy CA cleanup if cacert.pem doesn't exist

* Thu May 16 2013 Globus Toolkit <support@globus.org> 2.0.29-1
- Ignore myproxy CA cleanup if using cilogon

* Thu May 16 2013 Globus Toolkit <support@globus.org> 2.0.28-1
- Update to 2.0.28
- KOA-2583: Add CILogon Silver CA to set of trusted CAs in GCMU
- KOA-2584: Add Globus Online Transfer CA 2 Alpha only if sharing is enabled on GCMU

* Thu May 16 2013 Globus Toolkit <support@globus.org> 2.0.27-2
- use new transfer api client

* Thu May 16 2013 Globus Toolkit <support@globus.org> 2.0.27-1
- Add conditional enable of mod_wsgi

* Wed May 15 2013 Globus Toolkit <support@globus.org> 2.0.26-2
- Require same version of other subpackages

* Wed May 15 2013 Globus Toolkit <support@globus.org> 2.0.26-1
- Update to 2.0.26. Fix scoping problem, don't create sharing dir if None

* Wed May 15 2013 Globus Toolkit <support@globus.org> 2.0.25-1
- Update to 2.0.25. Avoid trying to configure non-local services

* Wed May 15 2013 Globus Toolkit <support@globus.org> 2.0.24-1
- Update to 2.0.24. Fixes to MANIFEST.in

* Tue May 14 2013 Globus Toolkit <support@globus.org> 2.0.23-1
- Update to 2.0.23. Fixes to sharing-related config

* Mon May 13 2013 Globus Toolkit <support@globus.org> 2.0.22-1
- Update to 2.0.22. Fix path to version file.

* Thu May 09 2013 Globus Toolkit <support@globus.org> 2.0.21-1
- Update to 2.0.21. Remove some config options.

* Wed May 08 2013 Globus Toolkit <support@globus.org> 2.0.20-1
- Update to 2.0.20

* Wed May 08 2013 Globus Toolkit <support@globus.org> 2.0.19-1
- Update to 2.0.19

* Fri Apr 26 2013 Globus Toolkit <support@globus.org> 2.0.17-1
- Remove outdated sharing options SharingFile and SharingFileControl

* Wed Apr 10 2013 Globus Toolkit <support@globus.org> 2.0.16-1
- Change from SharingFile to SharingStateDir

* Mon Mar 25 2013 Globus Toolkit <support@globus.org> 2.0.15-1
- Add options to remove and reset an endpoint

* Fri Mar 22 2013 Globus Toolkit <support@globus.org> 2.0.14-2
- Require some minimum package versions

* Fri Mar 22 2013 Globus Toolkit <support@globus.org> 2.0.14-1
- Enable the gridftp and myproxy services to run at boot time
- Add globus-connect-multiuser version number to the gridftp server's usage
  stats data

* Thu Mar 21 2013 Globus Toolkit <support@globus.org> 2.0.13-1
- Fix configuring services with non-default port

* Thu Mar 21 2013 Globus Toolkit <support@globus.org> 2.0.12-1
- Add detection of ec2 private IP addresses and set DataInterface
- Better automatic support of NATed servers
- Don't depend on particular arch for GT components

* Tue Mar 19 2013 Globus Toolkit <support@globus.org> 2.0.11-1
- Missing break in retry code

* Tue Mar 19 2013 Globus Toolkit <support@globus.org> 2.0.10-1
- Add retries on getting authentication token

* Tue Mar 19 2013 Globus Toolkit <support@globus.org> 2.0.9-1
- Fix some configuration file handling

* Tue Mar 19 2013 Globus Toolkit <support@globus.org> 2.0.8-1
- Fix some configuration file handling
- Fix nameopt for ca creation for real
- add socket timeout

* Mon Mar 18 2013 Globus Toolkit <support@globus.org> 2.0.7-1
- remove @PYTHON@ from globus-connect-multiuser-setup
- Fix nameopt for ca creation

* Mon Mar 18 2013 Globus Toolkit <support@globus.org> 2.0.6-2
- Update transfer api client version

* Fri Mar 15 2013 Globus Toolkit <support@globus.org> 2.0.6-1
- fix issues where MyProxyCA DN doesn't match MyProxy DN

* Fri Mar 15 2013 Globus Toolkit <support@globus.org> 2.0.5-1
- Fix setup.py

* Fri Mar 15 2013 Globus Toolkit <support@globus.org> 2.0.4-1
- fix MANIFEST.in

* Thu Mar 14 2013 Globus Toolkit <support@globus.org> 2.0.3-1
- dummy __init__.py

* Wed Mar 13 2013 Globus Toolkit <support@globus.org> 2.0.2-1
- Initial packaging as globus-connect-multiuser
