Name:           globus-connect-multiuser
Version:        2.0.2
Release:        1%{?dist}
Summary:        Globus Connect Multi-User

%global transferapi_name globusonline-transfer-api-client
%global transferapi_version 0.10.13
Group:          System Environment/Libraries
License:        ASL 2.0
URL:            http://www.globus.org/
Source:         %{name}-%{version}.tar.gz
Source1:        %{transferapi_name}-%{transferapi_version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:      noarch

%if "%{?rhel}" == "5"
%global python  python26
%else
%global python  python
%endif

Requires:       globus-gridftp-server-progs%{?_isa} >= 6
Requires:       globus-gass-copy-progs%{?_isa} 
Requires:       globus-gss-assist-progs%{?_isa} 
Requires:       myproxy%{?_isa} 
Requires:       myproxy-server%{?_isa} 
Requires:       gsi-openssh%{?_isa} 
Requires:       gsi-openssh-clients%{?_isa} 
Requires:       globus-gsi-cert-utils-progs%{?_isa} 
Requires:       globus-simple-ca
Requires:       globus-gridmap-verify-myproxy-callout%{?_isa}
Requires:       globus-gridmap-eppn-callout%{?_isa}
Requires:	%{python}
Obsoletes:      gcmu


%description
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
Globus Connect Multi-User

%prep
%setup 
%setup -a 1 -D -T

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
%{_bindir}/globus-connect-multiuser-setup
/usr/lib*/python*
/usr/lib*/globus-connect-multiuser/*
%config(noreplace) %{_sysconfdir}/%{name}.conf

%changelog
* Wed Mar 13 2013 Globus Toolkit <support@globus.org> 2.0.2-1
- Initial packaging as globus-connect-multiuser
