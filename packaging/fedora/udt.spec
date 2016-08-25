Name: udt
Version: 4.11
Release: 3g5%{?dist}
Vendor:	Globus Support
Summary: UDP-based Data Transfer

Group:   Development/Libraries
License: BSD
URL:     http://udt.sourceforge.net/
Source:  http://sourceforge.net/projects/udt/files/udt/%{version}/udt.sdk.%{version}.tar.gz

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: gcc-c++

%if %{?suse_version}%{!?suse_version:0} >= 1315
%global mainpkg libudt
%global nmainpkg -n %{mainpkg}
%else
%global mainpkg %{name}
%endif

%if %{?suse_version}%{!?suse_version:0} >= 1315
%package %{nmainpkg}
Group:   Development/Libraries
Summary: UDP-based Data Transfer

%description %{nmainpkg}
UDT is a reliable UDP based application level 
data transport protocol for distributed data 
intensive applications over wide area high-speed networks.
%endif

%description
UDT is a reliable UDP based application level 
data transport protocol for distributed data 
intensive applications over wide area high-speed networks.

%package devel
Summary: UDT - Development headers
Group: Development/Libraries

%description devel
%{summary}

%prep
%setup -q -n udt4

%build

# Note: hand-written Makefile, not multi-process safe.
%ifarch x86_64
env arch=AMD64 make -e
%else
env C++="g++ -m32" make -e
%endif

%install

mkdir -p $RPM_BUILD_ROOT%{_libdir}
install -m 0755 src/libudt.so $RPM_BUILD_ROOT%{_libdir}/libudt.so
mkdir -p $RPM_BUILD_ROOT%{_includedir}
install -m 0644 src/udt.h $RPM_BUILD_ROOT%{_includedir}/udt.h

%clean
rm -rf $RPM_BUILD_ROOT

%pre %{?nmainpkg}

%post %{?nmainpkg}

[ -x "/sbin/ldconfig" ] && /sbin/ldconfig

%preun %{?nmainpkg}

%postun %{?nmainpkg}

[ -x "/sbin/ldconfig" ] && /sbin/ldconfig


%files %{?nmainpkg}
%defattr(-,root,root,-)
%{_libdir}/libudt.so

%files devel
%defattr(-,root,root,-)
%{_includedir}/udt.h

%changelog
* Thu Aug 25 2016 Globus Toolkit <support@globus.org> - 4.11-3g4
- Updates for SLES 12

* Wed May 26 2013 Globus Toolkit <support@globus.org> - 4.11-1
- Upstream update

* Thu Dec 22 2011 Brian Bockelman <bbockelm@cse.unl.edu> - 4.9-2
- Package header file.

* Thu Dec 22 2011 Brian Bockelman <bbockelm@cse.unl.edu> - 4.9-1
- Initial packaging for UDT.

