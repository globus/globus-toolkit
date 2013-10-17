Name: udt
Version: 4.11
Release: 2g2
Summary: UDP-based Data Transfer
Vendor:  UDT Team

Group:   Development/Libraries
License: BSD
URL:     http://udt.sourceforge.net/
Source:  http://sourceforge.net/projects/udt/files/udt/%{version}/udt.sdk.%{version}.tar.gz

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: gcc-c++

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

%pre

%post

[ -x "/sbin/ldconfig" ] && /sbin/ldconfig

%preun

%postun

[ -x "/sbin/ldconfig" ] && /sbin/ldconfig


%files
%defattr(-,root,root,-)
%{_libdir}/libudt.so

%files devel
%defattr(-,root,root,-)
%{_includedir}/udt.h

%changelog
* Wed May 26 2013 Globus Toolkit <support@globus.org> - 4.11-1
- Upstream update

* Thu Dec 22 2011 Brian Bockelman <bbockelm@cse.unl.edu> - 4.9-2
- Package header file.

* Thu Dec 22 2011 Brian Bockelman <bbockelm@cse.unl.edu> - 4.9-1
- Initial packaging for UDT.

