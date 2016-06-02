Name:           libnice
Version:        0.0.9
Release:        4%{?dist}
Summary:        GLib ICE implementation

Group:          System Environment/Libraries
License:        LGPLv2 and MPLv1.1
URL:            http://nice.freedesktop.org/wiki/
Source0:        http://nice.freedesktop.org/releases/%{name}-%{version}.tar.gz
Patch0:         libnice-0.0.9-bz605078.patch
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:	glib2-devel
BuildRequires:  gstreamer-devel
BuildRequires:	gstreamer-plugins-base-devel

%if %{?rhel}%{!?rhel:0} > 5 || %{?fedora}%{!?fedora:0} > 18
BuildRequires:	gupnp-igd-devel >= 0.1.2
%endif


%description
%{name} is an implementation of the IETF's draft Interactive Connectivity
Establishment standard (ICE). ICE is useful for applications that want to
establish peer-to-peer UDP data streams. It automates the process of traversing
NATs and provides security against some attacks. Existing standards that use
ICE include the Session Initiation Protocol (SIP) and Jingle, XMPP extension
for audio/video calls.


%package        devel
Summary:        Development files for %{name}
Group:          Development/Libraries
Requires:       %{name} = %{version}-%{release}
Requires:	glib2-devel
Requires:	pkgconfig


%description    devel
The %{name}-devel package contains libraries and header files for
developing applications that use %{name}.


%prep
%setup -q
%patch0 -p1


%build
%if %{?rhel}%{!?rhel:0} > 5 || %{?fedora}%{!?fedora:0} > 18
%configure --disable-static
%else
%configure --disable-static --disable-gupnp
%endif
sed -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' libtool
sed -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' libtool
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
find $RPM_BUILD_ROOT -name '*.la' -exec rm -f {} ';'


%clean
rm -rf $RPM_BUILD_ROOT


%post -p /sbin/ldconfig


%postun -p /sbin/ldconfig


%files
%defattr(-,root,root,-)
%doc NEWS README COPYING COPYING.LGPL COPYING.MPL
%{_bindir}/stunbdc
%{_bindir}/stund
%{_libdir}/gstreamer-0.10/libgstnice.so
%{_libdir}/*.so.*


%files devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/*.so
%{_libdir}/pkgconfig/nice.pc
%{_datadir}/gtk-doc/html/%{name}/


%changelog
* Thu Jun 02 2016 Globus Toolkit <support@globus.org>  - 0.0.9-4
- --disable-gupnp on el5

* Mon Jun 21 2010 Kamil Dudka <kdudka@redhat.com> - 0.0.9-3
- suppress some compile-time warnings (#605078)

* Fri Dec 04 2009 Dennis Gregorovic <dgregor@redhat.com> - 0.0.9-2.1
- Rebuilt for RHEL 6

* Thu Sep 17 2009 Bastien Nocera <bnocera@redhat.com> 0.0.9-2
- Rebuild for new gupnp

* Sun Aug  2 2009 Brian Pepple <bpepple@fedoraproject.org> - 0.0.9-1
- Update to 0.0.9.
- Drop sha1 patch. Fixed upstream.

* Fri Jul 24 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.0.8-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Tue Jul 21 2009 Warren Togami <wtogami@redhat.com> - 0.0.8-2
- stun sha1 patch from upstream to make it work at all

* Sun Jun 21 2009 Brian Pepple <bpepple@fedoraproject.org> - 0.0.8-1
- Update to 0.0.8.

* Sun Jun 14 2009 Brian Pepple <bpepple@fedoraproject.org> - 0.0.7-1
- Update to 0.0.7.
- Add BR on gupnp-igd-devel.

* Mon Apr 13 2009 Brian Pepple <bpepple@fedoraproject.org> - 0.0.6-1
- Update to 0.0.6.

* Wed Mar 18 2009 Brian Pepple <bpepple@fedoraproject.org> - 0.0.5-1
- Update to 0.0.5.

* Wed Feb 25 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.0.4-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Sat Dec 27 2008 Brian Pepple <bpepple@fedoraproject.org> - 0.0.4-1
- Initial Fedora spec.

