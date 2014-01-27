%if %{?fedora}%{!?fedora:0} <= 16 || %{?rhel}%{!?rhel:0} < 7
%global backwardcompat "--with-backward-compatibility-hack"
%endif

%{!?perl_vendorlib: %global perl_vendorlib %(eval "`perl -V:installvendorlib`"; echo $installvendorlib)}

Name:		globus-common
%global _name %(tr - _ <<< %{name})
Version:	15.2
Release:	1%{?dist}
Summary:	Globus Toolkit - Common Library

Group:		System Environment/Libraries
License:	ASL 2.0
URL:		http://www.globus.org/
Source:		http://www.globus.org/ftppub/gt5/5.2/testing/packages/src/%{_name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

#		Obsolete dropped packages from Globus Toolkit 4.2.1
Obsoletes:	globus-data-conversion
Obsoletes:	globus-mp
Obsoletes:	globus-nexus
Obsoletes:	globus-duct-common
Obsoletes:	globus-duct-control
Obsoletes:	globus-duroc-common
Obsoletes:	globus-duroc-control
%if %{?fedora}%{!?fedora:0} <= 16 || %{?rhel}%{!?rhel:0} < 7
Provides:	globus-libtool%{?_isa}
Provides:       globus-common-setup%{?_isa}
%endif
Obsoletes:      globus-libtool%{?_isa} < 2
Obsoletes:      globus-common-setup%{?_isa} < 3
BuildRequires:	doxygen
BuildRequires:	graphviz
%if 0%{?suse_version} == 0
%if 0%{?rhel} > 4 || 0%{?rhel} == 0
BuildRequires:	libtool-ltdl-devel
%endif
%endif
%if "%{?rhel}" == "5"
BuildRequires:	graphviz-gd
%endif

%package progs
Summary:	Globus Toolkit - Common Library Programs
Group:		Applications/Internet
Requires:	%{name}%{?_isa} = %{version}-%{release}
%if 0%{?suse_version} > 0
    %if %{suse_version} < 1140
Requires:     perl = %{perl_version}
    %else
%{perl_requires}
    %endif
%else
Requires:	perl(:MODULE_COMPAT_%(eval "`perl -V:version`"; echo $version))
%endif

%package devel
Summary:	Globus Toolkit - Common Library Development Files
Group:		Development/Libraries
Requires:	%{name}%{?_isa} = %{version}-%{release}
Obsoletes:	globus-libtool-devel%{?_isa}
#		Obsolete dropped packages from Globus Toolkit 4.2.1
Obsoletes:	globus-core
Obsoletes:	globus-data-conversion-devel
Obsoletes:	globus-mp-devel
Obsoletes:	globus-nexus-devel
Obsoletes:	globus-duct-common-devel
Obsoletes:	globus-duct-control-devel
Obsoletes:	globus-duroc-common-devel
Obsoletes:	globus-duroc-control-devel

%package doc
Summary:	Globus Toolkit - Common Library Documentation Files
Group:		Documentation
%if %{?fedora}%{!?fedora:0} >= 10 || %{?rhel}%{!?rhel:0} >= 6
BuildArch:	noarch
%endif
Requires:	%{name} = %{version}-%{release}

%description
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
Common Library

%description progs
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-progs package contains:
Common Library Programs
Common Setup

%description devel
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-devel package contains:
Common Library Development Files

%description doc
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-doc package contains:
Common Library Documentation Files

%prep
%setup -q -n %{_name}-%{version}

# custom perl requires that removes dependency on gpt perl modules
cat << EOF > %{name}-req
#!/bin/sh
%{__perl_requires} $* |\
sed -e '/perl(Grid::GPT::.*)/d'
EOF
%global __perl_requires %{_builddir}/%{_name}-%{version}/%{name}-req
chmod +x %{__perl_requires}

%build
%if %{?fedora}%{!?fedora:0} >= 19 || %{?rhel}%{!?rhel:0} >= 7
# Remove files that should be replaced during bootstrap
rm -rf autom4te.cache

autoreconf -i
%endif

%if "%{?globus_version}" != ""
GLOBUS_VERSION=%{globus_version}
%else
GLOBUS_VERSION=5.2.5
%endif
export GLOBUS_VERSION
%configure \
           --disable-static %{backwardcompat} \
           --docdir=%{_docdir}/%{name}-%{version} \
           --includedir=%{_includedir}/globus \
           --datadir=%{_datadir}/globus \
           --libexecdir=%{_datadir}/globus \
           --with-perlmoduledir=%{perl_vendorlib}

make %{?_smp_mflags}

cd -

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

# Remove libtool archives (.la files)
find $RPM_BUILD_ROOT%{_libdir} -name 'lib*.la' -exec rm -v '{}' \;

%check
make %{?_smp_mflags} check

%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files 
%defattr(-,root,root,-)
%dir %{_docdir}/%{name}-%{version}
%dir %{_datadir}/globus
%{_docdir}/%{name}-%{version}/GLOBUS_LICENSE
%dir %{perl_vendorlib}/Globus
%dir %{perl_vendorlib}/Globus/Core
%{perl_vendorlib}/Globus/Core/*
%{_libdir}/libglobus_*so.*

%files progs
%defattr(-,root,root,-)
%{_bindir}/*
%{_sbindir}/*
%{_datadir}/man/man1/*
%{_datadir}/globus/*

%files devel
%defattr(-,root,root,-)
%dir %{_includedir}/globus
%{_includedir}/globus/*.h
%{_libdir}/libglobus_*so
%{_libdir}/pkgconfig/%{name}.pc

%files doc
%defattr(-,root,root,-)
%dir %{_docdir}/%{name}-%{version}/html
%{_datadir}/man/man3/*
%{_docdir}/%{name}-%{version}/html/*

%changelog
* Mon Jan 27 2014 Globus Toolkit <support@globus.org> - 15.2-1
- Repackage for GT6 without GPT

* Mon Jul 08 2013 Globus Toolkit <support@globus.org> - 14.10-3
- Incorrect %dir for license file

* Wed Jun 26 2013 Globus Toolkit <support@globus.org> - 14.10-2
- GT-424: New Fedora Packaging Guideline - no %_isa in BuildRequires

* Mon Mar 18 2013 Globus Toolkit <support@globus.org> - 14.10-1
- GT-354: Compatibility with automake 1.13

* Wed Feb 20 2013 Globus Toolkit <support@globus.org> - 14.9-4
- Workaround missing F18 doxygen/latex dependency

* Mon Feb 4 2013 Globus Toolkit <support@globus.org> - 14.9-3

* Mon Nov 26 2012 Globus Toolkit <support@globus.org> - 14.9-2
- 5.2.3

* Tue Oct 09 2012 Globus Toolkit <support@globus.org> - 14.9-1
- GT-288: Deprecate globus_libc_setenv

* Thu Aug 09 2012 Joseph Bester <bester@mcs.anl.gov> - 14.8-1
- GT-264: link error in globus-redia

* Mon Jul 16 2012 Joseph Bester <bester@mcs.anl.gov> - 14.7-3
- GT 5.2.2 final

* Fri Jun 29 2012 Joseph Bester <bester@mcs.anl.gov> - 14.7-2
- GT 5.2.2 Release

* Wed Jun 13 2012 Joseph Bester <bester@mcs.anl.gov> - 14.7-1
- GT-227: API Documentation for Globus Priority Queue

* Wed May 09 2012 Joseph Bester <bester@mcs.anl.gov> - 14.6-3
- RHEL 4 patches

* Fri May 04 2012 Joseph Bester <bester@mcs.anl.gov> - 14.6-2
- SLES 11 patches

* Tue Feb 14 2012 Joseph Bester <bester@mcs.anl.gov> - 14.6-1
- RIC-221: Remove unnecessary evals of path components from script initializers
- RIC-223: Some commands in globus_common have no manpage
- RIC-224: Eliminate some doxygen warnings
- RIC-228: potentially unsafe format strings in common
- RIC-230: Remove obsolete globus_libtool_windows code
- RIC-255: Missing default value for shell script variable in globus-sh-exec

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 14.5-2
- Update for 5.2.0 release

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 14.5-1
- Last sync prior to 5.2.0

* Wed Nov 23 2011 Joseph Bester <bester@mcs.anl.gov> - 14.4-1
- make GPT_EXTERNAL_LIBS=-lpthread for backward-compatibility hack

* Fri Nov 11 2011 Joseph Bester <bester@mcs.anl.gov> - 14.3-2
- Set default GLOBUS_VERSION to version 5.1.3

* Thu Nov 03 2011 Joseph Bester <bester@mcs.anl.gov> - 14.3-1
- RIC-199: Can't install 32 and 64 bit Globus RPMs at the same time (missed
  perl libdir change)

* Fri Oct 28 2011 Joseph Bester <bester@mcs.anl.gov> - 14.2-1
- Allow pthread extensions to be activated, but warn in globus_extension_activate debug output

* Mon Oct 24 2011 Joseph Bester <bester@mcs.anl.gov> - 14.1-2
- Add explicit dependencies on >= 5.2 libraries
- Move libglobus_thread_pthread.so symlink to globus-common package
  from globus-common-devel
- Add backward-compatibility hack
- Obsolete globus-libtool-devel instead of globus-libtool in devel package
- Remove text about extracting source from installer

* Thu Sep 01 2011 Joseph Bester <bester@mcs.anl.gov> - 14.0-2
- Update for 5.1.2 release

* Mon Sep 06 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 11.5-3
- Updated pthread exception patch for better compatibility with boost's headers

* Sun Aug 08 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 11.5-2
- Fix perl dependncies (use vs. require)

* Sat Jul 17 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 11.5-1
- Update to Globus Toolkit 5.0.2

* Tue Jun 01 2010 Marcela Maslanova <mmaslano@redhat.com> - 11.4-2
- Mass rebuild with perl-5.12.0

* Tue Apr 13 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 11.4-1
- Update to Globus Toolkit 5.0.1

* Wed Feb 24 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 11.2-2
- Make the globus-version script return the right value

* Thu Jan 21 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 11.2-1
- Update to Globus Toolkit 5.0.0

* Fri Dec 04 2009 Stepan Kasal <skasal@redhat.com> - 10.2-9
- rebuild against perl 5.10.1

* Sun Nov 08 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 10.2-8
- Let globus-makefile-header fail gracefully when GPT is not present
- Workaround a bug in doxygen

* Mon Aug 03 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 10.2-7
- Patch globus_location function to allow unset GLOBUS_LOCATION
- Put back config.guess file

* Thu Jul 23 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 10.2-6
- Add instruction set architecture (isa) tags
- Make doc subpackage noarch
- Replace /usr/bin/env shebangs

* Tue Jun 02 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 10.2-5
- Update to official Fedora Globus packaging guidelines

* Mon Apr 27 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 10.2-4
- Rebuild with updated libtool

* Tue Apr 21 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 10.2-3
- Put GLOBUS_LICENSE file in extracted source tarball

* Thu Apr 16 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 10.2-2
- Remove config.guess file

* Tue Apr 07 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 10.2-1
- Change defines to globals

* Mon Apr 06 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 10.2-0.6
- Make comment about source retrieval more explicit

* Sun Mar 15 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 10.2-0.5
- Adapting to updated globus-core package

* Thu Feb 26 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 10.2-0.4
- Add s390x to the list of 64 bit platforms
- Move globus-makefile-header to devel package

* Thu Jan 01 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 10.2-0.3
- Adapt to updated GPT package

* Wed Oct 15 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 10.2-0.2
- Update to Globus Toolkit 4.2.1

* Mon Jul 14 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 10.2-0.1
- Autogenerated
