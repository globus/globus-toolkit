%ifarch alpha ia64 ppc64 s390x sparc64 x86_64
%global flavor gcc64
%global enable64 yes
%else
%global flavor gcc32
%global enable64 no
%endif

%global debug_package %{nil}

%if "%{?rhel}" == "5"
%global docdiroption "with-docdir"
%else
%global docdiroption "docdir"
%endif

%{!?perl_vendorlib: %global perl_vendorlib %(eval "`perl -V:installvendorlib`"; echo $installvendorlib)}

Name:		globus-core
%global _name %(tr - _ <<< %{name})
Version:	7.8
Release:	2%{?dist}
Summary:	Globus Toolkit - Globus Core

Group:		Development/Tools
License:	ASL 2.0
URL:		http://www.globus.org/
#		Source is extracted from the globus toolkit installer:
#		wget -N http://www-unix.globus.org/ftppub/gt5/5.0/5.0.2/installers/src/gt5.0.2-all-source-installer.tar.bz2
#		tar -jxf gt5.0.2-all-source-installer.tar.bz2
#		mv gt5.0.2-all-source-installer/source-trees/core/cource globus_core-5.17
#		tar -zcf globus_core-5.17.tar.gz globus_core-5.17
Source:		%{_name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Provides:	%{name}-devel = %{version}-%{release}
Obsoletes:	%{name}-devel < 5.15-0.5
Requires:	pkgconfig
Requires:	perl(XML::Parser)
BuildRequires:	grid-packaging-tools
BuildRequires:	perl(XML::Parser)

%description
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
Globus Core

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
rm -rf autom4te.cache
unset GLOBUS_LOCATION
unset GPT_LOCATION
./bootstrap

%configure --includedir='${prefix}/include/globus' \
	   --libexecdir='${datadir}/globus' \
	   --with-flavor=%{flavor} \
	   --enable-64bit=%{enable64} \
           --enable-debug \
           --%{docdiroption}=%{_docdir}/%{name}-%{version} \
	   --with-setupdir='${datadir}/globus/setup' \
	   --with-testdir='${datadir}/globus/test/${PACKAGE}' \
	   --with-flavorincludedir='${libdir}/globus/include' \
	   --with-perlmoduledir=%{perl_vendorlib} \
	   --with-doxygendir='${datadir}/globus/doxygen'

make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

# These scripts are intended to be sourced, not executed
chmod 644 $RPM_BUILD_ROOT%{_datadir}/globus/globus-build-env-*.sh

GLOBUSPACKAGEDIR=$RPM_BUILD_ROOT%{_datadir}/globus/packages

# Don't use /usr/bin/env
sed 's!/usr/bin/env perl!/usr/bin/perl!' -i $RPM_BUILD_ROOT%{_sbindir}/globus-*

# Remove license file installed directly in the buildroot
rm -f $RPM_BUILD_ROOT/GLOBUS_LICENSE
sed /GLOBUS_LICENSE/d -i $GLOBUSPACKAGEDIR/%{_name}/noflavor_data.filelist

# Generate package filelists
cat $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_pgm.filelist \
    $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_dev.filelist \
    $GLOBUSPACKAGEDIR/%{_name}/noflavor_data.filelist \
  | sed s!^!%{_prefix}! > package.filelist

# man_MANS may get compressed
cat $GLOBUSPACKAGEDIR/%{_name}/noflavor_doc.filelist \
  | sed -e s!^!%{_prefix}! -e 's!\.[0-9]$!&*!' >> package.filelist

%clean
rm -rf $RPM_BUILD_ROOT

%files -f package.filelist
%defattr(-,root,root,-)
%dir %{_datadir}/globus
%dir %{_datadir}/globus/aclocal
%dir %{_datadir}/globus/doxygen
%dir %{_datadir}/globus/flavors
%dir %{_datadir}/globus/packages
%dir %{_datadir}/globus/packages/%{_name}
%dir %{_libdir}/globus
%dir %{_libdir}/globus/include
%{_bindir}/globus-spec-creator
%dir %{_docdir}/%{name}-%{version}

%changelog
* Sat Jul 17 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.17-1
- Update to Globus Toolkit 5.0.2

* Mon Apr 12 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.16-1
- Update to Globus Toolkit 5.0.1

* Thu Jan 21 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.15-8
- Update to Globus Toolkit 5.0.0

* Mon Dec 07 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.15-7
- rebuild against perl 5.10.1

* Thu Jul 23 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.15-6
- The globus-spec-creator script now uses isa tags and noarch doc subpackages
- Replace /usr/bin/env shebangs

* Tue Jun 02 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.15-5
- Update to official Fedora Globus packaging guidelines
- Fix build configuration for s390x and kfreebsd
- Make globus-core work with automake 1.11

* Mon Apr 27 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.15-4
- Install the globus-spec-creator script
- Add -Wl,--as-needed to the libtool script

* Tue Apr 21 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.15-3
- Update after clarification of packaging guidelines

* Wed Apr 15 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.15-2
- Make comment about source retrieval more explicit

* Fri Mar 20 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.15-1
- Change defines to globals

* Sun Mar 15 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.15-0.5
- Merge devel with main

* Thu Feb 26 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.15-0.4
- Add s390x to the list of 64 bit platforms

* Mon Dec 29 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.15-0.3
- Adapt to updated GPT package

* Sun Oct 12 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.15-0.2
- Update to Globus Toolkit 4.2.1

* Mon Jul 14 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.14-0.1
- Autogenerated
