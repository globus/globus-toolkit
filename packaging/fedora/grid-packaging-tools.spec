Name:		grid-packaging-tools
Version:	.
Release:	1%{?dist}
Summary:	Grid Packaging Tools (GPT)

Group:		Development/Tools
License:	NCSA
URL:		http://www.gridpackagingtools.com/
#		Maintenance of GPT has been taken over by the Globus Alliance.
#		Use the latest source tarball from their repository.
Source:		http://www.globus.org/ftppub/gt5/5.2/testing/packages/src/gpt-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires:	libtool
BuildRequires:	perl
Requires:	gzip
Requires:	tar
Requires:	autoconf
Requires:	automake
Requires:	libtool
Requires:	rpm
%if %{?suse_version:0}%{!?suse_version:1}
Requires:	rpm-build
%endif
%if %{?fedora}%{!?fedora:0}
Requires:	perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))
%else
%if %{?rhel}%{!?rhel:0} >= 4
Requires:	perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))
%else
Requires:	perl
%endif
%endif
BuildArch:	noarch

%{!?perl_vendorlib: %global perl_vendorlib %(eval "`%{__perl} -V:installvendorlib`"; echo $installvendorlib)}

%description
GPT is a collection of packaging tools built around an XML based
packaging data format. This format provides a straight forward way to
define complex dependency and compatibility relationships between
packages. The tools provide a means for developers to easily define the
packaging data and include it as part of their source code distribution.
Binary packages can be automatically generated from this data. The
packages defined by GPT are compatible with other packages and can be
easily converted.

%prep
%setup -q -n gpt-%{version}

%build

touch aclocal.m4
touch Makefile.in
touch configure
unset GLOBUS_LOCATION
unset GPT_LOCATION

for i in config.guess config.sub ; do
  [ -f /usr/share/libtool/$i ] && rm $i && cp -p /usr/share/libtool/$i $i
done

%configure --libexecdir='${datadir}/globus' \
           --mandir='${prefix}/share/man' \
	   --with-perlmoduledir=%{perl_vendorlib}
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT

make install DESTDIR=$RPM_BUILD_ROOT
make install-man DESTDIR=$RPM_BUILD_ROOT

# Remove old globus core source tarball - users should install an up-to-date
# globus-core package instead of having gpt compile it from source
rm $RPM_BUILD_ROOT%{_datadir}/globus/gpt/globus_core-src.tar.gz

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc CHANGES LICENSE README
%{_sbindir}/*
%{_datadir}/globus
%{_mandir}/man8/*
%{perl_vendorlib}/Grid

%changelog
* Wed Jun 26 2013 Globus Toolkit <support@globus.org> - .-1
- GT-424: New Fedora Packaging Guideline - no %_isa in BuildRequires

* Thu Jun 20 2013 Globus Toolkit <support@globus.org> - 3.6.5-1
- GT-402: gpt-bootstrap should call automake with --force-missing

* Thu Jun 20 2013 Globus Toolkit <support@globus.org> - 3.6.4-1
- GT-342: Warning from GPT with newer perl version

* Mon Nov 26 2012 Globus Toolkit <support@globus.org> - 3.6.3-2
- 5.2.3

* Tue Jul 31 2012 Joseph Bester <bester@mcs.anl.gov> - 3.6.3-1
- GT-257: gpt_create_automake_rules creates duplicate rules for man pages

* Thu Mar 15 2012 Joseph Bester <bester@mcs.anl.gov> - 3.6.2-1
- Patch to allow GPT_LOCATION and GLOBUS_LOCATION to be different

* Tue Feb 14 2012 Joseph Bester <bester@mcs.anl.gov> - 3.6.1-1
- RIC-207: pkg-config files have undefined variable GLOBUS_FLAVOR_NAME
- RIC-219: GPT-created pkg-config files are missing major versions in
           dependencies
- RIC-220: GPT doesn't know about shared library extensions on some platforms
- RIC-221: Remove unneccessary evals of path components from GPT initializer
- RIC-222: Make GPT configure help message have standard autotools format

* Thu Dec 22 2011 Joseph Bester <bester@mcs.anl.gov> - 3.6-1
- RIC-207: pkg-config files have undefined variable GLOBUS_FLAVOR_NAME

* Fri Oct 28 2011 Joseph Bester <bester@mcs.anl.gov> - 3.5-1
- Quote paths in regular expressions
- Fix bugs in pkgconfig file generator

* Thu Sep 01 2011 Joseph Bester <bester@mcs.anl.gov> - 3.4-1
- Update for GT 5.1.2

* Mon Aug 03 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.2-20
- Rename config.guess script

* Fri Jul 24 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.2-19
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Wed May 27 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.2-18
- Make GPT work with automake 1.11

* Thu Mar 26 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.2-17
- Adding wrong-url patch

* Mon Mar 16 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.2-16
- Adding version-info patch

* Fri Feb 27 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.2-15
- Newest version of redhat-rpm-config doesn't copy config.guess by default
  in the configure macro anymore - added explicit copy

* Mon Feb 16 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.2-14
- Added BuildRequires on perl
- Moved license charset conversion to prep section
- Added comments with reasons for removing installed files

* Tue Dec 16 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.2-13
- change name from gpt to grid-packaging-tools to avoid potential confusion
  with ubuntu's gpt package (G-Portugol)

* Tue Dec 09 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.2-12
- Make gpt work with older automake versions

* Sat Oct 04 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.2-11
- Add some backward compatibility
- Make perl module directory configurable

* Sun Jul 13 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.2-10
- use the sources from Globus Alliance since those are maintained
- split the big FHS patch into several smaller ones
- change name back gpt again

* Wed Jul 02 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.2-9
- change name from gpt to grid-packaging-tools

* Wed Jul 02 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.2-8
- Convert to noarch package

* Tue Jun 24 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.2-7
- Add export of GPT_AGE_VERSION

* Sat Jun 21 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.2-6
- Install in /usr instead of /opt/gpt - quite some work...
- Make it work without having GPT_LOCATION set if we are in /usr
- Drop the /etc/profile.d scripts (not needed since we are now in /usr)
- Do not build and install dependencies - use system versions
- Use RPM Group "Development/Tools"

* Tue Jun 19 2007 Anders Wäänänen <waananen@nbi.dk> - 3.2-5ng
- Add dist tag to release
- Change BuildRoot

* Wed Jun 01 2005 Anders Wäänänen <waananen@nbi.dk> - 3.2-4ng
- Add fix to setup dir handling
- Restructure changelog to have versions on main line

* Fri Mar 18 2005 Anders Wäänänen <waananen@nbi.dk> - 3.2-3ng
- Add patch to fix globus_package.dtd

* Tue Mar 01 2005 Anders Wäänänen <waananen@nbi.dk> - 3.2-2ng
- Add patch with fixes from the Globus 3.9.5 GPT release
  (Do not include the core though)

* Fri May 21 2004 Anders Wäänänen <waananen@nbi.dk> - 3.2-1ng

* Sun Feb 01 2004 Anders Wäänänen <waananen@nbi.dk> - 3.1-3ng
- Fix problem when new files are links rather than directories

* Thu Jan 08 2004 Anders Wäänänen <waananen@nbi.dk> - 3.1-2ng
- Fix for Mandrake 9.2 - unset RPM_BUILD_ROOT before building
  Found by Jakob Langgaard Nielsen <langgard@nbi.dk>

* Sat Jan 03 2004 Anders Wäänänen <waananen@nbi.dk> - 3.1-1ng
- Drop patches: gpt-3.0.1-dependency.patch, gpt-3.0.1-doc.patch
  since the problems involved are either solved or obsolete
- Make /etc/profile.d relocatable
- Use gpt_location macro to define GPT_LOCATION
- Use RPM Group "System Environment/Base" instead of Applications
- Slightly change build procedure

* Tue Oct 07 2003 Anders Wäänänen <waananen@nbi.dk> - 3.0.1-1ng
- Remove the now unecessary dependency cleanup introduced in 2.2.10-2ng
- Fix some cases in the documentation

* Tue Jun 24 2003 Anders Wäänänen <waananen@nbi.dk> - 2.2.10-2ng
- Dependency cleanup by Mattias Ellert <mattias.ellert@tsl.uu.se>

* Mon Jun 23 2003 Anders Wäänänen <waananen@nbi.dk> - 2.2.10

* Sat Jun 02 2003 Anders Wäänänen <waananen@nbi.dk> - 3.1a1-2
- Fix perl inconsistencies reported by Mattias Ellert
  <mattias.ellert@tsl.uu.se>

* Sat May 24 2003 Anders Wäänänen <waananen@nbi.dk> - 3.1a1
- Bring back perl-Tk dependency

* Mon Apr 07 2003 Anders Wäänänen <waananen@nbi.dk> - 3.0-1ng

* Tue Mar 22 2003 Anders Wäänänen <waananen@nbi.dk> - 2.2.9-1ng
- Add bogus perl(Grid::GPT::Version) provides to help rpm

* Tue Mar 04 2003 Anders Wäänänen <waananen@nbi.dk> - 2.2.8-1ng

* Tue Dec 05 2002 Anders Wäänänen <waananen@nbi.dk> - 2.2.7-1ng

* Tue Nov 05 2002 Anders Wäänänen <waananen@nbi.dk> - 2.2.5-1ng
- Remove Tk dependence for RedHat 8.0

* Tue Oct 29 2002 Anders Wäänänen <waananen@nbi.dk> - 2.2.4-2ng
- Insert missing backslash in csh profile script

* Tue Sep 24 2002 Anders Wäänänen <waananen@nbi.dk>
- Use 2.2 final

* Sat Aug 31 2002 Anders Wäänänen <waananen@nbi.dk>
- Use 2.2rc1 tarball from Globus CVS

* Thu Aug 15 2002 Anders Wäänänen <waananen@nbi.dk>
- Use NCSA distribution instead of Globus

* Mon Apr 08 2002 Anders Wäänänen <waananen@nbi.dk>
- Initial build.
