%ifarch alpha ia64 ppc64 s390x sparc64 x86_64
%global flavor gcc64
%else
%global flavor gcc32
%endif

%if "%{?rhel}" == "5"
%global docdiroption "with-docdir"
%else
%global docdiroption "docdir"
%endif

Name:		globus-gatekeeper
%global _name %(tr - _ <<< %{name})
Version:	9.10
Release:	1%{?dist}
Summary:	Globus Toolkit - Globus Gatekeeper

Group:		Applications/Internet
License:	ASL 2.0
URL:		http://www.globus.org/
Source:         http://www.globus.org/ftppub/gt5/5.2/5.2.1/packages/src/%{_name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires:	globus-common >= 14
Requires:	globus-gss-assist%{?_isa} >= 8
Requires:	globus-gssapi-gsi%{?_isa} >= 9
Requires:       psmisc

Requires:       lsb
Requires(post): globus-common-progs >= 13.4
Requires(preun):globus-common-progs >= 13.4
BuildRequires:  lsb
BuildRequires:	grid-packaging-tools >= 3.4
BuildRequires:	globus-gss-assist-devel%{?_isa} >= 8
BuildRequires:	globus-gssapi-gsi-devel%{?_isa} >= 9
BuildRequires:	globus-core%{?_isa} >= 8

%description
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
Globus Gatekeeper
Globus Gatekeeper Setup

%prep
%setup -q -n %{_name}-%{version}

%build
# Remove files that should be replaced during bootstrap
rm -f doxygen/Doxyfile*
rm -f doxygen/Makefile.am
rm -f pkgdata/Makefile.am
rm -f globus_automake*
rm -rf autom4te.cache

%{_datadir}/globus/globus-bootstrap.sh

%configure --with-flavor=%{flavor} \
           --%{docdiroption}=%{_docdir}/%{name}-%{version} \
           --disable-static \
           --with-lsb \
	   --with-initscript-config-path=/etc/sysconfig/globus-gatekeeper \
           --with-lockfile-path='${localstatedir}/lock/subsys/globus-gatekeeper'

make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

GLOBUSPACKAGEDIR=$RPM_BUILD_ROOT%{_datadir}/globus/packages

# Generate package filelists
cat $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_pgm.filelist \
    $GLOBUSPACKAGEDIR/%{_name}/noflavor_doc.filelist \
    $GLOBUSPACKAGEDIR/%{_name}/noflavor_data.filelist \
  | grep -v '^/etc' \
  | sed -e s!^!%{_prefix}! -e 's!.*/man/.*!%doc &*!' > package.filelist
cat $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_pgm.filelist \
    $GLOBUSPACKAGEDIR/%{_name}/noflavor_doc.filelist \
    $GLOBUSPACKAGEDIR/%{_name}/noflavor_data.filelist \
  | grep '^/etc' >> package.filelist
mkdir -p $RPM_BUILD_ROOT/etc/grid-services
mkdir -p $RPM_BUILD_ROOT/etc/grid-services/available

%clean
rm -rf $RPM_BUILD_ROOT

%post
if [ $1 -eq 1 ]; then
    /sbin/chkconfig --add %{name}
fi

%preun
if [ $1 -eq 0 ]; then
    /sbin/chkconfig --del %{name}
    /sbin/service %{name} stop > /dev/null 2>&1 || :
fi

%postun
if [ $1 -eq 1 ]; then
    /sbin/service %{name} condrestart > /dev/null 2>&1 || :
fi

%files -f package.filelist
%defattr(-,root,root,-)
%dir %{_datadir}/globus/packages/%{_name}
%dir %{_docdir}/%{name}-%{version}
%dir /etc/grid-services
%dir /etc/grid-services/available
%config(noreplace) /etc/sysconfig/globus-gatekeeper
%config(noreplace) /etc/logrotate.d/globus-gatekeeper

%changelog
* Fri Apr 06 2012 Joseph Bester <bester@mcs.anl.gov> - 9.10-1
- GRAM-335: init scripts fail on solaris because of stop alias
- RIC-205: Missing directories $GLOBUS_LOCATION/var/lock and $GLOBUS_LOCATION/var/run

* Tue Feb 14 2012 Joseph Bester <bester@mcs.anl.gov> - 9.9-1
- GRAM-303: Gatekeeper's syslog output cannot be controlled
- GRAM-309: GRAM5 doesn't work with IPv4 only gatekeepers
- RIC-226: Some dependencies are missing in GPT metadata

* Fri Jan 06 2012 Joe Bester <jbester@mactop2.local> - 9.7-1
- GRAM-303: Gatekeeper's syslog output cannot be controlled

* Mon Dec 12 2011 Joseph Bester <bester@mcs.anl.gov> - 9.6-1
- init script fixes

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 9.5-3
- Update for 5.2.0 release

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 9.5-2
- Last sync prior to 5.2.0

* Mon Nov 28 2011 Joseph Bester <bester@mcs.anl.gov> - 9.5-1
- GRAM-285: Set default gatekeeper log in native packages

* Mon Nov 28 2011 Joseph Bester <bester@mcs.anl.gov> - 9.4-1
- GRAM-287: Hang of globus-gatekeeper process

* Wed Nov 23 2011 Joseph Bester <bester@mcs.anl.gov> - 9.3-1
- Updated version numbers

* Tue Nov 15 2011 Joseph Bester <bester@mcs.anl.gov> - 9.2-1
- GRAM-276: Increase backlog for gatekeeper

* Mon Nov 07 2011 Joseph Bester <bester@mcs.anl.gov> - 9.1-1
- Add default chkconfig line

* Mon Nov 07 2011 Joseph Bester <bester@mcs.anl.gov> - 9.0-1
- GRAM-268: GRAM requires gss_export_sec_context to work

* Fri Oct 28 2011 Joseph Bester <bester@mcs.anl.gov> - 8.2-1
- GRAM-267: globus-gatekeeper uses inappropriate Default-Start in init script

* Fri Oct 21 2011 Joseph Bester <bester@mcs.anl.gov> - 8.1-2
- Fix %post* scripts to check for -eq 1
- Add explicit dependencies on >= 5.2 libraries

* Fri Sep 23 2011 Joe Bester <bester@mcs.anl.gov> - 8.1-1
- GRAM-260: Detect and workaround bug in start_daemon for LSB < 4

* Thu Sep 01 2011 Joseph Bester <bester@mcs.anl.gov> - 8.0-2
- Update for 5.1.2 release

* Mon Apr 25 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.7-4
- Add README file

* Tue Apr 19 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.7-3
- Add start-up script and README.Fedora file

* Mon Feb 28 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.7-2
- Fix typos in the setup patch

* Thu Feb 24 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.7-1
- Update to Globus Toolkit 5.0.3

* Tue Feb 08 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 5.5-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Sat Jul 17 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.5-2
- Simplify directory ownership

* Wed Apr 14 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.5-1
- Update to Globus Toolkit 5.0.1

* Sat Jan 23 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.3-1
- Update to Globus Toolkit 5.0.0

* Wed Jul 29 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.0-1
- Autogenerated
