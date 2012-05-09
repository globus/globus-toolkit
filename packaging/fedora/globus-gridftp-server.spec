%ifarch alpha ia64 ppc64 s390x sparc64 x86_64
%global flavor gcc64
%else
%global flavor gcc32
%endif

%if "%{?rhel}" == "4" || "%{?rhel}" == "5"
%global docdiroption "with-docdir"
%else
%global docdiroption "docdir"
%endif

Name:		globus-gridftp-server
%global _name %(tr - _ <<< %{name})
Version:	6.10
Release:	2%{?dist}
Summary:	Globus Toolkit - Globus GridFTP Server

Group:		System Environment/Libraries
License:	ASL 2.0
URL:		http://www.globus.org/
Source:		http://www.globus.org/ftppub/gt5/5.2/5.2.1/packages/src/%{_name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires:	globus-common%{?_isa} >= 14
Requires:	globus-gridftp-server-control%{?_isa} >= 2
Requires:	globus-usage%{?_isa} >= 3
Requires:	globus-xio%{?_isa} >= 3
Requires:	globus-authz%{?_isa} >= 2
Requires:	globus-gfork%{?_isa} >= 3
Requires:	globus-ftp-control%{?_isa} >= 4
Requires:	globus-xio-gsi-driver%{?_isa} >= 2

BuildRequires:	grid-packaging-tools >= 3.4
BuildRequires:	globus-gridftp-server-control-devel%{?_isa} >= 2
BuildRequires:	globus-usage-devel%{?_isa} >= 3
BuildRequires:	globus-xio-gsi-driver-devel%{?_isa} >= 2
BuildRequires:	globus-xio-devel%{?_isa} >= 3
BuildRequires:	globus-authz-devel%{?_isa} >= 2
BuildRequires:	globus-gfork-devel%{?_isa} >= 3
BuildRequires:	globus-ftp-control-devel%{?_isa} >= 4

%package progs
Summary:	Globus Toolkit - Globus GridFTP Server Programs
Group:		Applications/Internet
Requires:	%{name}%{?_isa} = %{version}-%{release}
Requires:	globus-xio-gsi-driver%{?_isa} >= 2

%package devel
Summary:	Globus Toolkit - Globus GridFTP Server Development Files
Group:		Development/Libraries
Requires:	%{name}%{?_isa} = %{version}-%{release}
Requires:	globus-gridftp-server-control-devel%{?_isa} >= 2
Requires:	globus-usage-devel%{?_isa} >= 3
Requires:	globus-xio-gsi-driver-devel%{?_isa} >= 2
Requires:	globus-xio-devel%{?_isa} >= 3
Requires:	globus-authz-devel%{?_isa} >= 2
Requires:	globus-gfork-devel%{?_isa} >= 3
Requires:	globus-ftp-control-devel%{?_isa} >= 4

%description
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
Globus GridFTP Server

%description progs
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-progs package contains:
Globus GridFTP Server Programs

%description devel
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-devel package contains:
Globus GridFTP Server Development Files

%prep
%setup -q -n %{_name}-%{version}

%build
# Remove files that should be replaced during bootstrap
rm -f doxygen/Doxyfile*
rm -f doxygen/Makefile.am
rm -f pkgdata/Makefile.am
rm -f globus_automake*
rm -rf autom4te.cache
unset GLOBUS_LOCATION
unset GPT_LOCATION

%{_datadir}/globus/globus-bootstrap.sh

export GRIDMAP=/etc/grid-security/grid-mapfile
%configure --with-flavor=%{flavor} --sysconfdir=/etc/%{name} \
           --%{docdiroption}=%{_docdir}/%{name}-%{version} \
           --disable-static

make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
mv $RPM_BUILD_ROOT%{_sysconfdir}/gridftp.conf.default $RPM_BUILD_ROOT%{_sysconfdir}/gridftp.conf
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/xinetd.d
mv $RPM_BUILD_ROOT%{_sysconfdir}/gridftp.xinetd.default $RPM_BUILD_ROOT%{_sysconfdir}/xinetd.d/gridftp
mv $RPM_BUILD_ROOT%{_sysconfdir}/gridftp.gfork.default $RPM_BUILD_ROOT%{_sysconfdir}/gridftp.gfork

GLOBUSPACKAGEDIR=$RPM_BUILD_ROOT%{_datadir}/globus/packages

# Remove libtool archives (.la files)
find $RPM_BUILD_ROOT%{_libdir} -name 'lib*.la' -exec rm -v '{}' \;
sed '/lib.*\.la$/d' -i $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_dev.filelist

# Generate package filelists
cat $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_rtl.filelist \
    $GLOBUSPACKAGEDIR/%{_name}/noflavor_doc.filelist \
  | sed -e '/\/man[0-9]/d' \
  | sed s!^!%{_prefix}! > package.filelist
cat $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_pgm.filelist \
    $GLOBUSPACKAGEDIR/%{_name}/noflavor_data.filelist \
  | grep -Ev '(gridftp.conf.default|gridftp.xinetd.default|gridftp.gfork.default)' \
  | sed -e s!^!%{_prefix}! | sed -e s!^/usr/etc!/etc! \
  > package-progs.filelist
cat $GLOBUSPACKAGEDIR/%{_name}/noflavor_doc.filelist \
  | grep '/man[0-9]/' \
  | sed -e s!^!%{_prefix}! | sed -e s!^/usr/etc!/etc! \
  | sed -e 's!/man[0-9]/.*!&.gz!' \
  >> package-progs.filelist
cat $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_dev.filelist \
  | sed s!^!%{_prefix}! > package-devel.filelist

%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%post progs
if [ $1 -eq 1 ]; then
    /sbin/chkconfig --add globus-gridftp-server
    /sbin/chkconfig --add globus-gridftp-sshftp
fi

%preun progs
if [ $1 -eq 0 ]; then
    /sbin/chkconfig --del globus-gridftp-server
    /sbin/chkconfig --del globus-gridftp-sshftp
    /sbin/service globus-gridftp-server stop
    /sbin/service globus-gridftp-sshftp stop
fi

%postun progs
if [ $1 -eq 1 ]; then
    /sbin/service globus-gridftp-server condrestart > /dev/null 2>&1 || :
    /sbin/service globus-gridftp-sshftp condrestart > /dev/null 2>&1 || :
fi

%files -f package.filelist
%defattr(-,root,root,-)
%dir %{_datadir}/globus/packages/%{_name}
%dir %{_docdir}/%{name}-%{version}

%files -f package-progs.filelist progs
%defattr(-,root,root,-)
%config(noreplace) %{_sysconfdir}/gridftp.conf
%config(noreplace) %{_sysconfdir}/gridftp.gfork
%config(noreplace) %{_sysconfdir}/xinetd.d/gridftp

%files -f package-devel.filelist devel
%defattr(-,root,root,-)

%changelog
* Wed May 09 2012 Joseph Bester <bester@mcs.anl.gov> - 6.10-2
- RHEL 4 patches

* Fri Apr 13 2012 Joseph Bester <bester@mcs.anl.gov> - 6.10-1
- RIC-258: Can't rely on MKDIR_P

* Tue Mar 27 2012  <mlink@mcs.anl.gov> - 6.9-1
- GRIDFTP-228: Don't require delegated cred on initial log in.

* Fri Mar 23 2012 Joseph Bester <bester@mcs.anl.gov> - 6.8-1
- GRIDFTP-227: Add server option to enable threaded operation and set number of threads.
- GRIDFTP-226: Fix recursed dir listings in split/striped server mode, when recursion wasn't requested.
- GRIDFTP-224: Add option to set custom client starting/home directory
- GRIDFTP-221: additional changes towards maintaining backwards compatibility.
- GRIDFTP-215: add MFMT synonym to SITE UTIME

* Tue Mar 06 2012 Joseph Bester <bester@mcs.anl.gov> - 6.7-1
- GRIDFTP-164: improve dir streaming stability
- GRIDFTP-165: correct chunking of MLSC response
- GRIDFTP-165: fix MLSC over split processes
- GRIDFTP-196: fix behaviour for syntax errors in server options
- GRIDFTP-201: Add heartbeat/status markers to CKSM and RETR
- GRIDFTP-209: Add manpage for globus-gridftp-server
- GRIDFTP-212: GridFTP server doesn't build if PATH_MAX is not defined
- GRIDFTP-217: fix -connections-disabled for inetd
- GRIDFTP-218: add -fork-fallback
- GRIDFTP-219: allow prot without gsi
- GRIDFTP-221: backwards compatibility fix and future binary compatibility
               stability additions
- GRIDFTP-222: fix threaded issues with streaming dir info for mlsd and mlsc
- RIC-226: Some dependencies are missing in GPT metadata
- RIC-229: Clean up GPT metadata

* Tue Feb 14 2012 Joseph Bester <bester@mcs.anl.gov> - 6.6-1
- GRIDFTP-209: Add manpage for globus-gridftp-server
- GRIDFTP-212: GridFTP server doesn't build if PATH_MAX is not defined
- RIC-226: Some dependencies are missing in GPT metadata
- RIC-229: Clean up GPT metadata

* Mon Dec 12 2011 Joseph Bester <bester@mcs.anl.gov> - 6.5-1
- init script fixes

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 6.4-3
- Update for 5.2.0 release

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 6.4-2
- Last sync prior to 5.2.0

* Fri Nov 11 2011 Joseph Bester <bester@mcs.anl.gov> - 6.3-1
- GRIDFTP-190: add in config dir loading

* Mon Oct 24 2011 Joseph Bester <bester@mcs.anl.gov> - 6.2-2
- Add explicit dependencies on >= 5.2 libraries
- Add backward-compatibility aging
- Fix %post* scripts to check for -eq 1

* Fri Sep 23 2011 Joseph Bester <bester@mcs.anl.gov> - 6.1-1
- GRIDFTP-184: Detect and workaround bug in start_daemon for LSB < 4

* Wed Aug 31 2011 Joseph Bester <bester@mcs.anl.gov> - 6.0-3
- Add more config files for xinetd or gfork startup
- Update to Globus Toolkit 5.1.2

* Sat Jul 17 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.23-1
- Update to Globus Toolkit 5.0.2

* Wed Apr 14 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.21-1
- Update to Globus Toolkit 5.0.1

* Sat Jan 23 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.19-1
- Update to Globus Toolkit 5.0.0

* Mon Oct 19 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.17-2
- Fix location of default config file

* Thu Jul 30 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 3.17-1
- Autogenerated
