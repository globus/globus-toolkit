Name:		globus-gridftp-server
%global _name %(tr - _ <<< %{name})
Version:	7.26
Release:	1%{?dist}
Summary:	Globus Toolkit - Globus GridFTP Server

Group:		System Environment/Libraries
License:	ASL 2.0
URL:		http://toolkit.globus.org/
Source:	http://toolkit.globus.org/ftppub/gt6/packages/%{_name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires:	globus-common%{?_isa} >= 15
Requires:	globus-gridftp-server-control%{?_isa} >= 2
Requires:	globus-usage%{?_isa} >= 3
Requires:	globus-xio%{?_isa} >= 5
Requires:	globus-authz%{?_isa} >= 2
Requires:	globus-gfork%{?_isa} >= 3
Requires:	globus-ftp-control%{?_isa} >= 6
Requires:	globus-xio-gsi-driver%{?_isa} >= 2
Requires:	globus-gsi-credential%{?_isa} >= 6
Requires:       globus-xio-udt-driver%{?_isa} >= 1

BuildRequires:	globus-gridftp-server-control-devel >= 2
BuildRequires:	globus-usage-devel >= 3
BuildRequires:	globus-xio-gsi-driver-devel >= 2
BuildRequires:	globus-xio-devel >= 5
BuildRequires:	globus-authz-devel >= 2
BuildRequires:	globus-gfork-devel >= 3
BuildRequires:	globus-ftp-control-devel >= 6
BuildRequires:	globus-gss-assist-devel >= 9
BuildRequires:  globus-common-progs >= 15
BuildRequires:	globus-gsi-credential-devel >= 6
%if %{?fedora}%{!?fedora:0} >= 19 || %{?rhel}%{!?rhel:0} >= 7
BuildRequires:  automake >= 1.11
BuildRequires:  autoconf >= 2.60
BuildRequires:  libtool >= 2.2
%endif
BuildRequires:  pkgconfig
%if 0%{?suse_version} > 0
BuildRequires: libtool
%else
BuildRequires: libtool-ltdl-devel
%endif

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
Requires:	globus-xio-devel%{?_isa} >= 5
Requires:	globus-authz-devel%{?_isa} >= 2
Requires:	globus-gfork-devel%{?_isa} >= 3
Requires:	globus-ftp-control-devel%{?_isa} >= 6
Requires:	globus-gss-assist%{?_isa} >= 9
Requires:	globus-gsi-credential%{?_isa} >= 6

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
%if %{?fedora}%{!?fedora:0} >= 19 || %{?rhel}%{!?rhel:0} >= 7
# Remove files that should be replaced during bootstrap
rm -rf autom4te.cache

autoreconf -if
%endif

export GRIDMAP=/etc/grid-security/grid-mapfile

%configure \
           --disable-static \
           --docdir=%{_docdir}/%{name}-%{version} \
           --includedir=%{_includedir}/globus \
           --libexecdir=%{_datadir}/globus

make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
mv $RPM_BUILD_ROOT%{_sysconfdir}/gridftp.conf.default $RPM_BUILD_ROOT%{_sysconfdir}/gridftp.conf
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/xinetd.d
mv $RPM_BUILD_ROOT%{_sysconfdir}/gridftp.xinetd.default $RPM_BUILD_ROOT%{_sysconfdir}/xinetd.d/gridftp
mv $RPM_BUILD_ROOT%{_sysconfdir}/gridftp.gfork.default $RPM_BUILD_ROOT%{_sysconfdir}/gridftp.gfork

# Remove libtool archives (.la files)
find $RPM_BUILD_ROOT%{_libdir} -name 'lib*.la' -exec rm -v '{}' \;

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

%files
%defattr(-,root,root,-)
%dir %{_docdir}/%{name}-%{version}
%{_docdir}/%{name}-%{version}/GLOBUS_LICENSE
%{_libdir}/libglobus*.so.*

%files progs
%defattr(-,root,root,-)
%config(noreplace) %{_sysconfdir}/gridftp.conf
%config(noreplace) %{_sysconfdir}/gridftp.gfork
%config(noreplace) %{_sysconfdir}/xinetd.d/gridftp
%{_sysconfdir}/init.d/*
%{_sbindir}/*
%{_mandir}/man8/*

%files devel
%defattr(-,root,root,-)
%{_includedir}/globus/*
%{_libdir}/libglobus*.so
%{_libdir}/pkgconfig/*.pc

%changelog
* Fri Jun 05 2015 Globus Toolkit <support@globus.org> - 7.26-1
- Fix GLOBUS_VERSION detection during configure from installer

* Tue Apr 07 2015 Globus Toolkit <support@globus.org> - 7.25-1
- Fix order of drivers when using netmgr

* Fri Mar 27 2015 Globus Toolkit <support@globus.org> - 7.24-1
- fix netmanager crash
- allow netmanager calls when taskid isn't set

* Mon Mar 16 2015 Globus Toolkit <support@globus.org> - 7.23-1
- fix threads commandline arg processing
- prevent parse error on pre-init envs from raising assertion

* Fri Mar 06 2015 Globus Toolkit <support@globus.org> - 7.22-1
- windows fix

* Fri Mar 06 2015 Globus Toolkit <support@globus.org> - 7.21-1
- GT-586: Restrict sharing based on username or group membership
- GT-552: don't enable udt without threads
- GT-585: Environrment and threading config not loaded from config dir
- Ignore config.d files with a '.' in name
- always install udt driver

* Tue Jan 06 2015 Globus Toolkit <support@globus.org> - 7.20-1
- Fix autoreconf error on some setups

* Tue Dec 23 2014 Globus Toolkit <support@globus.org> - 7.19-1
- Fix -help long line formatting

* Mon Dec 22 2014 Globus Toolkit <support@globus.org> - 7.18-1
- GT-575: Add support for the network manager driver.

* Fri Dec 05 2014 Globus Toolkit <support@globus.org> - 7.17-1
- Fix share file creation errors on bad fuse filesystems.

* Sun Nov 16 2014 Globus Toolkit <support@globus.org> - 7.16-1
- don't attempt to get retransmit count on http transfer

* Mon Nov 10 2014 Globus Toolkit <support@globus.org> - 7.15-1
- Remove reference to Globus::Core::Paths

* Mon Nov 03 2014 Globus Toolkit <support@globus.org> - 7.14-1
- Fix logging of IPv6 address

* Tue Oct 28 2014 Globus Toolkit <support@globus.org> - 7.13-1
- GT-477: Tracking TCP retransmits on the GridFTP server

* Tue Sep 23 2014 Globus Toolkit <support@globus.org> - 7.12-1
- Add missing dependencies
- Quiet some autoconf/automake warnings
- Fix some typos in help messages

* Fri Aug 22 2014 Globus Toolkit <support@globus.org> - 7.11-1
- Merge fixes from ellert-globus_6_branch

* Wed Aug 20 2014 Globus Toolkit <support@globus.org> - 7.10-2
- Fix Source path

* Mon Jun 09 2014 Globus Toolkit <support@globus.org> - 7.10-1
- Merge changes from Mattias Ellert

* Tue May 27 2014 Globus Toolkit <support@globus.org> - 7.9-1
- Use globus_libc_unsetenv

* Tue May 27 2014 Globus Toolkit <support@globus.org> - 7.8-1
- Use package-named config.h

* Thu Apr 24 2014 Globus Toolkit <support@globus.org> - 7.7-1
- Packaging fixes

* Fri Apr 18 2014 Globus Toolkit <support@globus.org> - 7.6-1
- Version bump for consistency

* Thu Feb 27 2014 Globus Toolkit <support@globus.org> - 7.4-1
- Packaging fixes, Warning Cleanup

* Thu Feb 20 2014 Globus Toolkit <support@globus.org> - 7.3-1
- Crash on DCAU N with custom net stack

* Fri Feb 14 2014 Globus Toolkit <support@globus.org> - 7.2-1
- Packaging fixes

* Thu Feb 13 2014 Globus Toolkit <support@globus.org> - 7.1-1
- Packagin fixes

* Tue Jan 21 2014 Globus Toolkit <support@globus.org> - 7.0-1
- Repackage for GT6 without GPT

* Mon Oct 28 2013 Globus Toolkit <support@globus.org> - 6.38-1
- Update dependencies for new credential/assist functions

* Mon Oct 28 2013 Globus Toolkit <support@globus.org> - 6.37-2
- Update dependencies for new credential/assist functions

* Tue Oct 15 2013 Globus Toolkit <support@globus.org> - 6.37-1
- GT-374: Can't share files in a path structure with symlinks
- GT-428: Improve handling of hanging GridFTP server processes
- GT-469: MFMT/UTIME update access time but shouldn't

* Thu Aug 15 2013 Globus Toolkit <support@globus.org> - 6.36-1
- GT-368: Fix log message concatination when writing to syslog
- GT-420: revert to documented behavior for restricted paths

* Wed Jul 31 2013 Globus Toolkit <support@globus.org> - 6.35-1
- GT-428: improve handling of hanging server processes

* Wed Jul 31 2013 Globus Toolkit <support@globus.org> - 6.34-1
- GT-428: improve handling of hanging server processes

* Wed Jun 26 2013 Globus Toolkit <support@globus.org> - 6.33-2
- GT-424: New Fedora Packaging Guideline - no %_isa in BuildRequires

* Wed Jun 19 2013 Globus Toolkit <support@globus.org> - 6.33-1
- Add GLOBUS_OPENSSL in configure

* Wed Jun 05 2013 Globus Toolkit <support@globus.org> - 6.32-1
- GT-396: fix mlst on filenames that end in a newline
- GT-412: add -version-tag to set an identifier in the server version string
- fix minor memory leaks
- fix mlsx symlink target not urlencoding properly

* Tue Jun 04 2013 Globus Toolkit <support@globus.org> - 6.31-1
- GT-407 regression

* Mon Jun 03 2013 Globus Toolkit <support@globus.org> - 6.30-1
- GT-408: service globus-gridftp-server status returns incorrect status on SL5

* Sat Jun 01 2013 Globus Toolkit <support@globus.org> - 6.29-1
- GT-337: add UDT NAT traversal protocol
- GT-400: send confid when configured with default target

* Fri May 31 2013 Globus Toolkit <support@globus.org> - 6.28-1
- GT-407: globus-gridftp-server status returns 0 when not running on ubuntu

* Thu May 16 2013 Globus Toolkit <support@globus.org> - 6.27-1
- Allow variables in -sharing-rp
- fix 32/64 rpm conflicts
- create -sharing-state-dir when default
- correctly handle a share root containing "

* Wed May 08 2013 Globus Toolkit <support@globus.org> - 6.26-1
- GT-388: perform sharing access check inside the chroot
- fix chroot setup script for different MAKEDEV location

* Fri Apr 26 2013 Globus Toolkit <support@globus.org> - 6.25-1
- GT-365 control sharing by individual share ids
- GT-365 always restrict state dir when sharing

* Mon Apr 15 2013 Globus Toolkit <support@globus.org> - 6.24-1
- GT-365 verify sharing cert chain
- GT-365 update sharing config from sharing-file to state-dir
- GT-364 SSHFTP fixes

* Tue Mar 19 2013 Globus Toolkit <support@globus.org> - 6.23-1
- Update sharing to support a full cert chain at logon

* Mon Mar 18 2013 Globus Toolkit <support@globus.org> - 6.22-1
- GT-354: Compatibility with automake 1.13

* Wed Mar 06 2013 Globus Toolkit <support@globus.org> - 6.21-1
- missing build dependency

* Wed Mar 06 2013 Globus Toolkit <support@globus.org> - 6.20-1
- GT-365: Switch sharing user identification from DN to CERT

* Mon Feb 04 2013 Globus Toolkit <support@globus.org> - 6.19-1
- GT-302: Add initial sharing support to the GridFTP server
- GT-335: Update doc to clarify restrict_paths backend usage.
- GT-348: fix for logging of username after a hybrid mode striped transfer
- GT-351: fix for errors when surpassing config line limit, remove limits
- GT-353: avoid accessing new struct member if DSI isn't compatible
- GT-356: Add configuration and a command to make the sharing authorization file easier to manage
- GT-358: Invalid values for boolean config options silently sets the option false.

* Mon Nov 26 2012 Globus Toolkit <support@globus.org> - 6.16-2
- 5.2.3

* Thu Nov 08 2012 Globus Toolkit <support@globus.org> - 6.16-1
- GT-299: fix race condition occuring when transfer finishes while COMMIT event is outstanding
- GT-304: fix bashim in sh script
- GT-310: clarify -rp-follow-symlinks help
- GT-314: fix crash when attempting striping in hybrid mode and backends are not available
- GT-316: log ip address of incoming connection after failure discovering hostname

* Wed Sep 19 2012 Michael Link <mlink@mcs.anl.gov> - 6.15-1
- GT-269: GridFTP servers do not report the DEST IP address in transfer logs or usage stats when configured for striping or split processes

* Tue Jul 17 2012 Joseph Bester <bester@mcs.anl.gov> - 6.14-1
- GT-254: Gridftp server uses dynamic string as sprintf argument

* Mon Jul 16 2012 Joseph Bester <bester@mcs.anl.gov> - 6.13-2
- GT 5.2.2 final

* Thu Jul 12 2012 Joseph Bester <bester@mcs.anl.gov> - 6.13-1
- GT-172: Removed custom MLSx tag feature
- GT-244: Cleaned up memory leaks
- GT-243: Fix needless frontend->backend connections

* Wed Jun 27 2012 Joseph Bester <bester@mcs.anl.gov> - 6.12-1
- GRIDFTP-164: improve dir streaming stability
- GRIDFTP-165: correct chunking of MLSC response
- GRIDFTP-165: fix MLSC over split processes
- GRIDFTP-196: fix behaviour for syntax errors in server options
- GRIDFTP-201: Add heartbeat/status markers to CKSM and RETR
- GRIDFTP-209: Add manpage for globus-gridftp-server
- GRIDFTP-212: GridFTP server doesn't build if PATH_MAX is not defined
- GRIDFTP-215: add MFMT synonym to SITE UTIME
- GRIDFTP-217: fix -connections-disabled for inetd
- GRIDFTP-218: add -fork-fallback
- GRIDFTP-219: allow prot without gsi
- GRIDFTP-221: additional changes towards maintaining backwards compatibility.
- GRIDFTP-221: backwards compatibility fix and future binary compatibility stability additions
- GRIDFTP-221: improvements to backwards compatibility
- GRIDFTP-222: fix threaded issues with streaming dir info for mlsd and mlsc
- GRIDFTP-224: Add option to set custom client starting/home directory
- GRIDFTP-224: make -home-dir option work correctly with -restrict-paths, clarify
- GRIDFTP-226: Fix recursed dir listings in split/striped server mode, when recursion wasn't requested.
- GRIDFTP-227: Add server option to enable threaded operation and set number of threads.
- GRIDFTP-228: Don't require delegated cred on initial log in.
- GRIDFTP-230: downgrade gfork not loaded message
- GT-152: GRIDFTP acts as wrong user when gridmap user doesnt exist
- GT-152: fix issues with CHMOD when mode_t is 2 bytes
- GT-164: add a hybrid mode to stripe configuration which only creates backend connections if client requests stripes.
- GT-167: ensure log files are created with acceptable default permissions
- GT-173: Allow a frontend->backend connection via admin defined credentials
- GT-3: gridftp server incorrectly handles relative path configuration values
- RIC-226: Some dependencies are missing in GPT metadata
- RIC-229: Clean up GPT metadata
- RIC-258: Can't rely on MKDIR_P

* Thu May 17 2012 Joseph Bester <bester@mcs.anl.gov> - 6.11-1
- GT-195: GridFTP acts as wrong user when user doesn't exist

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
