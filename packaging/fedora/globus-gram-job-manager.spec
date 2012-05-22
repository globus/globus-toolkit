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

Name:		globus-gram-job-manager
%global _name %(tr - _ <<< %{name})
Version:	13.41
Release:	1%{?dist}
Summary:	Globus Toolkit - GRAM Jobmanager

Group:		Applications/Internet
License:	ASL 2.0
URL:		http://www.globus.org/
Source:		http://www.globus.org/ftppub/gt5/5.2/5.2.1/packages/src/%{_name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires:	globus-common >= 14
Requires:	globus-scheduler-event-generator%{?_isa} >= 4
Requires:	globus-xio-popen-driver%{?_isa} >= 2
Requires:	globus-xio%{?_isa} >= 3
Requires:	globus-gss-assist%{?_isa} >= 8
Requires:	libxml2%{?_isa}
Requires:	globus-gsi-sysconfig%{?_isa} >= 5
Requires:	globus-callout%{?_isa} >= 2
Requires:	globus-gram-job-manager-callout-error%{?_isa} >= 2
Requires:	globus-gram-protocol >= 11
Requires:	globus-usage%{?_isa} >= 3
Requires:	globus-rsl%{?_isa} >= 9
Requires:	globus-gass-cache%{?_isa} >= 8
Requires:	globus-gass-transfer%{?_isa} >= 7
Requires:	globus-gram-job-manager-scripts
Requires:	globus-gass-copy-progs >= 8
Requires:	globus-proxy-utils >= 5
Requires:	globus-gass-cache-program >= 2
Requires:	globus-gatekeeper >= 9
Requires:	psmisc

BuildRequires:	grid-packaging-tools >= 3.4
BuildRequires:	globus-scheduler-event-generator-devel%{?_isa} >= 4
BuildRequires:	globus-xio-popen-driver-devel%{?_isa} >= 2
BuildRequires:	globus-xio-devel%{?_isa} >= 3
BuildRequires:	globus-gss-assist-devel%{?_isa} >= 8
BuildRequires:	globus-core%{?_isa} >= 8
BuildRequires:	globus-gsi-sysconfig-devel%{?_isa} >= 5
BuildRequires:	globus-callout-devel%{?_isa} >= 2
BuildRequires:	globus-gram-job-manager-callout-error-devel%{?_isa} >= 2
BuildRequires:	globus-gram-protocol-devel%{?_isa} >= 11
BuildRequires:	globus-common-devel%{?_isa} >= 14
BuildRequires:	globus-usage-devel%{?_isa} >= 3
BuildRequires:	globus-rsl-devel%{?_isa} >= 9
BuildRequires:	globus-gass-cache-devel%{?_isa} >= 8
BuildRequires:	libxml2-devel%{?_isa} >= 2.6.11
BuildRequires:	globus-gass-transfer-devel%{?_isa} >= 7
BuildRequires:	globus-gram-protocol-doc >= 11
BuildRequires:	globus-common-doc >= 14
BuildRequires:	doxygen
BuildRequires:	graphviz
%if "%{?rhel}" == "5"
BuildRequires:	graphviz-gd
%endif
BuildRequires:	ghostscript
%if %{?fedora}%{!?fedora:0} >= 9 || %{?rhel}%{!?rhel:0} >= 5
BuildRequires:	tex(latex)
%else
%if 0%{?suse_version} > 0
BuildRequires:  texlive-latex
%else
BuildRequires:	tetex-latex
%endif
%endif

%package doc
Summary:	Globus Toolkit - GRAM Jobmanager Documentation Files
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
GRAM Jobmanager
GRAM Job Manager Setup

%description doc
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-doc package contains:
GRAM Jobmanager Documentation Files

%prep
%setup -q -n %{_name}-%{version}

%build
# Remove files that should be replaced during bootstrap
rm -f doxygen/Doxyfile*
rm -f doxygen/Makefile.am
rm -f pkgdata/Makefile.am
rm -f globus_automake*
rm -rf autom4te.cache

aclocal_includes="-I ." %{_datadir}/globus/globus-bootstrap.sh

%configure --with-flavor=%{flavor} --enable-doxygen \
           --%{docdiroption}=%{_docdir}/%{name}-%{version} \
           --disable-static

make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

GLOBUSPACKAGEDIR=$RPM_BUILD_ROOT%{_datadir}/globus/packages

# Move client and server man pages to main package
grep '.[18]$' $GLOBUSPACKAGEDIR/%{_name}/noflavor_doc.filelist \
  >> $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_pgm.filelist
sed '/.[18]$/d' -i $GLOBUSPACKAGEDIR/%{_name}/noflavor_doc.filelist

# Move documentation to default RPM location

# Fix doxygen glitches
for f in man3/globus_gram_job_manager_configuration.3 \
	 man3/globus_gram_job_manager_job_execution_environment.3 \
	 man3/globus_gram_job_manager_rsl_validation_file.3 \
	 man5/rsl.5 ; do
  sed 's/P\.RS/P\n.RS/' -i $RPM_BUILD_ROOT%{_mandir}/$f
done

# Remove unwanted documentation (needed for RHEL4)
rm -f $RPM_BUILD_ROOT%{_mandir}/man3/*_%{_name}-%{version}_*.3
sed -e '/_%{_name}-%{version}_.*\.3/d' \
  -i $GLOBUSPACKAGEDIR/%{_name}/noflavor_doc.filelist

# Generate package filelists
cat $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_pgm.filelist \
    $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_dev.filelist \
    $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_rtl.filelist \
    $GLOBUSPACKAGEDIR/%{_name}/noflavor_data.filelist \
  | sed -e s!^!%{_prefix}! -e 's!.*/man/.*!%doc &*!' \
  | sed -e s!^%{_prefix}/etc!/etc!  > package.filelist

cat $GLOBUSPACKAGEDIR/%{_name}/noflavor_doc.filelist \
  | sed -e 's!/man/.*!&*!' -e 's!^!%doc %{_prefix}!' > package-doc.filelist

%clean
rm -rf $RPM_BUILD_ROOT

%files -f package.filelist
%defattr(-,root,root,-)
%dir %{_datadir}/globus/packages/%{_name}
%dir %{_docdir}/%{name}-%{version}
%dir %{_localstatedir}/lib/globus/gram_job_state
%dir %{_localstatedir}/log/globus
%config(noreplace) %{_sysconfdir}/globus/globus-gram-job-manager.conf
%config(noreplace) %{_sysconfdir}/logrotate.d/globus-job-manager

%files doc -f package-doc.filelist
%defattr(-,root,root,-)
%dir %{_docdir}/%{name}-%{version}/html

%changelog
* Tue May 22 2012 Joseph Bester <bester@mcs.anl.gov> - 13.41-1
- GT-199: GRAM audit checks result username incorrectly
- GT-192: Segfault in globus-gram-streamer

* Fri May 18 2012 Joseph Bester <bester@mcs.anl.gov> - 13.40-1
- GT-149: Memory leaks in globus-job-manager
- GT-186: GRAM job manager leaks condor log path
- GT-187: GRAM job manager leaks during stdio update
- GT-189: GRAM job manager regular expression storage grows
- GT-190: GRAM job manager leaks callback contact

* Fri May 11 2012 Joseph Bester <bester@mcs.anl.gov> - 13.38-1
- GT-185: globus-personal-gatekeeper creates too-long paths on MacOS

* Fri May 11 2012 Joseph Bester <bester@mcs.anl.gov> - 13.37-1
- GT-65: GRAM records datagram socket failure, but doesn't record socket name

* Wed May 09 2012 Joseph Bester <bester@mcs.anl.gov> - 13.36-1
- GRAM-288: Kill off perl processes when idle

* Wed May 09 2012 Joseph Bester <bester@mcs.anl.gov> - 13.35-3
- RHEL 4 patches

* Fri May 04 2012 Joseph Bester <bester@mcs.anl.gov> - 13.35-2
- SLES 11 patches

* Thu May 03 2012 Joseph Bester <bester@mcs.anl.gov> - 13.35-1
- GRAM-329: Condor fake-SEG loses track of job
- GRAM-345: Job manager deletes job dir sometimes

* Wed Apr 11 2012 Joseph Bester <bester@mcs.anl.gov> - 13.33-1
- GRAM-334: job manager doesn't work if unix socket path is too long
- GRAM-338: GRAM job manager mishandles peer name when proxying messages through the gatekeeper
- GRAM-340: job manager crashes during stdio size query
- GRAM-342: intra-job manager protocol doesn't keep do signal-safe reads

* Mon Apr 02 2012 Joseph Bester <bester@mcs.anl.gov> - 13.31-1
- GRAM-329: Condor fake-SEG loses track of job

* Thu Mar 29 2012 Joseph Bester <bester@mcs.anl.gov> - 13.30-1
- GRAM-327: list default values for RSL attributes

* Wed Mar 28 2012 Joseph Bester <jbester@mcs.anl.gov> - 13.29-1
- GRAM-330: Buffer overflow in globus_gram_job_manager_seg_parse_condor_id

* Tue Mar 27 2012 Joseph Bester <bester@mcs.anl.gov> - 13.28-1
- GRAM-321: globus-job-manager emits warning about all jobs on restart
- GRAM-323: RVF parser leaks file descriptors
- GRAM-326: Can't renew job proxy after GLOBUS_GRAM_PROTOCOL_ERROR_COMMIT_TIMED_OUT error
- GRAM-328: job manager waits for two-phase delay when stopping

* Thu Mar 22 2012 Joseph Bester <jbester@mcs.anl.gov> - 13.27-1
- GRAM-325: job manager crashes when reading empty condor log

* Wed Mar 14 2012 Joseph Bester <bester@mcs.anl.gov> - 13.26-1
- GRAM-314: Jobmanager locking protocol doesn't handle deletion of lockfiles

* Wed Mar 14 2012 Joseph Bester <bester@mcs.anl.gov> - 13.25-1
- GRAM-273: Crufty Condor logs can cause major performance hit
- GRAM-306: Job Manager stdio_size query logging crash
- GRAM-315: Job locking doesn't handle ENOENT gracefully
- GRAM-317: job manager fails transferring job between processes if the proxy is larger than the socket buffer

* Thu Mar 1 2012 Joseph Bester <bester@mcs.anl.gov> - 13.22-1
- RIC-239: GSSAPI Token inspection fails when using TLS 1.2

* Tue Feb 14 2012 Joseph Bester <bester@mcs.anl.gov> - 13.21-1
- GRAM-272: Allow site-specific RVF entries
- GRAM-294: GRAM should clean up files better
- GRAM-305: Jobmanager reporting DONE status when stage-out failed
- RIC-226: Some dependencies are missing in GPT metadata

* Thu Dec 22 2011 Joseph Bester <bester@mcs.anl.gov> - 13.19-1
- GRAM-232: Incorrect directory permissions cause an infinite loop
- GRAM-302: Incorrect error when state file write fails
- GRAM-301: GRAM validation file parser doesn't handle empty quoted values
            correctly
- GRAM-300: GRAM job manager doxygen refers to obsolete command-line options
- GRAM-299: Not all job log messages obey loglevel RSL attribute
- GRAM-296: Compile Failure on Solaris

* Thu Dec 08 2011 Joseph Bester <bester@mcs.anl.gov> - 13.14-1
- Fix some cases of multiple submits of a GRAM job to condor

* Wed Dec 07 2011  <bester@centos55.local> - 13.13-1
- GRAM-292: GRAM crashes when parsing partial condor log

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 13.12-2
- Update for 5.2.0 release

* Thu Dec 01 2011 Joseph Bester <bester@mcs.anl.gov> - 13.12-1
- GRAM-289: GRAM jobs resubmitted

* Mon Nov 28 2011 Joseph Bester <bester@mcs.anl.gov> - 13.11-1
- GRAM-286: Set default jobmanager log in native packages
- Add gatekeeper and psmisc dependencies

* Mon Nov 21 2011 Joseph Bester <bester@mcs.anl.gov> - 13.10-1
- GRAM-282: Add hooks to job manager to handle log rotation

* Mon Nov 14 2011 Joseph Bester <bester@mcs.anl.gov> - 13.9-1
- GRAM-271: GRAM Condor polling overpolls

* Mon Nov 07 2011 Joseph Bester <bester@mcs.anl.gov> - 13.8-1
- GRAM-268: GRAM requires gss_export_sec_context to work

* Fri Oct 28 2011 Joseph Bester <bester@mcs.anl.gov> - 13.7-1
- GRAM-266: Do not issue "Error locking file" warning if another jobmanager
  exists

* Wed Oct 26 2011 Joseph Bester <bester@mcs.anl.gov> - 13.6-1
- GRAM-265: GRAM logging.c sets FD_CLOEXEC incorrectly

* Mon Oct 24 2011 Joseph Bester <bester@mcs.anl.gov> - 13.5-2
- set aclocal_includes="-I ." prior to bootsrap

* Thu Oct 20 2011 Joseph Bester <bester@mcs.anl.gov> - 13.5-1
- GRAM-227: Manager double-locked

* Tue Oct 18 2011 Joseph Bester <bester@mcs.anl.gov> - 13.4-1
- GRAM-262: job manager -extra-envvars implementation doesn't match description

* Tue Oct 11 2011 Joseph Bester <bester@mcs.anl.gov> - 13.3-2
- Add explicit dependencies on >= 5.2 libraries

* Tue Oct 04 2011 Joseph Bester <bester@mcs.anl.gov> - 13.3-1
- GRAM-240: globus_xio_open in script code can recurse

* Thu Sep 22 2011  <bester@mcs.anl.gov> - 13.2-1
- GRAM-257: Set default values for GLOBUS_GATEKEEPER_*

* Thu Sep 22 2011 Joseph Bester <bester@mcs.anl.gov> - 13.1-1
- Fix: GRAM-250

* Thu Sep 01 2011 Joseph Bester <bester@mcs.anl.gov> - 13.0-2
- Update for 5.1.2 release

* Sun Jun 05 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 10.70-1
- Update to Globus Toolkit 5.0.4
- Fix doxygen markup

* Mon Apr 25 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 10.67-3
- Add README file

* Tue Apr 19 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 10.67-2
- Updated patch

* Thu Feb 24 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 10.67-1
- Update to Globus Toolkit 5.0.3

* Tue Feb 08 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 10.59-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Sun Jul 18 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 10.59-2
- Move client and server man pages to main package

* Sat Jul 17 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 10.59-1
- Update to Globus Toolkit 5.0.2

* Sat Jun 05 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 10.42-2
- Additional portability fixes

* Wed Apr 14 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 10.42-1
- Update to Globus Toolkit 5.0.1

* Sat Jan 23 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 10.17-1
- Update to Globus Toolkit 5.0.0

* Thu Jul 30 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 8.15-1
- Autogenerated
