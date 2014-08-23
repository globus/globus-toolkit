%{!?perl_vendorlib: %global perl_vendorlib %(eval "`perl -V:installvendorlib`"; echo $installvendorlib)}

Name:		globus-gram-job-manager-sge
%global _name %(tr - _ <<< %{name})
Version:	2.4
Release:	1%{?dist}
Summary:	Globus Toolkit - SGE Job Manager

Group:		Applications/Internet
License:	LGPL 2.1 and Apache License 2.0
URL:		http://www.globus.org/
Source:	http://www.globus.org/ftppub/gt6/packages/globus_gram_job_manager_sge-2.4.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Obsoletes:      globus-gram-job-manager-setup-sge < 4.5

Requires:       globus-gram-job-manager-scripts >= 4
Requires:	globus-gass-cache-program >= 4
Requires:	globus-common-progs >= 14
Requires:       gridengine
%if 0%{?suse_version} > 0
    %if %{suse_version} < 1140
Requires:     perl = %{perl_version}
    %else
%{perl_requires}
    %endif
%else
Requires:	perl(:MODULE_COMPAT_%(eval "`perl -V:version`"; echo $version))
%endif
BuildRequires:	globus-common-devel >= 14
BuildRequires:	globus-xio-devel >= 3
BuildRequires:	globus-scheduler-event-generator-devel >= 4
BuildRequires:	globus-gram-protocol-devel >= 11
BuildRequires:	doxygen
BuildRequires:	graphviz
%if "%{?rhel}" == "5"
BuildRequires:	graphviz-gd
%endif
%if %{?fedora}%{!?fedora:0} >= 19 || %{?rhel}%{!?rhel:0} >= 7
BuildRequires:  automake >= 1.11
BuildRequires:  autoconf >= 2.60
BuildRequires:  libtool >= 2.2
%endif
BuildRequires:  pkgconfig

%package setup-poll
Summary:        Globus Toolkit - SGE Job Manager Setup Files
Group:		Applications/Internet
%if %{?fedora}%{!?fedora:0} >= 10 || %{?rhel}%{!?rhel:0} >= 6
BuildArch:      noarch
%endif
Provides:       %{name}-setup
Provides:       globus-gram-job-manager-setup
Requires:       gridengine
Requires:	%{name} = %{version}-%{release}
Requires(post): globus-gram-job-manager-scripts >= 4
Requires(preun): globus-gram-job-manager-scripts >= 4
Conflicts:      %{name}-setup-seg

%package setup-seg
Summary:	Globus Toolkit - SGE Job Manager Setup Files
Group:		Applications/Internet
Provides:       %{name}-setup
Provides:       globus-gram-job-manager-setup
Requires:	%{name} = %{version}-%{release}
Requires:       globus-scheduler-event-generator-progs >= 4
Requires:       gridengine
Requires(post): globus-gram-job-manager-scripts >= 4
Requires(preun): globus-gram-job-manager-scripts >= 4
Conflicts:      %{name}-setup-poll

%description
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
SGE Job Manager 

%description setup-poll
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
SGE Job Manager Setup using polling to monitor job state

%description setup-seg
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
SGE Job Manager Setup using SEG to monitor job state

%prep
%setup -q -n %{_name}-%{version}

%build
%if %{?fedora}%{!?fedora:0} >= 19 || %{?rhel}%{!?rhel:0} >= 7
# Remove files that should be replaced during bootstrap
rm -rf autom4te.cache

autoreconf -if
%endif

# Explicitly set SGE-related command paths
export QSUB=/usr/bin/qsub-ge
export QSTAT=/usr/bin/qstat-ge
export QDEL=/usr/bin/qdel-ge

export QCONF=/usr/bin/qconf
export MPIRUN=no
export SUN_MPRUN=no

%configure \
           --disable-static \
           --docdir=%{_docdir}/%{name}-%{version} \
           --includedir=%{_includedir}/globus \
           --libexecdir=%{_datadir}/globus \
           --with-perlmoduledir=%{perl_vendorlib} \
           --with-globus-state-dir=%{_localstatedir}/lib/globus \
           --with-sge-config=/etc/sysconfig/gridengine \
           --with-sge-root=undefined \
           --with-sge-cell=undefined \
           --without-queue-validation \
           --without-pe-validation

make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
# Remove jobmanager-sge from install dir so that it can be
# added/removed by post scripts
rm $RPM_BUILD_ROOT/etc/grid-services/jobmanager-sge

# Remove libtool archives (.la files)
find $RPM_BUILD_ROOT%{_libdir} -name 'lib*.la' -exec rm -v '{}' \;

%check
make %{?_smp_mflags} check

%clean
rm -rf $RPM_BUILD_ROOT

%post setup-poll
if [ $1 -eq 1 ]; then
    globus-gatekeeper-admin -e jobmanager-sge-poll -n jobmanager-sge > /dev/null 2>&1 || :
    if [ ! -f /etc/grid-services/jobmanager ]; then
        globus-gatekeeper-admin -e jobmanager-sge-poll -n jobmanager
    fi
fi

%preun setup-poll
if [ $1 -eq 0 ]; then
    globus-gatekeeper-admin -d jobmanager-sge-poll > /dev/null 2>&1 || :
fi

%postun setup-poll
if [ $1 -eq 1 ]; then
    globus-gatekeeper-admin -e jobmanager-sge-poll -n jobmanager-sge > /dev/null 2>&1 || :
elif [ $1 -eq 0 -a ! -f /etc/grid-services/jobmanager ]; then
    globus-gatekeeper-admin -E > /dev/null 2>&1 || :
fi

%post setup-seg
ldconfig
if [ $1 -eq 1 ]; then
    globus-gatekeeper-admin -e jobmanager-sge-seg -n jobmanager-sge > /dev/null 2>&1 || :
    globus-scheduler-event-generator-admin -e sge > /dev/null 2>&1 || :
    service globus-scheduler-event-generator condrestart sge
fi

%preun setup-seg
if [ $1 -eq 0 ]; then
    globus-gatekeeper-admin -d jobmanager-sge-seg > /dev/null 2>&1 || :
    globus-scheduler-event-generator-admin -d sge > /dev/null 2>&1 || :
    service globus-scheduler-event-generator stop sge > /dev/null 2>&1 || :
fi

%postun setup-seg
ldconfig
if [ $1 -eq 1 ]; then
    globus-gatekeeper-admin -e jobmanager-sge-seg > /dev/null 2>&1 || :
    globus-scheduler-event-generator-admin -e sge > /dev/null 2>&1 || :
    service globus-scheduler-event-generator condrestart sge > /dev/null 2>&1 || :
elif [ $1 -eq 0 -a ! -f /etc/grid-services/jobmanager ]; then
    globus-gatekeeper-admin -E > /dev/null 2>&1 || :
fi

%files
%defattr(-,root,root,-)
%config(noreplace) %{_sysconfdir}/globus/globus-sge.conf
%{perl_vendorlib}/Globus/GRAM/JobManager/sge.pm
%{_sysconfdir}/globus/scheduler-event-generator/available/sge
%{_libdir}/libglobus*
%dir %{_docdir}/%{name}-%{version}
%{_docdir}/%{name}-%{version}/*
%{_datadir}/globus/globus_gram_job_manager/sge.rvf

%files setup-poll
%defattr(-,root,root,-)
%config(noreplace) %{_sysconfdir}/grid-services/available/jobmanager-sge-poll

%files setup-seg
%defattr(-,root,root,-)
%config(noreplace) %{_sysconfdir}/grid-services/available/jobmanager-sge-seg

%changelog
* Fri Aug 22 2014 Globus Toolkit <support@globus.org> - 2.4-1
- Merge fixes from ellert-globus_6_branch

* Wed Aug 20 2014 Globus Toolkit <support@globus.org> - 2.3-2
- Fix Source path

* Mon Jun 09 2014 Globus Toolkit <support@globus.org> - 2.3-1
- Merge changes from Mattias Ellert

* Fri Apr 18 2014 Globus Toolkit <support@globus.org> - 2.2-1
- Version bump for consistency

* Sat Feb 15 2014 Globus Toolkit <support@globus.org> - 2.1-1
- Packaging fixes

* Wed Jan 22 2014 Globus Toolkit <support@globus.org> - 2.0-1
- Repackage for GT6 without GPT

* Wed Jun 26 2013 Globus Toolkit <support@globus.org> - 1.7-2
- GT-424: New Fedora Packaging Guideline - no %_isa in BuildRequires

* Tue May 21 2013 Globus Toolkit <support@globus.org> - 1.7-1
- solves an issue where globus gets confused at midnight about running jobs

* Fri Mar 08 2013 Globus Toolkit <support@globus.org> - 1.6-3
- Dependency updates

* Wed Feb 20 2013 Globus Toolkit <support@globus.org> - 1.6-2
- Workaround missing F18 doxygen/latex dependency

* Wed Feb 13 2013 Globus Toolkit <support@globus.org> - 1.6-1
- GT-359: SGE SEG hangs when log_path points to directory

* Mon Nov 26 2012 Globus Toolkit <support@globus.org> - 1.5-6
- 5.2.3

* Mon Jul 16 2012 Joseph Bester <bester@mcs.anl.gov> - 1.5-5
- GT 5.2.2 final

* Fri Jun 29 2012 Joseph Bester <bester@mcs.anl.gov> - 1.5-4
- GT 5.2.2 Release

* Thu May 24 2012 Joseph Bester <bester@mcs.anl.gov> - 1.5-3
- use qstat-ge and co. on rhel5 as well

* Wed May 09 2012 Joseph Bester <bester@mcs.anl.gov> - 1.5-3
- RHEL 4 patches

* Fri May 04 2012 Joseph Bester <bester@mcs.anl.gov> - 1.5-2
- SLES 11 patches

* Thu Apr 12 2012 Joseph Bester <bester@mcs.anl.gov> - 1.5-1
- GRAM-343: lrm packages grid-service files aren't in CLEANFILES

* Wed Mar 14 2012 Joseph Bester <bester@mcs.anl.gov> - 1.4-1
- GRAM-318: Periodic lockup of SEG

* Tue Feb 14 2012 Joseph Bester <bester@mcs.anl.gov> - 1.3-1
- GRAM-297: job manager service definitions contain unresolved variables
- GRAM-310: sge configure script error
- RIC-229: Clean up GPT metadata

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 1.0-7
- Update for 5.2.0 release

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 1.0-6
- Last sync prior to 5.2.0

* Fri Oct 21 2011 Joseph Bester <bester@mcs.anl.gov> - 1.0-5
- Fix %post* scripts to check for -eq 1
- Add explicit dependencies on >= 5.2 libraries

* Thu Sep 22 2011 Joseph Bester <bester@mcs.anl.gov> - 1.0-4

* Mon Sep 12 2011 Joseph Bester <bester@mcs.anl.gov> - 1.0-3
- Update path to qsub, etc for RHEL5 / EPEL

* Thu Sep 01 2011 Joseph Bester <bester@mcs.anl.gov> - 1.0-2
- Update for 5.1.2 release

