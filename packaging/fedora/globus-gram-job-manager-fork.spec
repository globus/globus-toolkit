%{!?perl_vendorlib: %global perl_vendorlib %(eval "`perl -V:installvendorlib`"; echo $installvendorlib)}

Name:		globus-gram-job-manager-fork
%global _name %(tr - _ <<< %{name})
Version:	2.4
Release:	1%{?dist}
Summary:	Globus Toolkit - Fork Job Manager

Group:		Applications/Internet
License:	ASL 2.0
URL:		http://www.globus.org/
Source:	http://www.globus.org/ftppub/gt6/packages/globus_gram_job_manager_fork-2.4.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires:	globus-gram-job-manager-scripts >= 4
Requires:	globus-gass-cache-program >= 5
Requires:	globus-common-progs >= 14
%if 0%{?suse_version} > 0
    %if %{suse_version} < 1140
Requires:     perl = %{perl_version}
    %else
%{perl_requires}
    %endif
%else
Requires:	perl(:MODULE_COMPAT_%(eval "`perl -V:version`"; echo $version))
%endif
Requires:       %{name}-setup
Obsoletes:      globus-gram-job-manager-setup-fork < 4.3
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
Summary:	Globus Toolkit - Fork Job Manager Setup Files
Group:		Applications/Internet
%if %{?fedora}%{!?fedora:0} >= 10 || %{?rhel}%{!?rhel:0} >= 6
BuildArch:      noarch
%endif
Provides:       %{name}-setup
Requires:	%{name} = %{version}-%{release}
Requires(post): globus-gram-job-manager-scripts >= 4
Requires(preun): globus-gram-job-manager-scripts >= 4
Conflicts:      %{name}-setup-seg

%package setup-seg
Summary:	Globus Toolkit - Fork Job Manager Setup Files
Group:		Applications/Internet
Provides:       %{name}-setup
Requires:	%{name} = %{version}-%{release}
Requires:       globus-scheduler-event-generator-progs >= 4
Requires(post): globus-gram-job-manager-scripts >= 4
Requires(preun): globus-gram-job-manager-scripts >= 4
Conflicts:      %{name}-setup-poll

%description
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
Fork Job Manager 

%description setup-poll
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
Fork Job Manager Setup using polling to monitor job state

%description setup-seg
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
Fork Job Manager Setup using SEG to monitor job state

%prep
%setup -q -n %{_name}-%{version}

%build
%if %{?fedora}%{!?fedora:0} >= 19 || %{?rhel}%{!?rhel:0} >= 7
# Remove files that should be replaced during bootstrap
rm -rf autom4te.cache

autoreconf -if
%endif

export MPIEXEC=no
export MPIRUN=no

%configure \
           --disable-static \
           --docdir=%{_docdir}/%{name}-%{version} \
           --includedir=%{_includedir}/globus \
           --libexecdir=%{_datadir}/globus \
           --with-globus-state-dir=%{_localstatedir}/lib/globus \
           --with-perlmoduledir=%{perl_vendorlib}

make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

# Remove jobmanager-fork from install dir so that it can be
# added/removed by post scripts
rm $RPM_BUILD_ROOT/etc/grid-services/jobmanager-fork

# Remove libtool archives (.la files)
find $RPM_BUILD_ROOT%{_libdir} -name 'lib*.la' -exec rm -v '{}' \;

%clean
rm -rf $RPM_BUILD_ROOT

%post setup-poll
if [ $1 -eq 1 ]; then
    globus-gatekeeper-admin -e jobmanager-fork-poll -n jobmanager-fork
    if [ ! -f /etc/grid-services/jobmanager ]; then
        globus-gatekeeper-admin -e jobmanager-fork-poll -n jobmanager
    fi
fi

%preun setup-poll
if [ $1 -eq 0 ]; then
    globus-gatekeeper-admin -d jobmanager-fork-poll > /dev/null 2>&1 || :
fi

%postun setup-poll
if [ $1 -eq 1 ]; then
    globus-gatekeeper-admin -e jobmanager-fork-poll -n jobmanager-fork
    if [ ! -f /etc/grid-services/jobmanager ]; then
        globus-gatekeeper-admin -e jobmanager-fork-poll -n jobmanager
    fi
elif [ $1 -eq 0 -a ! -f /etc/grid-services/jobmanager ]; then
    globus-gatekeeper-admin -E > /dev/null 2>&1 || :
fi

%post setup-seg
/sbin/ldconfig
if [ $1 -eq 1 ]; then
    globus-gatekeeper-admin -e jobmanager-fork-seg -n jobmanager-fork
    globus-scheduler-event-generator-admin -e fork
    /sbin/service globus-scheduler-event-generator condrestart fork
    if [ ! -f /etc/grid-services/jobmanager ]; then
        globus-gatekeeper-admin -e jobmanager-fork-seg -n jobmanager
    fi
    if [ ! -f /var/lib/globus/globus-fork.log ]; then
        mkdir -p /var/lib/globus
        touch /var/lib/globus/globus-fork.log
        chmod 0622 /var/lib/globus/globus-fork.log
    fi
fi

%preun setup-seg
if [ $1 -eq 0 ]; then
    globus-gatekeeper-admin -d jobmanager-fork-seg > /dev/null 2>&1 || :
    globus-scheduler-event-generator-admin -d fork > /dev/null 2>&1 || :
    service globus-scheduler-event-generator stop fork > /dev/null 2>&1 || :
fi

%postun setup-seg
/sbin/ldconfig
if [ $1 -eq 1 ]; then
    globus-gatekeeper-admin -e jobmanager-fork-seg > /dev/null 2>&1 || :
    globus-scheduler-event-generator-admin -e fork > /dev/null 2>&1 || :
    service globus-scheduler-event-generator condrestart fork > /dev/null 2>&1 || :
    if [ ! -f /etc/grid-services/jobmanager ]; then
        globus-gatekeeper-admin -e jobmanager-fork-seg -n jobmanager
    fi
fi

%files
%defattr(-,root,root,-)
%dir %{_docdir}/%{name}-%{version}
%{_docdir}/%{name}-%{version}/GLOBUS_LICENSE
%config(noreplace) %{_sysconfdir}/globus/globus-fork.conf
%{_sysconfdir}/globus/scheduler-event-generator/available/fork
%{perl_vendorlib}/Globus/GRAM/JobManager/fork.pm


%files setup-poll
%defattr(-,root,root,-)
%config(noreplace) %{_sysconfdir}/grid-services/available/jobmanager-fork-poll

%files setup-seg
%defattr(-,root,root,-)
%config(noreplace) %{_sysconfdir}/grid-services/available/jobmanager-fork-seg
%{_libdir}/libglobus_seg_fork.so*
%{_sbindir}/globus-fork-starter
%{_mandir}/man8/globus-fork-starter.8.gz

%changelog
* Fri Aug 22 2014 Globus Toolkit <support@globus.org> - 2.4-1
- Merge fixes from ellert-globus_6_branch

* Wed Aug 20 2014 Globus Toolkit <support@globus.org> - 2.3-2
- Fix Source path

* Mon Jun 09 2014 Globus Toolkit <support@globus.org> - 2.3-1
- Merge changes from Mattias Ellert

* Fri Apr 18 2014 Globus Toolkit <support@globus.org> - 2.2-1
- Version bump for consistency

* Thu Feb 27 2014 Globus Toolkit <support@globus.org> - 2.1-1
- Packaging fixes, Warning Cleanup

* Wed Jan 22 2014 Globus Toolkit <support@globus.org> - 2.0-1
- Repackage for GT6 without GPT

* Wed Jun 26 2013 Globus Toolkit <support@globus.org> - 1.5-9
- GT-424: New Fedora Packaging Guideline - no %_isa in BuildRequires

* Fri Mar 08 2013 Globus Toolkit <support@globus.org> - 1.5-8
- Fixes to dependencies

* Wed Feb 20 2013 Globus Toolkit <support@globus.org> - 1.5-7
- Workaround missing F18 doxygen/latex dependency

* Mon Nov 26 2012 Globus Toolkit <support@globus.org> - 1.5-6
- 5.2.3

* Mon Jul 16 2012 Joseph Bester <bester@mcs.anl.gov> - 1.5-5
- GT 5.2.2 final

* Fri Jun 29 2012 Joseph Bester <bester@mcs.anl.gov> - 1.5-4
- GT 5.2.2 Release

* Wed May 09 2012 Joseph Bester <bester@mcs.anl.gov> - 1.5-3
- RHEL 4 patches

* Fri May 04 2012 Joseph Bester <bester@mcs.anl.gov> - 1.5-2
- SLES 11 patches

* Thu Apr 12 2012 Joseph Bester <bester@mcs.anl.gov> - 1.5-1
- GRAM-343: lrm packages grid-service files aren't in CLEANFILES

* Wed Apr 04 2012 Joseph Bester <bester@mcs.anl.gov> - 1.4-1
- GRAM-333: SEG config in installer has variables that aren't resolved at runtime

* Wed Mar 14 2012 Joseph Bester <bester@mcs.anl.gov> - 1.3-1
- GRAM-318: Periodic lockup of SEG

* Tue Feb 14 2012 Joseph Bester <bester@mcs.anl.gov> - 1.2-1
- GRAM-297: job manager service definitions contain unresolved variables
- GRAM-310: sge configure script error
- RIC-229: Clean up GPT metadata

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 1.0-8
- Update for 5.2.0 release

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 1.0-7
- Last sync prior to 5.2.0

* Fri Oct 21 2011 Joseph Bester <bester@mcs.anl.gov> - 1.0-6
- Apply OSG's globus-gram-job-manager-fork.spec patch to fix %post* scripts
- Add explicit dependencies on >= 5.2 libraries

* Thu Sep 22 2011 Joseph Bester <bester@mcs.anl.gov> - 1.0-5
- Change %post check for -eq 1

* Wed Sep 14 2011 Joseph Bester <bester@mcs.anl.gov> - 1.0-3
- Create globus-fork.log at postinstall time if it's not present

* Thu Sep 01 2011 Joseph Bester <bester@mcs.anl.gov> - 1.0-2
- Update for 5.1.2 release

