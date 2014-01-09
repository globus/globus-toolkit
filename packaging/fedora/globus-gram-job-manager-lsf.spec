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

%{!?perl_vendorlib: %global perl_vendorlib %(eval "`perl -V:installvendorlib`"; echo $installvendorlib)}

Name:		globus-gram-job-manager-lsf
%global _name %(tr - _ <<< %{name})
Version:	1.3
Release:	1%{?dist}
Summary:	Globus Toolkit - PBS Job Manager

Group:		Applications/Internet
License:	ASL 2.0
URL:		http://www.globus.org/
Source:		http://www.globus.org/ftppub/gt5/5.2/testing/packages/src/%{_name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Obsoletes:      globus-gram-job-manager-setup-lsf < 4.5

Requires:       globus-gram-job-manager-scripts >= 4
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
BuildRequires:	grid-packaging-tools >= 3.4
BuildRequires:	globus-core >= 8
BuildRequires:	globus-common-devel >= 14
BuildRequires:	globus-xio-devel >= 3
BuildRequires:	globus-scheduler-event-generator-devel >= 4
BuildRequires:	globus-gram-protocol-devel >= 11

%package setup-poll
Summary:        Globus Toolkit - PBS Job Manager Setup Files
Group:		Applications/Internet
%if %{?fedora}%{!?fedora:0} >= 10 || %{?rhel}%{!?rhel:0} >= 6
BuildArch:      noarch
%endif
Provides:       %{name}-setup
Provides:       globus-gram-job-manager-setup
Requires:	%{name} = %{version}-%{release}
requires(post): globus-gram-job-manager-scripts >= 3.4
requires(preun): globus-gram-job-manager-scripts >= 3.4
Conflicts:      %{name}-setup-seg

%package setup-seg
Summary:	Globus Toolkit - PBS Job Manager Setup Files
Group:		Applications/Internet
Provides:       %{name}-setup
Provides:       globus-gram-job-manager-setup
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
PBS Job Manager 

%description setup-poll
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
PBS Job Manager Setup using polling to monitor job state

%description setup-seg
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
PBS Job Manager Setup using SEG to monitor job state

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

export MPIEXEC=no
export MPIRUN=no
%configure --with-flavor=%{flavor} \
           --%{docdiroption}=%{_docdir}/%{name}-%{version} \
           --with-globus-state-dir=%{_localstatedir}/lib/globus \
           --disable-static

make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
# Remove jobmanager-lsf from install dir so that it can be
# added/removed by post scripts
rm $RPM_BUILD_ROOT/etc/grid-services/jobmanager-lsf

GLOBUSPACKAGEDIR=$RPM_BUILD_ROOT%{_datadir}/globus/packages

# Remove libtool archives (.la files)
find $RPM_BUILD_ROOT%{_libdir} -name 'lib*.la' -exec rm -v '{}' \;
sed '/lib.*\.la$/d' -i $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_dev.filelist


# Generate package filelists
# Main package: lsf.pm and globus-lsf.config
cat $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_rtl.filelist \
    $GLOBUSPACKAGEDIR/%{_name}/noflavor_data.filelist \
  | sed s!^!%{_prefix}! \
  | sed s!^%{_prefix}/etc!/etc! \
  | grep -E 'lsf\.pm|lsf\.rvf|globus-lsf\.conf|pkg_data_|.filelist' > package.filelist

# setup-poll package: /etc/grid-services/available/job-manager-lsf-poll
cat $GLOBUSPACKAGEDIR/%{_name}/noflavor_data.filelist \
  | sed s!^!%{_prefix}! \
  | sed s!^%{_prefix}/etc!/etc! \
  | grep jobmanager-lsf-poll > package-setup-poll.filelist

# setup-seg package: /etc/grid-services/available/job-manager-lsf-seg
# plus seg module
cat $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_pgm.filelist \
    $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_dev.filelist \
    $GLOBUSPACKAGEDIR/%{_name}/%{flavor}_rtl.filelist \
    $GLOBUSPACKAGEDIR/%{_name}/noflavor_data.filelist \
  | sed s!^!%{_prefix}! \
  | sed s!^%{_prefix}/etc!/etc! \
  | grep -Ev 'jobmanager-lsf-poll|globus-lsf.conf|lsf.pm|pkg_data_%{flavor}_rtl|pkg_data_noflavor_data|%{flavor}_rtl.filelist|noflavor_data.filelist' > package-setup-seg.filelist

cat $GLOBUSPACKAGEDIR/%{_name}/noflavor_doc.filelist \
  | sed 's!^!%doc %{_prefix}!' >> package.filelist

%clean
rm -rf $RPM_BUILD_ROOT

%post setup-poll
if [ $1 -eq 1 ]; then
    globus-gatekeeper-admin -e jobmanager-lsf-poll -n jobmanager-lsf > /dev/null 2>&1 || :
    if [ ! -f /etc/grid-services/jobmanager ]; then
        globus-gatekeeper-admin -e jobmanager-lsf-poll -n jobmanager
    fi
fi

%preun setup-poll
if [ $1 -eq 0 ]; then
    globus-gatekeeper-admin -d jobmanager-lsf-poll > /dev/null 2>&1 || :
fi

%postun setup-poll
if [ $1 -eq 1 ]; then
    globus-gatekeeper-admin -e jobmanager-lsf-poll -n jobmanager-lsf > /dev/null 2>&1 || :
elif [ $1 -eq 0 -a ! -f /etc/grid-services/jobmanager ]; then
    globus-gatekeeper-admin -E > /dev/null 2>&1 || :
fi

%post setup-seg
ldconfig
if [ $1 -eq 1 ]; then
    globus-gatekeeper-admin -e jobmanager-lsf-seg -n jobmanager-lsf > /dev/null 2>&1 || :
    globus-scheduler-event-generator-admin -e lsf > /dev/null 2>&1 || :
    service globus-scheduler-event-generator condrestart lsf
fi

%preun setup-seg
if [ $1 -eq 0 ]; then
    globus-gatekeeper-admin -d jobmanager-lsf-seg > /dev/null 2>&1 || :
    globus-scheduler-event-generator-admin -d lsf > /dev/null 2>&1 || :
    service globus-scheduler-event-generator stop lsf > /dev/null 2>&1 || :
fi

%postun setup-seg
ldconfig
if [ $1 -eq 1 ]; then
    globus-gatekeeper-admin -e jobmanager-lsf-seg > /dev/null 2>&1 || :
    globus-scheduler-event-generator-admin -e lsf > /dev/null 2>&1 || :
    service globus-scheduler-event-generator condrestart lsf > /dev/null 2>&1 || :
elif [ $1 -eq 0 -a ! -f /etc/grid-services/jobmanager ]; then
    globus-gatekeeper-admin -E > /dev/null 2>&1 || :
fi

%files -f package.filelist
%defattr(-,root,root,-)
%dir %{_datadir}/globus/packages/%{_name}
%dir %{_docdir}/%{name}-%{version}
%config(noreplace) %{_sysconfdir}/globus/globus-lsf.conf

%files setup-poll -f package-setup-poll.filelist
%defattr(-,root,root,-)
%config(noreplace) %{_sysconfdir}/grid-services/available/jobmanager-lsf-poll

%files setup-seg -f package-setup-seg.filelist
%defattr(-,root,root,-)
%config(noreplace) %{_sysconfdir}/grid-services/available/jobmanager-lsf-seg

%changelog
* Thu Jan 09 2014 Globus Toolkit <support@globus.org> - 1.3-1
- GT-493: Missing configure option in GRAM LSF

* Thu Oct 10 2013 Globus Toolkit <support@globus.org> - 1.2-1
- GT-344: Cut and past error in gpt metadata for GRAM LSF module

* Wed Jun 26 2013 Globus Toolkit <support@globus.org> - 1.1-2
- GT-424: New Fedora Packaging Guideline - no %_isa in BuildRequires

* Mon Nov 26 2012 Globus Toolkit <support@globus.org> - 1.1-1
- 5.2.3

* Fri Aug 17 2012 Joseph Bester <bester@mcs.anl.gov> - 1.0-1
- Initial packaging
