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

%{!?perl_vendorlib: %global perl_vendorlib %(eval "`perl -V:installvendorlib`"; echo $installvendorlib)}

Name:		globus-gram-audit
%global _name %(tr - _ <<< %{name})
Version:	3.1
Release:	5%{?dist}
Summary:	Globus Toolkit - GRAM Auditing

Group:		Applications/Internet
License:	ASL 2.0
URL:		http://www.globus.org/
Source:		http://www.globus.org/ftppub/gt5/5.2/5.2.1/packages/src/%{_name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
%if %{?fedora}%{!?fedora:0} >= 10 || %{?rhel}%{!?rhel:0} >= 6
BuildArch:      noarch
%endif
Requires:	globus-common >= 14
Requires:	perl(:MODULE_COMPAT_%(eval "`perl -V:version`"; echo $version))
Requires:	perl(DBI)
Requires:	crontabs
BuildRequires:	grid-packaging-tools >= 3.4
BuildRequires:	globus-core >= 8

%description
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
GRAM Auditing

%prep
%setup -q -n %{_name}-%{version}

%build
# Remove files that should be replaced during bootstrap
rm -f pkgdata/Makefile.am
rm -f globus_automake*
rm -rf autom4te.cache

unset GLOBUS_LOCATION
unset GPT_LOCATION

%{_datadir}/globus/globus-bootstrap.sh

%configure --%{docdiroption}=%{_docdir}/%{name}-%{version}

make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

GLOBUSPACKAGEDIR=$RPM_BUILD_ROOT%{_datadir}/globus/packages

# Generate package filelists
# Main package: fork.pm and globus-fork.config
cat $GLOBUSPACKAGEDIR/%{_name}/noflavor_data.filelist \
    $GLOBUSPACKAGEDIR/%{_name}/noflavor_doc.filelist \
    $GLOBUSPACKAGEDIR/%{_name}/noflavor_pgm.filelist \
  | sed s!^!%{_prefix}! \
  | sed -e 's!/man/.*!&*!' \
  | sed s!^%{_prefix}/etc!/etc! > package.filelist

%clean
rm -rf $RPM_BUILD_ROOT

%post
if [ $1 -eq 1 ]; then
    globus-gram-audit --query 'select 1 from gram_audit_table' 2> /dev/null \
    || globus-gram-audit --create --quiet \
    || :
fi

%files -f package.filelist
%defattr(-,root,root,-)
%dir %{_datadir}/globus/packages/%{_name}
%dir %{_localstatedir}/lib/globus/gram-audit
%dir %{_docdir}/%{name}-%{version}
%config(noreplace) %{_sysconfdir}/globus/gram-audit.conf

%changelog
* Tue Feb 14 2012 Joseph Bester <bester@mcs.anl.gov> - 3.1-5
- GRAM-312: Make crontab not fail if the package is uninstalled

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 3.1-4
- Update for 5.2.0 release

* Mon Dec 05 2011 Joseph Bester <bester@mcs.anl.gov> - 3.1-3
- Last sync prior to 5.2.0

* Tue Oct 11 2011 Joseph Bester <bester@mcs.anl.gov> - 3.1-2
- Add explicit dependencies on >= 5.2 libraries

* Fri Sep 02 2011 Joseph Bester <bester@mcs.anl.gov> - 3.1-2
- Fix incorrect path to globus-gram-job-manager.conf

* Thu Sep 01 2011 Joseph Bester <bester@mcs.anl.gov> - 3.0-2
- Update for 5.1.2 release

* Wed Aug 31 2011 Joseph Bester <bester@mcs.anl.gov> - 3.0-1
- Updated version numbers

