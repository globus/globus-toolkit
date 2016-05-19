Name:           globus-toolkit-repo
Version:        6
Release:        19
Summary:        Globus Repository Configuration
Group:          System Environment/Base
License:        ASL 2.0
URL:            http://toolkit.globus.org/toolkit
Source0:        RPM-GPG-KEY-Globus
Source1:        globus-toolkit-6-stable.repo.in
Source2:        globus-toolkit-6-testing.repo.in
Source3:        globus-toolkit-6-unstable.repo.in
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:      noarch
Provides:       globus-connect-server-repo

%description
This package installs the Globus yum repository configuration and GPG key for
Globus Toolkit 6.

%prep
%setup -c -T

%build
repo_root='http://toolkit.globus.org/ftppub/gt6'
unstable_root='http://toolkit.globus.org/ftppub/gt6/unstable/rpm'
pkg_repos="${pkg_repos:+$pkg_repos }el5"
el5_stable_baseurl="${repo_root}/stable/rpm/el/5/\$basearch/"
el5_stable_sourceurl="${repo_root}/stable/rpm/el/5/SRPMS/"
el5_testing_baseurl="${repo_root}/testing/rpm/el/5/\$basearch/"
el5_testing_sourceurl="${repo_root}/testing/rpm/el/5/SRPMS/"
el5_unstable_baseurl="${unstable_root}/el/5/\$basearch/"
el5_unstable_sourceurl="${unstable_root}/el/5/SRPMS/"
el5_repo_type=""

pkg_repos="${pkg_repos:+$pkg_repos }el6"
el6_stable_baseurl="${repo_root}/stable/rpm/el/6/\$basearch/"
el6_stable_sourceurl="${repo_root}/stable/rpm/el/6/SRPMS/"
el6_testing_baseurl="${repo_root}/testing/rpm/el/6/\$basearch/"
el6_testing_sourceurl="${repo_root}/testing/rpm/el/6/SRPMS/"
el6_unstable_baseurl="${unstable_root}/el/6/\$basearch/"
el6_unstable_sourceurl="${unstable_root}/el/6/SRPMS/"
el6_repo_type=""

pkg_repos="${pkg_repos:+$pkg_repos }el7"
el7_stable_baseurl="${repo_root}/stable/rpm/el/7/\$basearch/"
el7_stable_sourceurl="${repo_root}/stable/rpm/el/7/SRPMS/"
el7_testing_baseurl="${repo_root}/testing/rpm/el/7/\$basearch/"
el7_testing_sourceurl="${repo_root}/testing/rpm/el/7/SRPMS/"
el7_unstable_baseurl="${unstable_root}/el/7/\$basearch/"
el7_unstable_sourceurl="${unstable_root}/el/7/SRPMS/"
el7_repo_type=""

pkg_repos="${pkg_repos:+$pkg_repos }fedora"
fedora_stable_baseurl="${repo_root}/stable/rpm/fedora/\$releasever/\$basearch/"
fedora_stable_sourceurl="${repo_root}/stable/rpm/fedora/\$releasever/SRPMS/"
fedora_testing_baseurl="${repo_root}/testing/rpm/fedora/\$releasever/\$basearch/"
fedora_testing_sourceurl="${repo_root}/testing/rpm/fedora/\$releasever/SRPMS/"
fedora_unstable_baseurl="${unstable_root}/fedora/\$releasever/\$basearch/"
fedora_unstable_sourceurl="${unstable_root}/fedora/\$releasever/SRPMS/"
fedora_repo_type=""

pkg_repos="${pkg_repos:+$pkg_repos }sles11"
sles11_stable_baseurl="${repo_root}/stable/rpm/sles/11"
sles11_stable_sourceurl="${repo_root}/stable/rpm/sles/11"
sles11_testing_baseurl="${repo_root}/testing/rpm/sles/11"
sles11_testing_sourceurl="${repo_root}/testing/rpm/sles/11"
sles11_unstable_baseurl="${unstable_root}/sles/11"
sles11_unstable_sourceurl="${unstable_root}/sles/11"
sles11_repo_type="yast2"

echo $pkg_repos > pkg_repos
for repo in $pkg_repos ; do
    eval "stable_baseurl=\"\$${repo}_stable_baseurl\""
    eval "stable_sourceurl=\"\$${repo}_stable_sourceurl\""
    eval "testing_baseurl=\"\$${repo}_testing_baseurl\""
    eval "testing_sourceurl=\"\$${repo}_testing_sourceurl\""
    eval "unstable_baseurl=\"\$${repo}_unstable_baseurl\""
    eval "unstable_sourceurl=\"\$${repo}_unstable_sourceurl\""
    eval "repo_type=\"\$${repo}_repo_type\""
    sed -e "s!@REPO@!$repo!g" \
        -e "s!@STABLE_BASEURL@!$stable_baseurl!g" \
        -e "s!@STABLE_SOURCEURL@!$stable_sourceurl!g" \
        -e "s!@TESTING_BASEURL@!$testing_baseurl!g" \
        -e "s!@TESTING_SOURCEURL@!$testing_sourceurl!g" \
        -e "s!@UNSTABLE_BASEURL@!$unstable_baseurl!g" \
        -e "s!@UNSTABLE_SOURCEURL@!$unstable_sourceurl!g" \
        -e "s!@REPO_TYPE@!${repo_type:+type=$repo_type}!g" \
        < %{SOURCE1} > globus-toolkit-6-stable-$repo.repo
    sed -e "s!@REPO@!$repo!g" \
        -e "s!@STABLE_BASEURL@!$stable_baseurl!g" \
        -e "s!@STABLE_SOURCEURL@!$stable_sourceurl!g" \
        -e "s!@TESTING_BASEURL@!$testing_baseurl!g" \
        -e "s!@TESTING_SOURCEURL@!$testing_sourceurl!g" \
        -e "s!@UNSTABLE_BASEURL@!$unstable_baseurl!g" \
        -e "s!@UNSTABLE_SOURCEURL@!$unstable_sourceurl!g" \
        -e "s!@REPO_TYPE@!${repo_type:+type=$repo_type}!g" \
        < %{SOURCE2} > globus-toolkit-6-testing-$repo.repo
    sed -e "s!@REPO@!$repo!g" \
        -e "s!@STABLE_BASEURL@!$stable_baseurl!g" \
        -e "s!@STABLE_SOURCEURL@!$stable_sourceurl!g" \
        -e "s!@TESTING_BASEURL@!$testing_baseurl!g" \
        -e "s!@TESTING_SOURCEURL@!$testing_sourceurl!g" \
        -e "s!@UNSTABLE_BASEURL@!$unstable_baseurl!g" \
        -e "s!@UNSTABLE_SOURCEURL@!$unstable_sourceurl!g" \
        -e "s!@REPO_TYPE@!${repo_type:+type=$repo_type}!g" \
        < %{SOURCE3} > globus-toolkit-6-unstable-$repo.repo
done

%install
rm -rf $RPM_BUILD_ROOT

# gpg
install -Dpm 644 %{SOURCE0} \
  $RPM_BUILD_ROOT%{_sysconfdir}/pki/rpm-gpg/RPM-GPG-KEY-Globus

for repo in $(cat pkg_repos); do
    install -dm 755 $RPM_BUILD_ROOT%{_datadir}/globus/repo
    install -pm 644 globus-toolkit-6-stable-${repo}.repo \
      $RPM_BUILD_ROOT%{_datadir}/globus/repo
    install -pm 644 globus-toolkit-6-testing-${repo}.repo \
      $RPM_BUILD_ROOT%{_datadir}/globus/repo
    install -pm 644 globus-toolkit-6-unstable-${repo}.repo \
      $RPM_BUILD_ROOT%{_datadir}/globus/repo
done

%clean
rm -rf $RPM_BUILD_ROOT

%posttrans
# Can't do this here, as it deadlocks on SUSE
if [ ! -f /etc/SuSE-release ]; then
    rpm --import %{_sysconfdir}/pki/rpm-gpg/RPM-GPG-KEY-Globus
fi

if [ -f /etc/redhat-release ]; then
    osname=$(rpm -qf /etc/redhat-release --queryformat '%%{Name}')
    osver=$(rpm -qf /etc/redhat-release --queryformat '%%{Version}')
elif [ -f /etc/SuSE-release ]; then
    osname=$(rpm -qf /etc/SuSE-release --queryformat '%%{Name}')
    osver=$(rpm -qf /etc/SuSE-release --queryformat '%%{Version}')
else
    osname=unknown
    osver=unknown
fi
case ${osname}:${osver} in
    centos*:5* | sl*:5* | redhat*:5* | springdale*:5*)
        repo=el5
        ;;
    centos*:6* | sl*:6* | redhat*:6* | springdale*:6*)
)
        repo=el6
        ;;
    centos*:7* | sl*:7* | redhat*:7* | springdale*:7*))
        repo=el7
        ;;
    fedora*:*)
        repo=fedora
        ;;
    sles*:11*)
        repo=sles11
        ;;
    *)
	echo "Unsupported repo" 1>&2
	exit 1
        ;;
esac

if command -v zypper > /dev/null; then
    sed 's/enabled=0/enabled=1/' \
        < %{_datadir}/globus/repo/globus-toolkit-6-stable-${repo}.repo \
        > %{_sysconfdir}/zypp/repos.d/globus-toolkit-6-stable-${repo}.repo 
    cp %{_datadir}/globus/repo/globus-toolkit-6-testing-${repo}.repo %{_sysconfdir}/zypp/repos.d
    cp %{_datadir}/globus/repo/globus-toolkit-6-unstable-${repo}.repo %{_sysconfdir}/zypp/repos.d
elif command -v yum-config-manager > /dev/null; then
    yum-config-manager --add-repo file://%{_datadir}/globus/repo/globus-toolkit-6-stable-${repo}.repo
    yum-config-manager --add-repo file://%{_datadir}/globus/repo/globus-toolkit-6-testing-${repo}.repo
    yum-config-manager --add-repo file://%{_datadir}/globus/repo/globus-toolkit-6-unstable-${repo}.repo
    yum-config-manager --enable Globus-Toolkit-6-$repo > /dev/null
elif [ -d %{_sysconfdir}/yum.repos.d ] ; then
    sed 's/enabled=0/enabled=1/' \
        < %{_datadir}/globus/repo/globus-toolkit-6-stable-${repo}.repo \
        > %{_sysconfdir}/yum.repos.d/globus-toolkit-6-stable-${repo}.repo 
    cp %{_datadir}/globus/repo/globus-toolkit-6-testing-${repo}.repo %{_sysconfdir}/yum.repos.d
    cp %{_datadir}/globus/repo/globus-toolkit-6-unstable-${repo}.repo %{_sysconfdir}/yum.repos.d
else
    echo "Copy the Globus Repository Definition from %{_datadir}/globus/repo/ to your system's repo configuration"
fi

%preun
if [ "$1" != 0 ]; then
    exit 0
fi
if [ -f /etc/redhat-release ]; then
    osname=$(rpm -qf /etc/redhat-release --queryformat '%%{Name}')
    osver=$(rpm -qf /etc/redhat-release --queryformat '%%{Version}')
elif [ -f /etc/SuSE-release ]; then
    osname=$(rpm -qf /etc/SuSE-release --queryformat '%%{Name}')
    osver=$(rpm -qf /etc/SuSE-release --queryformat '%%{Version}')
else
    osname=unknown
    osver=unknown
fi
case ${osname}:${osver} in
    centos*:5* | sl*:5* | redhat*:5* | springdale*:5*)
        repo=el5
        ;;
    centos*:6* | sl*:6* | redhat*:6* | springdale*:6*)
        repo=el6
        ;;
    centos*:7* | sl*:7* | redhat*:7* | springdale*:7*)
        repo=el7
        ;;
    fedora*:*)
        repo=fedora
        ;;
    sles*:11*)
        repo=sles11
        ;;
    *)
	echo "Unsupported repo" 1>&2
	exit 1
        ;;
esac

if command -v zypper > /dev/null; then
    rm -f %{_sysconfdir}/zypp/repos.d/globus-toolkit-6-stable-${repo}.repo 
    rm -f %{_sysconfdir}/zypp/repos.d/globus-toolkit-6-testing-${repo}.repo 
    rm -f %{_sysconfdir}/zypp/repos.d/globus-toolkit-6-unstable-${repo}.repo 
elif [ -d %{_sysconfdir}/yum.repos.d ]; then
    rm -f %{_sysconfdir}/yum.repos.d/globus-toolkit-6-stable-${repo}.repo
    rm -f %{_sysconfdir}/yum.repos.d/globus-toolkit-6-testing-${repo}.repo
    rm -f %{_sysconfdir}/yum.repos.d/globus-toolkit-6-unstable-${repo}.repo
else
    echo "Remove the Globus Repository defintion from your system configuration"
fi

%files
%defattr(-,root,root,-)
%{_sysconfdir}/pki/rpm-gpg/*
%{_datadir}/globus/repo/*

%changelog
* Thu Mar 19 2016 Globus Toolkit <support@globus.org> - 6-19
- Add springdale (rhel-compatible)

* Mon Apr 06 2015 Globus Toolkit <support@globus.org> - 6-18
- Handle update from broken versions

* Wed Apr 01 2015 Globus Toolkit <support@globus.org> - 6-17
- Don't require lsb

* Tue Mar 31 2015 Globus Toolkit <support@globus.org> - 6-16
- Don't preun when upgrading

* Mon Mar 30 2015 Globus Toolkit <support@globus.org> - 6-15
- Rename www.globus.org -> toolkit.globus.org

* Thu Nov 13 2014 Globus Toolkit <support@globus.org> - 6-14
- Don't use zypper from postinstall on SUSE

* Thu Nov 06 2014 Globus Toolkit <support@globus.org> - 6-13
- Import key on non-SUSE

* Thu Nov 06 2014 Globus Toolkit <support@globus.org> - 6-12
- Fix sed substitution command line

* Tue Sep 16 2014 Globus Toolkit <support@globus.org> - 6-11
- Fix sed substitution to enable stable when yum-utils are not present

* Mon Sep 15 2014 Globus Toolkit <support@globus.org> - 6-10
- Add Provides alias for globus-connect-server-repo

* Fri Aug 22 2014 Globus Toolkit <support@globus.org> - 6-9
- Add pre/post dependency on lsb

* Fri Aug 15 2014 Globus Toolkit <support@globus.org> - 6-8
- Move unstable repo to www.globus.org

* Wed Aug 13 2014 Globus Toolkit <support@globus.org> - 6-7
- Add priority to repositories

* Mon Aug 11 2014 Globus Toolkit <support@globus.org> - 6-6
- Fix "type" line

* Mon Aug 11 2014 Globus Toolkit <support@globus.org> - 6-5
- Avoid rpm import deadlock

* Mon Aug 11 2014 Globus Toolkit <support@globus.org> - 6-4
- Don't require yum-utils

* Mon Aug 11 2014 Globus Toolkit <support@globus.org> - 6-3
- Add SLES11 to repo list

* Tue Jul 22 2014 Globus Toolkit <support@globus.org> - 6-2
- Add EL7 to repo list
