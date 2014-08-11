Name:           globus-toolkit-repo
Version:        6
Release:        3
Summary:        Globus Repository Configuration
Group:          System Environment/Base
License:        ASL 2.0
URL:            http://www.globus.org/toolkit
Source0:        RPM-GPG-KEY-Globus
Source1:        globus-toolkit-6-stable.repo.in
Source2:        globus-toolkit-6-testing.repo.in
Source3:        globus-toolkit-6-unstable.repo.in
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:      noarch
Requires(post): yum-utils
Requires(preun): yum-utils

%description
This package installs the Globus yum repository configuration and GPG key for
Globus Toolkit 6.

%prep
%setup -c -T

%build
repo_root='http://www.globus.org/ftppub/gt6'
unstable_root='http://builds.globus.org/repo6/rpm'
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
        -e "s!@REPO_TYPE@!$repo_type!g" \
        < %{SOURCE1} > globus-toolkit-6-stable-$repo.repo
    sed -e "s!@REPO@!$repo!g" \
        -e "s!@STABLE_BASEURL@!$stable_baseurl!g" \
        -e "s!@STABLE_SOURCEURL@!$stable_sourceurl!g" \
        -e "s!@TESTING_BASEURL@!$testing_baseurl!g" \
        -e "s!@TESTING_SOURCEURL@!$testing_sourceurl!g" \
        -e "s!@UNSTABLE_BASEURL@!$unstable_baseurl!g" \
        -e "s!@UNSTABLE_SOURCEURL@!$unstable_sourceurl!g" \
        -e "s!@REPO_TYPE@!$repo_type!g" \
        < %{SOURCE2} > globus-toolkit-6-testing-$repo.repo
    sed -e "s!@REPO@!$repo!g" \
        -e "s!@STABLE_BASEURL@!$stable_baseurl!g" \
        -e "s!@STABLE_SOURCEURL@!$stable_sourceurl!g" \
        -e "s!@TESTING_BASEURL@!$testing_baseurl!g" \
        -e "s!@TESTING_SOURCEURL@!$testing_sourceurl!g" \
        -e "s!@UNSTABLE_BASEURL@!$unstable_baseurl!g" \
        -e "s!@UNSTABLE_SOURCEURL@!$unstable_sourceurl!g" \
        -e "s!@REPO_TYPE@!$repo_type!g" \
        < %{SOURCE3} > globus-toolkit-6-unstable-$repo.repo
done

%install
rm -rf $RPM_BUILD_ROOT

# gpg
install -Dpm 644 %{SOURCE0} \
  $RPM_BUILD_ROOT%{_sysconfdir}/pki/rpm-gpg/RPM-GPG-KEY-Globus

for repo in $(cat pkg_repos); do
    install -dm 755 $RPM_BUILD_ROOT%{_datadir}
    install -pm 644 globus-toolkit-6-stable-${repo}.repo \
      $RPM_BUILD_ROOT%{_datadir}
    install -pm 644 globus-toolkit-6-testing-${repo}.repo \
      $RPM_BUILD_ROOT%{_datadir}
    install -pm 644 globus-toolkit-6-unstable-${repo}.repo \
      $RPM_BUILD_ROOT%{_datadir}
done

%clean
rm -rf $RPM_BUILD_ROOT

%post
rpm --import %{_sysconfdir}/pki/rpm-gpg/RPM-GPG-KEY-Globus
case $(lsb_release -is):$(lsb_release -rs) in
    CentOS:5* | Scientific*:5* | RedHat*:5* )
        repo=el5
        ;;
    CentOS:6* | Scientific*:6* | RedHat*:6* )
        repo=el6
        ;;
    CentOS:7* | Scientific*:7* | RedHat*:7* )
        repo=el7
        ;;
    Fedora*:*)
        repo=fedora
        ;;
    SUSE*:11*)
        repo=sles11
        ;;
    *)
	echo "Unsupported repo" 1>&2
	exit 1
        ;;
esac

if [ "$repo" != "sles11" ]; then
    yum-config-manager --add-repo file://%{_datadir}/globus-toolkit-6-stable-${repo}.repo
    yum-config-manager --add-repo file://%{_datadir}/globus-toolkit-6-testing-${repo}.repo
    yum-config-manager --add-repo file://%{_datadir}/globus-toolkit-6-unstable-${repo}.repo
    yum-config-manager --enable Globus-Toolkit-6-$repo > /dev/null
else
    zypper ar %{_datadir}/globus-toolkit-6-stable-${repo}.repo
    zypper ar -d %{_datadir}/globus-toolkit-6-testing-${repo}.repo
    zypper ar -d %{_datadir}/globus-toolkit-6-unstable-${repo}.repo
fi

%preun
case $(lsb_release -is):$(lsb_release -rs) in
    CentOS:5* | Scientific*:5* | RedHat*:5* )
        repo=el5
        ;;
    CentOS:6* | Scientific*:6* | RedHat*:6* )
        repo=el6
        ;;
    CentOS:7* | Scientific*:7* | RedHat*:7* )
        repo=el7
        ;;
    Fedora*:*)
        repo=fedora
        ;;
    SUSE*:11*)
        repo=sles11
        for reponame in Globus-Toolkit-6 \
                        Globus-Toolkit-6-Testing \
                        Globus-Toolkit-6-Unstable; do
            zypper rr ${reponame}-${repo}
            zypper rr ${reponame}-Source-${repo}
        done
        exit 0
        ;;
esac
rm -f /etc/yum.repo.d/globus-toolkit-6-stable-${repo}.repo
rm -f /etc/yum.repo.d/globus-toolkit-6-testing-${repo}.repo
rm -f /etc/yum.repo.d/globus-toolkit-6-unstable-${repo}.repo

%files
%defattr(-,root,root,-)
%{_sysconfdir}/pki/rpm-gpg/*
%{_datadir}/*

%changelog
* Mon Aug 11 2014 Globus Toolkit <support@globus.org> - 6-3
- Add SLES11 to repo list

* Tue Jul 22 2014 Globus Toolkit <support@globus.org> - 6-2
- Add EL7 to repo list
