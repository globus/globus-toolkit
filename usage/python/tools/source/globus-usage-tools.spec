%define name globus-usage-tools
%define _name globus_usage_tools
%define version 0.11
%define release 1
%define home http://www.globus.org/toolkit/usagestats_server


Summary: Globus Usage Collector Tools
Name: %{name}
Version: %{version}
Release: %{release}
Source: %{home}/%{_name}-%{version}.tar.gz
License: ASL 2.0
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: noarch
Requires: postgresql
Requires: python-psycopg2
Vendor: Globus Toolkit <support@globus.org>
Url: %{home}

%description
his package contains the Globus Usage Tools. These tools provide
services to collect usage stats packages from Globus services and
store them into an SQL database for analysis.

%prep
%setup -q -n %{_name}-%{version}

%build
python setup.py build

%install
rm -rf "$RPM_BUILD_ROOT"
python setup.py install \
    --root $RPM_BUILD_ROOT \
    --install-scripts /usr/sbin \
    --install-data /usr \
    --record=INSTALLED_FILES
sed -i INSTALLED_FILES -e 's|\.8|.8*|'
sed -i INSTALLED_FILES -e '/\.pyc$/d' -e 's|\.py$|.py*|'
# --install-data puts globus and init.d dirs in /usr/etc, so move 
# them. Also, the config is marked as %config below, so doesn't need
# to be int he INSTALLED_FILED list
mkdir -p $RPM_BUILD_ROOT/etc
mv $RPM_BUILD_ROOT/usr/etc/globus $RPM_BUILD_ROOT/etc/globus
sed -i INSTALLED_FILES -e '/\/etc\/globus\/usage-tools.conf/d'

mv $RPM_BUILD_ROOT/usr/etc/init.d $RPM_BUILD_ROOT/etc/init.d
sed -i INSTALLED_FILES -e 's/usr\/etc/etc/'

install -d -m 700 $RPM_BUILD_ROOT/%{_localstatedir}/lib/globus/usage

%pre
getent group usagestats >/dev/null || groupadd -r usagestats
getent passwd usagestats >/dev/null || \
    useradd -r -g usagestats -d %{_localstatedir}/lib/globus/usage \
            -s /sbin/nologin \
            -c "User to run the usage stats service" usagestats


%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES
%defattr(-,root,root)
%attr(700,usagestats,usagestats) %{_localstatedir}/lib/globus/usage
%docdir /usr/share/doc/%{name}
%config(noreplace) /etc/globus/usage-tools.conf

%changelog
* Wed Dec 12 2012 Globus Toolkit <support@globus.org> - 0.11-1
- Add gridftp_aggregations_hourly and gram5_aggregations_hourly tables
- Add automatic aggregation of hourly data after individual transfer and job
  packets are uploaded
