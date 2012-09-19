Name:           gcmu
%global _name %(tr - _ <<< %{name})
Version:        1.2
Release:        1%{?dist}
Summary:        Globus Connect Multi-User

Group:          System Environment/Libraries
License:        ASL 2.0
URL:            http://www.globus.org/
Source:         gcmu-1.2.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:      noarch

Requires:       globus-gridftp-server-progs%{?_isa} >= 6
Requires:       globus-gass-copy-progs%{?_isa} 
Requires:       globus-gss-assist-progs%{?_isa} 
Requires:       myproxy%{?_isa} 
Requires:       myproxy-server%{?_isa} 
Requires:       gsi-openssh%{?_isa} 
Requires:       gsi-openssh-clients%{?_isa} 
Requires:       gsi-openssh-server%{?_isa} 
Requires:       globus-gsi-cert-utils-progs%{?_isa} 
Requires:       globus-simple-ca
Requires:       globus-gridmap-verify-myproxy-callout 
Requires:	python
Requires:	xinetd


%description
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
Globus Connect Multi-User Installation Tool

%prep
%setup -n %{_name}-src

%build
find . -depth -name CVS -exec rm -rf {} \;

%install
rm -rf $RPM_BUILD_ROOT
mkdir $RPM_BUILD_ROOT
cp -r gc/* $RPM_BUILD_ROOT
cert_dir="$RPM_BUILD_ROOT/etc/grid-security/certificates"
old_ca_hash="4396eb4d"
new_ca_hash="`openssl x509 -noout -hash -in $cert_dir/$old_ca_hash.0`"
if [ "$new_ca_hash" != "$old_ca_hash" ]; then 
    mv "$cert_dir/${old_ca_hash}.signing_policy" \
       "$cert_dir/${new_ca_hash}.signing_policy"
    mv "${cert_dir}/${old_ca_hash}.0" \
       "$cert_dir/${new_ca_hash}.0"
fi
cp install $RPM_BUILD_ROOT/usr/share/gcmu/install
cp root-unsetup $RPM_BUILD_ROOT/usr/share/gcmu/uninstall
mkdir -p $RPM_BUILD_ROOT/var/lib/gcmu
mkdir -p $RPM_BUILD_ROOT/usr/etc/ssh
mkdir -p $RPM_BUILD_ROOT/usr/share/doc/gcmu

# Compile python modules explicitly. Some RPM versions do this for us, but not
# all
python -c "import compileall; compileall.compile_dir('$RPM_BUILD_ROOT/usr/share/gcmu')"
python -O -c "import compileall; compileall.compile_dir('$RPM_BUILD_ROOT/usr/share/gcmu')"

# Generate package filelists
cd $RPM_BUILD_ROOT
find ./ -type f |sed s/^\.// > $RPM_BUILD_DIR/%{_name}-src/package.filelist
echo "/var/lib/gcmu" >> $RPM_BUILD_DIR/%{_name}-src/package.filelist
echo "/usr/etc/ssh" >> $RPM_BUILD_DIR/%{_name}-src/package.filelist

%clean
rm -rf $RPM_BUILD_ROOT

%files -f package.filelist

%changelog
* Mon Sep 17 2012 Joseph Bester <bester@mcs.anl.gov> 1.2
- Initial packaging
