Name:           gridftp-hdfs
Version:        0.1.0
Release:        1%{?dist}
Summary:        HDFS DSI plugin for GridFTP

Group:          System Environment/Daemons
License:        ASL 2.0
URL:            http://twiki.grid.iu.edu/bin/view/Storage/HadoopInstallation
# TODO:  Check if this svn tag is the same as the source tarball available
# for download.  That might simplify this a bit.
# svn co svn://t2.unl.edu/brian/gridftp_hdfs
# ln -s /usr/share/libtool/ltmain.sh
# autoreconf
# automake -a
# autoreconf
# ./configure --with-java=/usr/java/jdk1.6.0_14/ --with-hadoop=/opt/hadoop
# make dist
Source0:        gridftp-hdfs-0.1.0.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

# RHEL4 doesn't have java-devel, so we build with Sun's jdk instead.
# Use Sun's jdk on both RHEL4 and RHEL5 for consistency.
BuildRequires:  jdk >= 2000:1.6.0_07-fcs
BuildRequires:  jpackage-utils
BuildRequires: hadoop-fuse
BuildRequires: hadoop-sources
BuildRequires: gpt
BuildRequires: vdt_globus_essentials
BuildRequires: vdt_globus_data_server
BuildRequires: vdt_globus_sdk

Requires:  hadoop-fuse
Requires:  vdt_globus_data_server
Requires:  xinetd

Requires(pre): shadow-utils
Requires(post): /sbin/service
Requires(postun): /sbin/chkconfig
Requires(postun): /sbin/service

%description
HDFS DIS plugin for GridFTP 

%prep
%setup -q

%build

#export JAVA_HOME=/usr/lib/jvm/java
export JAVA_HOME=/usr/java/latest
export PATH=$JAVA_HOME/bin:$PATH
export GLOBUS_LOCATION=/opt/globus
export GPT_LOCATION=/opt/gpt
export PATH=$PATH:$GPT_LOCATION/sbin
gpt-postinstall
%ifarch x86_64
gpt-build -nosrc gcc64
%else
gpt-build -nosrc gcc32
%endif

./configure --with-java=/usr/java/latest/ --with-hadoop=/opt/hadoop --sysconfdir=$RPM_BUILD_ROOT%{_sysconfdir} --prefix=$RPM_BUILD_ROOT/usr

make

%install
rm -rf $RPM_BUILD_ROOT

make install

%clean
rm -rf $RPM_BUILD_ROOT

%post
/sbin/service xinetd restart

%preun
/sbin/service xinetd restart

%files
%defattr(-,root,root,-)
/usr/bin/gridftp-hdfs-inetd
/usr/bin/gridftp-hdfs-standalone
/etc/xinetd.d/gridftp-hdfs
/usr/lib/libglobus_gridftp_server_hdfs_gcc64.a
/usr/lib/libglobus_gridftp_server_hdfs_gcc64.la
/usr/lib/libglobus_gridftp_server_hdfs_gcc64.so
/usr/lib/libglobus_gridftp_server_hdfs_gcc64.so.0
/usr/lib/libglobus_gridftp_server_hdfs_gcc64.so.0.0.0
/usr/share/gridftp-hdfs/gridftp-inetd.conf
/usr/share/gridftp-hdfs/gridftp.conf

%changelog
* Thu Jun 18 2009 Brian Bockelman <bbockelm@cse.unl.edu> 0.1.0-1
- Creation of GridFTP/HDFS plugin

