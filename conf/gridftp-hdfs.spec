Name:           gridftp-hdfs
Version:        0.2.0
Release:        1%{?dist}
Summary:        HDFS DSI plugin for GridFTP

Group:          System Environment/Daemons
License:        ASL 2.0
URL:            http://twiki.grid.iu.edu/bin/view/Storage/HadoopInstallation
# TODO:  Check if this svn tag is the same as the source tarball available
# for download.  That might simplify this a bit.
# svn co svn://t2.unl.edu/brian/gridftp_hdfs
# cd gridftp_hdfs
# ln -s /usr/share/libtool/ltmain.sh
# aclocal
# automake -a -c
# autoconf
# ./configure
# make dist
Source0:        %{name}-%{version}.tar.gz
Source1:        gridftp-hdfs-local.conf
Source2:        replica-map.conf
Source3:        gridftp-hdfs.logrotate
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

# RHEL4 doesn't have java-devel, so we build with Sun's jdk instead.
# Use Sun's jdk on both RHEL4 and RHEL5 for consistency.
BuildRequires:  jdk >= 2000:1.6.0_07-fcs
BuildRequires:  jpackage-utils
BuildRequires: hadoop-0.20-libhdfs
BuildRequires: gpt
BuildRequires: gpt-postinstall
BuildRequires: vdt_globus_essentials
BuildRequires: vdt_globus_data_server
BuildRequires: vdt_globus_sdk

Requires: hadoop-0.20-libhdfs
Requires: vdt_globus_data_server
Requires: prima
Requires: gpt-postinstall
Requires: xinetd
Requires: osg-ca-certs fetch-crl
Requires: gratia-probe-gridftp-transfer

Requires(pre): shadow-utils
Requires(post): /sbin/service
Requires(postun): /sbin/chkconfig
Requires(postun): /sbin/service

%description
HDFS DSI plugin for GridFTP 

%prep
%setup -q

%ifnarch x86_64
sed -i -e 's:gcc64dbg:gcc32dbg:g' src/Makefile.in
%endif

%build

export JAVA_HOME=/usr/java/latest
export PATH=$JAVA_HOME/bin:$PATH
export GLOBUS_LOCATION=/opt/globus

%configure --with-java=/usr/java/latest/

make

%install
rm -rf $RPM_BUILD_ROOT

make DESTDIR=$RPM_BUILD_ROOT install

install -p -m 0644 %{SOURCE1} $RPM_BUILD_ROOT%{_sysconfdir}/%{name}/
install -p -m 0644 %{SOURCE2} $RPM_BUILD_ROOT%{_sysconfdir}/%{name}/

# Remove libtool turds
rm -f $RPM_BUILD_ROOT%{_libdir}/*.la
rm -f $RPM_BUILD_ROOT%{_libdir}/*.a

mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d
install -p -m 0644 %{SOURCE3} $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/%{name}

%clean
rm -rf $RPM_BUILD_ROOT

%post
/sbin/ldconfig
/sbin/chkconfig --add %{name}
/sbin/service xinetd condrestart

%preun
if [ "$1" = "0" ] ; then
    /sbin/chkconfig --del %{name}
fi

%postun
/sbin/ldconfig
/sbin/service xinetd condrestart

%files
%defattr(-,root,root,-)
%{_bindir}/gridftp-hdfs-inetd
%{_bindir}/gridftp-hdfs-standalone
%config(noreplace) %{_sysconfdir}/xinetd.d/%{name}
%{_libdir}/libglobus_gridftp_server_hdfs_gcc*dbg.so.0
%{_libdir}/libglobus_gridftp_server_hdfs_gcc*dbg.so.0.0.0
# .so usually goes in a -devel package, but we'll leave it in this time.
%{_libdir}/libglobus_gridftp_server_hdfs_gcc*dbg.so
%config(noreplace) %{_sysconfdir}/%{name}/gridftp-inetd.conf
%config(noreplace) %{_sysconfdir}/%{name}/gridftp.conf
%config(noreplace) %{_sysconfdir}/%{name}/%{name}-local.conf
%config(noreplace) %{_sysconfdir}/%{name}/replica-map.conf
%config(noreplace) %{_sysconfdir}/logrotate.d/%{name}

%changelog
* Mon May 17 2010 Brian Bockelman <bbockelm@cse.unl.edu> 0.2.0-1
- Adjust build to depend on hadoop-0.20 RPM layout.
- Commit patches to upstream source.

* Fri Apr 9 2010 Michael Thomas <thomas@hep.caltech.edu> 0.1.0-16
- Add extra debugging lines for file buffer creation to help diagnose
  mmap() failures.  Clean up file buffer if mmap() fails.
- Use MAP_SHARED instead of MAP_PRIVATE to ensure that changes are
  written to disk and memory is not exhausted.

* Wed Feb 10 2010 Michael Thomas <thomas@hep.caltech.edu> 0.1.0-15
- Fix library name on 32-bit arch

* Fri Aug 21 2009 Michael Thomas <thomas@hep.caltech.edu> 0.1.0-14
- Add logrotate configuration file

* Mon Aug 17 2009 Michael Thomas <thomas@hep.caltech.edu> 0.1.0-13
- Add Requires: for osg-ca-certs and fetch-crl
- New upstream source fixing a potential seg fault

* Mon Jul 27 2009 Michael Thomas <thomas@hep.caltech.edu> 0.1.0-12
- Additional debugging lines.
- Add dependency on gratia probes

* Thu Jul 23 2009 Michael Thomas <thomas@hep.caltech.edu> 0.1.0-11
- New upstream sources with syslog fixes

* Sat Jul 4 2009 Michael Thomas <thomas@hep.caltech.edu> 0.1.0-10
- Add GRIDFTP_REPLICA_MAP env var for setting per-file replicas

* Thu Jul 2 2009 Michael Thomas <thomas@hep.caltech.edu> 0.1.0-9
- Move config files to /etc
- Allow local env settings in /etc/gridftp-hdfs/gridftp-hdfs-local.conf

* Thu Jul 2 2009 Michael Thomas <thomas@hep.caltech.edu> 0.1.0-8
- Restart xinetd after installing, but only if xinetd was already running

* Thu Jun 25 2009 Michael Thomas <thomas@hep.caltech.edu> 0.1.0-7
- Add hadoop environment setup to xinetd scripts

* Thu Jun 25 2009 Michael Thomas <thomas@hep.caltech.edu> 0.1.0-6
- Update to latest tarball that contains fixes for the so name

* Thu Jun 25 2009 Michael Thomas <thomas@hep.caltech.edu> 0.1.0-5
- Fix bug in postun
- Add Requires: prima

* Wed Jun 24 2009 Michael Thomas <thomas@hep.caltech.edu> 0.1.0-4
- Add Requires: gpt-postinstall so we know where the globus libraries are
  located
- Update source tarball to pick up xinetd service name change.

* Wed Jun 24 2009 Michael Thomas <thomas@hep.caltech.edu> 0.1.0-3
- Fix paths in inetd scripts
- Add explicit dependency on hadoop

* Wed Jun 24 2009 Michael Thomas <thomas@hep.caltech.edu> 0.1.0-2
- spec file cleanup

* Thu Jun 18 2009 Brian Bockelman <bbockelm@cse.unl.edu> 0.1.0-1
- Creation of GridFTP/HDFS plugin

