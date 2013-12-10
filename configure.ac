AC_INIT([globus_toolkit], [5.3.0], [support@globus.org])
export GLOBUS_VERSION=$VERSION
AM_INIT_AUTOMAKE(foreign)
AM_PROG_LIBTOOL
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES])

dnl Leading newline allows this multi-line value be AC_SUBST into the
dnl Makefile with a dummy first macro created by the automatic var = @var@
dnl that automake generates
m4_define([TARGETS_MACRO],[
])
# GT_PACKAGE(package, subdir, dependencies, bundle)
m4_define([GT_PACKAGE],
[
    m4_append([TARGETS_MACRO],[dnl
$1-all_SUBDIR = $2
$1-clean_SUBDIR = $2
$1-install_SUBDIR = $2
$1-distclean_SUBDIR = $2
$1-clean_stamp = $1-stamp
$1-install_stamp = $1-stamp
$1-dist_SUBDIR = $2
$1-deps = m4_foreach(p, m4_split(m4_normalize($3)), p[-stamp ]) 
$1: $1-all
$1-all: $1-stamp
$1-install: $1-stamp m4_foreach(p, m4_split(m4_normalize($3)), p[-install ]) 
$1-stamp: [\$(]$1[-deps)]
	@export PKG_CONFIG_PATH=\$(PKG_CONFIG_PATH) ; ( (cd \$($1-all_SUBDIR) && \$(MAKE) \$(AM_MAKEFLAGS) all) && touch \$[]@) || exit 1
$1-only:
	@export PKG_CONFIG_PATH=\$(PKG_CONFIG_PATH) ; cd \$($1-all_SUBDIR) && \$(MAKE) \$(AM_MAKEFLAGS) all
m4_pushdef([AC_INIT],[$]1-[$]2)dnl
m4_define([pkgver], m4_esyscmd(grep AC[_]INIT [$2][/configure.ac]))dnl
$1-dist-tarball = m4_normalize(pkgver)[.tar.gz]
m4_popdef([AC_INIT])dnl
])
    m4_append([GT_PKGCONFIG_DIRS_MACRO], ${ac_pwd}/[$2], [:])
    m4_append([GT_SUBDIRS_MACRO], [$2], [ ])dnl
    m4_append_uniq([GT_BUNDLES_MACRO],[$4], [ ])dnl
    m4_append([GT_BUNDLES_$4_MACRO],[$1-all], [ ])dnl
    m4_append([GT_TARGETS_ALL_MACRO], [$1-all], [ ])dnl
    m4_append([GT_TARGETS_CLEAN_MACRO], [$1-clean], [ ])dnl
    m4_append([GT_TARGETS_INSTALL_MACRO], [$1-install], [ ])dnl
    m4_append([GT_TARGETS_DISTCLEAN_MACRO], [$1-distclean], [ ])dnl
    m4_append([GT_TARGETS_DIST_MACRO], [$1-dist], [ ])dnl
    m4_append([GT_DOXYGEN_SUBDIRS_MACRO], [$srcdir/$2], [ ])dnl
    m4_append([GT_ALL_STAMPS_MACRO], [$1-stamp], [ ])dnl
])dnl


GT_PACKAGE(
    [globus_common], [common/source],[],[ccommonlibs])
GT_PACKAGE(
    [globus_xio], [xio/src], [globus_common],[ccommonlibs])
GT_PACKAGE(
    [globus_gfork], [gridftp/gfork/source], [globus_common globus_xio], [gridftp])
GT_PACKAGE(
    [globus_gsi_openssl_error], [gsi/openssl_error/source], [globus_common],
    [gsi])
GT_PACKAGE(
    [globus_gsi_proxy_ssl], [gsi/proxy/proxy_ssl/source], [], [gsi])
GT_PACKAGE(
    [globus_openssl_module], [gsi/openssl_module/source],
    [globus_common globus_gsi_proxy_ssl globus_gsi_openssl_error],
    [gsi])
GT_PACKAGE(
    [globus_gsi_cert_utils], [gsi/cert_utils/source],
    [globus_common globus_openssl_module globus_gsi_openssl_error 
     globus_gsi_proxy_ssl], [gsi])
GT_PACKAGE([globus_gsi_sysconfig], [gsi/sysconfig/source], 
    [globus_common globus_openssl_module globus_gsi_openssl_error], [gsi])
GT_PACKAGE([globus_callout], [callout/source], [globus_common], [ccommonlibs])
GT_PACKAGE([globus_gsi_callback], [gsi/callback/source],
    [ globus_common globus_openssl_module globus_gsi_openssl_error 
      globus_gsi_cert_utils globus_gsi_sysconfig globus_gsi_proxy_ssl ],
    [gsi])
GT_PACKAGE([globus_gsi_credential], [gsi/credential/source],
    [ globus_common globus_gsi_proxy_ssl globus_gsi_openssl_error 
      globus_gsi_cert_utils globus_gsi_sysconfig globus_gsi_callback],
    [gsi])
GT_PACKAGE([globus_gsi_proxy_core], [gsi/proxy/proxy_core/source],
    [ globus_common globus_openssl_module globus_gsi_openssl_error 
      globus_gsi_cert_utils globus_gsi_sysconfig globus_gsi_proxy_ssl 
      globus_gsi_credential ], [gsi])
GT_PACKAGE([globus_gssapi_gsi], [gsi/gssapi/source], 
    [ globus_common globus_openssl_module globus_gsi_openssl_error 
      globus_gsi_cert_utils globus_gsi_credential globus_gsi_callback 
      globus_gsi_proxy_core globus_gsi_sysconfig ], [gsi])
GT_PACKAGE([globus_gss_assist],[gsi/gss_assist/source],
    [ globus_common globus_gsi_sysconfig globus_gsi_cert_utils 
      globus_gssapi_gsi globus_callout globus_gsi_credential],
      [gsi])
GT_PACKAGE([globus_gssapi_error], [gsi/gssapi_error/source],
    [ globus_common  globus_gss_assist  globus_gssapi_gsi ], [gsi])
GT_PACKAGE([globus_xio_gsi_driver],[xio/drivers/gsi],
    [ globus_xio  globus_gss_assist  globus_gssapi_error  
      globus_gssapi_gsi  globus_common ], [ccommonlibs])
GT_PACKAGE([globus_io],[io/compat], 
    [ globus_common  globus_xio  globus_gss_assist  globus_gssapi_gsi  
      globus_xio_gsi_driver  globus_gssapi_error ], [ccommonlibs])
GT_PACKAGE([globus_ftp_control],[gridftp/control/source],
    [ globus_common  globus_gss_assist  globus_gssapi_gsi  globus_io
      globus_xio  globus_gssapi_error ], [gridftp])
GT_PACKAGE([globus_usage],[usage/c/sender/source],
    [globus_common globus_xio], [ccommonlibs])
GT_PACKAGE([globus_xio_pipe_driver],[xio/drivers/pipe/source],
    [globus_xio globus_common], [ccommonlibs])
GT_PACKAGE([globus_gridftp_server_control],[gridftp/server-lib/src],
    [ globus_common  globus_xio  globus_xio_gsi_driver  globus_xio_pipe_driver
      globus_gss_assist  globus_gssapi_gsi  globus_gsi_openssl_error
      globus_gssapi_error ], [gridftp])
GT_PACKAGE([globus_authz_callout_error],[gsi/authz/error],
    [globus_common], [gsi])
GT_PACKAGE([globus_authz],[gsi/authz/source],
    [globus_common globus_callout globus_gssapi_gsi
    globus_authz_callout_error], [gsi])
GT_PACKAGE([globus_gridftp_server],[gridftp/server/src],
    [ globus_common  globus_xio  globus_xio_gsi_driver  globus_gfork
      globus_gridftp_server_control  globus_ftp_control  globus_authz
      globus_usage  globus_gss_assist  globus_gsi_credential ],
    [gridftp])
GT_PACKAGE([globus_gram_protocol],[gram/protocol/source],
    [ globus_common globus_io globus_gssapi_gsi globus_gss_assist], [gram5])
GT_PACKAGE([globus_scheduler_event_generator],
    [gram/jobmanager/scheduler_event_generator/source],
    [ globus_common  globus_xio  globus_gram_protocol  globus_xio_gsi_driver],
    [gram5-server])
GT_PACKAGE([globus_gram_job_manager_lsf],
    [gram/jobmanager/lrms/lsf/source],
    [ globus_common  globus_xio  globus_scheduler_event_generator
      globus_gram_protocol], [gram5-lsf])
GT_PACKAGE([globus_xio_rate_driver],[xio/drivers/rate/source],
    [globus_xio], [ccommonlibs])
GT_PACKAGE([globus_gass_transfer],[gass/transfer/source],
    [globus_common globus_gssapi_gsi globus_gss_assist globus_io],
    [ccommonlibs])
GT_PACKAGE([globus_xio_popen_driver],[xio/drivers/popen/source],
    [globus_common globus_xio], [ccommonlibs])
GT_PACKAGE([globus_ftp_client],[gridftp/client/source],
    [ globus_common  globus_ftp_control  globus_gsi_callback
      globus_gsi_credential  globus_gsi_sysconfig  globus_gssapi_gsi
      globus_xio globus_xio_popen_driver ], [gridftp])
GT_PACKAGE([globus_gass_copy],[gass/copy/source],
    [ globus_common  globus_ftp_client  globus_ftp_control
      globus_gsi_sysconfig  globus_gass_transfer  globus_io  globus_gssapi_gsi
      globus_gssapi_error ], [gridftp])
dnl GT_PACKAGE([globus_xio_netlogger_driver], [xio/drivers/netlog])
GT_PACKAGE([globus_gass_cache],[gass/cache/source],
    [ globus_common ], [gram5])
GT_PACKAGE([globus_rsl],[gram/rsl/source], [globus_common], [gram5])
GT_PACKAGE([globus_gram_job_manager_callout_error],
        [gram/jobmanager/callout_error],
        [globus_common], [gram5-server])
GT_PACKAGE([globus_gram_job_manager],[gram/jobmanager/source],
    [ globus_common  globus_gsi_credential  globus_gass_cache
      globus_gass_transfer  globus_gram_protocol  globus_gssapi_gsi
      globus_gss_assist  globus_gsi_sysconfig  globus_callout  globus_xio
      globus_xio_popen_driver  globus_rsl
      globus_gram_job_manager_callout_error globus_scheduler_event_generator
      globus_usage ], [gram5-server])
GT_PACKAGE([globus_xio_gridftp_multicast],
        [gridftp/server/multi/source],
        [ globus_xio  globus_ftp_client  globus_xio_gsi_driver ],
        [ccommonlibs])
GT_PACKAGE([globus_simple_ca],[gsi/simple_ca/source], [], [gsi])
GT_PACKAGE([globus_gram_job_manager_sge],
        [gram/jobmanager/lrms/sge/source],
        [ globus_common  globus_xio  globus_scheduler_event_generator
          globus_gram_protocol ], [gram5-sge])
GT_PACKAGE([globus_gram_job_manager_scripts],
        [gram/jobmanager/scripts], [], [gram5-server])
dnl GT_PACKAGE([globus_authz_null_callout],
dnl         [gsi/authz_null_callout/source],
dnl         [globus_authz], [gsi])
GT_PACKAGE([globus_gram_job_manager_slurm],
        [gram/jobmanager/lrms/slurm/source], [], [gram5-slurm])
dnl GT_PACKAGE([globus_xio_udt_driver],[xio/drivers/udt_ref])
GT_PACKAGE([globus_gridmap_callout_error],
        [gsi/gridmap_callout/error], [globus_common globus_gssapi_error],
        [gsi])
dnl GT_PACKAGE([globus_xio_skeleton_driver], [xio/drivers/skeleton/source])
GT_PACKAGE([globus_gass_server_ez],[gass/server_ez/source],
    [ globus_common  globus_gass_transfer  globus_gssapi_gsi 
      globus_gss_assist ], [gram5])
GT_PACKAGE([globus_gram_client],[gram/client/source], 
    [ globus_common  globus_gram_protocol  globus_io  globus_rsl
      globus_gss_assist], [gram5])
GT_PACKAGE([globus_xio_gridftp_driver],
    [gridftp/gridftp_driver/source],
    [ globus_common  globus_xio  globus_ftp_client  globus_xio_gsi_driver ],
    [gridftp])
GT_PACKAGE([globus_gram_job_manager_fork],
    [gram/jobmanager/lrms/fork/source],
    [ globus_common  globus_xio  globus_scheduler_event_generator
      globus_gram_protocol ], [gram5-server])
GT_PACKAGE([globus_gridmap_verify_myproxy_callout],
    [gsi/gridmap_verify_myproxy_callout],
    [ globus_gsi_sysconfig  globus_gssapi_gsi  globus_gss_assist
      globus_gridmap_callout_error  globus_gsi_credential ],
      [gsi])
GT_PACKAGE([globus_gridmap_eppn_callout], [gsi/gridmap_eppn_callout],
    [ globus_gsi_sysconfig globus_gssapi_gsi globus_gss_assist
      globus_gridmap_callout_error globus_gsi_credential ],
    [gsi])
GT_PACKAGE([globus_usage_tools], [usage/python/tools/source], [], [usage])
GT_PACKAGE([globus_gram_job_manager_condor],
    [gram/jobmanager/lrms/condor/source], [], [gram5-condor])
GT_PACKAGE([globus_proxy_utils],[gsi/proxy/proxy_utils/source],
    [ globus_common globus_openssl_module globus_gsi_openssl_error
      globus_gsi_cert_utils globus_gsi_sysconfig globus_gsi_proxy_ssl
      globus_gsi_credential globus_gsi_callback globus_gsi_proxy_core
      globus_gss_assist ], [gsi])
GT_PACKAGE([globus_xioperf],[xio/xioperf/source],
    [ globus_common globus_xio ], [ccommonlibs])
GT_PACKAGE([globus_gatekeeper],[gram/gatekeeper/source],
    [ globus_common  globus_gss_assist  globus_gssapi_gsi ], [gram5-server])
GT_PACKAGE([globus_gass_cache_program],[gass/cache_program/source],
    [ globus_common  globus_gass_cache  globus_gass_copy  globus_gass_transfer
      globus_gass_server_ez  globus_gram_client ], [gram5])
GT_PACKAGE([globus_gram_job_manager_pbs],
    [gram/jobmanager/lrms/pbs/source],
    [globus_common globus_scheduler_event_generator], [gram5-pbs])
GT_PACKAGE([globus_gram_client_tools],[gram/client_tools/source],
    [ globus_common  globus_gram_client  globus_gram_protocol
      globus_gass_transfer  globus_gass_server_ez  globus_rsl
      globus_gss_assist ], [gram5])
PKG_CONFIG_PATH="[${PKG_CONFIG_PATH:+$PKG_CONFIG_PATH:}]GT_PKGCONFIG_DIRS_MACRO"
export PKG_CONFIG_PATH
dnl 
SUBDIRS=""
DIST_SUBDIRS="GT_SUBDIRS_MACRO"
GT_TARGETS_ALL="GT_TARGETS_ALL_MACRO"
GT_TARGETS_CLEAN="GT_TARGETS_CLEAN_MACRO"
GT_TARGETS_INSTALL="GT_TARGETS_INSTALL_MACRO"
GT_TARGETS_DISTCLEAN="GT_TARGETS_DISTCLEAN_MACRO"
GT_TARGETS_DIST="GT_TARGETS_DIST_MACRO"
GT_PKGCONFIG_DIRS="GT_PKGCONFIG_DIRS_MACRO"
GT_DOXYGEN_SUBDIRS="GT_DOXYGEN_SUBDIRS_MACRO"
GT_ALL_STAMPS="GT_ALL_STAMPS_MACRO"
TARGETS="TARGETS_MACRO m4_foreach([bundle],
    m4_split(GT_BUNDLES_MACRO),
    [
bundle: m4_expand([GT_BUNDLES_]bundle[_MACRO])])"
GT_BUNDLES="m4_normalize(GT_BUNDLES_MACRO)"
AC_PATH_PROGS([DOXYGEN], [doxygen])
AM_CONDITIONAL([ENABLE_DOXYGEN], [test "$DOXYGEN" != ""])
TARGETS_FILE=makefile.targets
echo "$TARGETS" > "$TARGETS_FILE"
AC_SUBST_FILE(TARGETS_FILE)
AC_SUBST(SUBDIRS)
AC_SUBST(DIST_SUBDIRS)
AC_SUBST(GT_TARGETS_ALL)
AC_SUBST(GT_TARGETS_CLEAN)
AC_SUBST(GT_TARGETS_INSTALL)
AC_SUBST(GT_TARGETS_DIST)
AC_SUBST(GT_TARGETS_DISTCLEAN)
AC_SUBST(GT_PKGCONFIG_DIRS)
AC_SUBST(GT_DOXYGEN_SUBDIRS)
AC_SUBST(GT_ALL_STAMPS)
AC_SUBST(GT_BUNDLES)
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([Doxyfile])
AC_CONFIG_FILES([doxygen/index.dox])
gittop="`git rev-parse --show-toplevel`"
if test -n "$gittop"; then
    export ACLOCAL_PATH="${ACLOCAL_PATH:+$ACLOCAL_PATH:}$gittop"
fi
AC_CONFIG_SUBDIRS(GT_SUBDIRS_MACRO)
AC_OUTPUT
