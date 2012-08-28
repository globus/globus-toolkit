#

# 
# Copyright 1999-2006 University of Chicago
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 

# Interpreters:
# 

GLOBUS_SH_PERL=/opt/local/bin/perl
GLOBUS_SH=/bin/sh

#--
# NECESSARY section: ALL of the following commands must be defined!
#
GLOBUS_SH_AWK="/usr/bin/awk"
GLOBUS_SH_AUTOCONF="/opt/local/bin/autoconf"
GLOBUS_SH_BASENAME="/usr/bin/basename"
GLOBUS_SH_CAT="/bin/cat"
GLOBUS_SH_CHGRP="/usr/bin/chgrp"
GLOBUS_SH_CHMOD="/bin/chmod"
GLOBUS_SH_CHOWN="/usr/sbin/chown"
GLOBUS_SH_CLEAR="/opt/local/bin/clear"
GLOBUS_SH_CP="/bin/cp"
GLOBUS_SH_CUT="/usr/bin/cut"
GLOBUS_SH_CVS="/usr/bin/cvs"
GLOBUS_SH_DATE="/bin/date"
GLOBUS_SH_DF="/bin/df"
GLOBUS_SH_DIFF="/usr/bin/diff"
GLOBUS_SH_DIRNAME="/usr/bin/dirname"
GLOBUS_SH_EXPR="/bin/expr"
GLOBUS_SH_FINGER="/usr/bin/finger"
GLOBUS_SH_GREP="/usr/bin/grep"
GLOBUS_SH_GROUPS="/usr/bin/groups"
GLOBUS_SH_GZIP="/usr/bin/gzip"
GLOBUS_SH_HEAD="/usr/bin/head"
GLOBUS_SH_HOSTID=""
GLOBUS_SH_HOSTNAME="/bin/hostname"
GLOBUS_SH_IFCONFIG="/sbin/ifconfig"
GLOBUS_SH_KILL="/bin/kill"
GLOBUS_SH_LN="/bin/ln"
GLOBUS_SH_LS="/bin/ls"
GLOBUS_SH_MKDIR="/bin/mkdir"
GLOBUS_SH_MKFIFO="/usr/bin/mkfifo"
GLOBUS_SH_MORE="/usr/bin/more"
GLOBUS_SH_MV="/bin/mv"
GLOBUS_SH_NETSTAT="/usr/sbin/netstat"
GLOBUS_SH_NSLOOKUP="/usr/bin/nslookup"
GLOBUS_SH_PRINTF="/usr/bin/printf"
GLOBUS_SH_PWD="/bin/pwd"
GLOBUS_SH_RM="/bin/rm"
GLOBUS_SH_SED="/usr/bin/sed"
GLOBUS_SH_SH="/bin/sh"
GLOBUS_SH_SLEEP="/bin/sleep"
GLOBUS_SH_SORT="/usr/bin/sort"
GLOBUS_SH_STTY="/bin/stty"
GLOBUS_SH_SU="/usr/bin/su"
GLOBUS_SH_TAIL="/usr/bin/tail"
GLOBUS_SH_TAR="/usr/bin/tar"
GLOBUS_SH_TEE="/usr/bin/tee"
GLOBUS_SH_TEST="/bin/test"
GLOBUS_SH_TOP="/usr/bin/top"
GLOBUS_SH_TOUCH="/usr/bin/touch"
GLOBUS_SH_TR="/usr/bin/tr"
GLOBUS_SH_UNAME="/usr/bin/uname"
GLOBUS_SH_UNIQ="/usr/bin/uniq"
GLOBUS_SH_UPTIME="/usr/bin/uptime"
GLOBUS_SH_WC="/usr/bin/wc"
GLOBUS_SH_WHOAMI="/usr/bin/whoami"
GLOBUS_SH_SUDO="/usr/bin/sudo"


#--
# OPTIONAL system section: needed only for DEC OSF
#
GLOBUS_SH_VMSTAT=""

#--
# OPTIONAL system section: needed only for HP-UX and Solaris
#
GLOBUS_SH_SYSINFO=""


#--
# OPTIONAL system section: needed only for IBM AIX
#
GLOBUS_SH_LSATTR=""
GLOBUS_SH_LSCFG=""
GLOBUS_SH_POE=""

#--
# OPTIONAL system section: needed only for CRAY T3E UNICOS
#
GLOBUS_SH_GRMVIEW=""

#--
# OPTIONAL system section: needed only for SGI IRIX
#
GLOBUS_SH_HINV=""

#--
# OPTIONAL system section: needed only for SUN SOLARIS
#
GLOBUS_SH_DMESG="/sbin/dmesg"


#--
# OPTIONAL jobmanager section: needed only if you plan to use  CONDOR
#
GLOBUS_SH_CONDOR_Q=""
GLOBUS_SH_CONDOR_RM=""
GLOBUS_SH_CONDOR_STATUS=""
GLOBUS_SH_CONDOR_SUBMIT=""


#--
# OPTIONAL jobmanager section: needed only if you plan to use  EASYMCS
#
GLOBUS_SH_SPFREE=""
GLOBUS_SH_SPQ=""
GLOBUS_SH_SPSUBMIT=""


#--
# OPTIONAL jobmanager section: needed only if you plan to use  GLUNIX
#
GLOBUS_SH_GLURUN=""
GLOBUS_SH_GLUSTAT=""


#--
# OPTIONAL jobmanager section: needed only if you plan to use  GLUNIX or PRUN
#
GLOBUS_SH_PRINTENV="/usr/bin/printenv"


#--
# OPTIONAL jobmanager section: needed only if you plan to use  LOADLEVELER
#
GLOBUS_SH_LLCANCEL=""
GLOBUS_SH_LLQ=""
GLOBUS_SH_LLSTATUS=""
GLOBUS_SH_LLSUBMIT=""


#--
# OPTIONAL jobmanager section: needed only if you plan to use  LSF
#
GLOBUS_SH_BJOBS=""
GLOBUS_SH_BKILL=""
GLOBUS_SH_BQUEUES=""
GLOBUS_SH_BSUB=""
GLOBUS_SH_LSHOSTS=""
GLOBUS_SH_LSLOAD=""


#--
# OPTIONAL jobmanager section: needed only if you plan to use  LSF  or  PBS
#
GLOBUS_SH_MPIRUN="/usr/bin/mpirun"


#--
# OPTIONAL jobmanager section: needed only if you plan to use  PBS, NQE or GRD
#
GLOBUS_SH_QDEL=""
GLOBUS_SH_QSTAT=""
GLOBUS_SH_QSUB=""

# these are only used for GRD
GLOBUS_SH_QSELECT=""
GLOBUS_SH_QHOST=""
GLOBUS_SH_QCONF=""


#--
# OPTIONAL jobmanager section: needed only if you plan to use  PEXEC
#
GLOBUS_SH_PEXEC=""
GLOBUS_SH_SHOWPART=""


#--
# OPTIONAL jobmanager section: needed only if you plan to use  PRUN
#
GLOBUS_SH_PKILL=""
GLOBUS_SH_POOL=""
GLOBUS_SH_PRESERVE=""
GLOBUS_SH_PRUN=""
GLOBUS_SH_PS="/bin/ps"










