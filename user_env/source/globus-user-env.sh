

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

#
# source this file to properly set up your environment for globus applications
# this requires that GLOBUS_LOCATION be set.
# GLOBUS_PATH will be set by this script to save the current location,
# should you decide to change GLOBUS_LOCATION to a different location and
# re source this script, the old GLOBUS_PATH information will be removed from
# your environment before applying the new GLOBUS_LOCATION
#

if [ -z "${GLOBUS_LOCATION}" ]; then
    echo "ERROR: environment variable GLOBUS_LOCATION not defined"  1>&2
    return 1
fi

if [ -n "${GLOBUS_PATH}" ]; then
    PATH=`echo "${PATH}" | sed -e "s%:${GLOBUS_PATH}[^:]*%%g" -e "s%^${GLOBUS_PATH}[^:]*:\{0,1\}%%"`
    LD_LIBRARY_PATH=`echo "${LD_LIBRARY_PATH}" | sed -e "s%:${GLOBUS_PATH}[^:]*%%g" -e "s%^${GLOBUS_PATH}[^:]*:\{0,1\}%%"`
    DYLD_LIBRARY_PATH=`echo "${DYLD_LIBRARY_PATH}" | sed -e "s%:${GLOBUS_PATH}[^:]*%%g" -e "s%^${GLOBUS_PATH}[^:]*:\{0,1\}%%"`
    LIBPATH=`echo "${LIBPATH}" | sed -e "s%:${GLOBUS_PATH}[^:]*%%g" -e "s%^${GLOBUS_PATH}[^:]*:\{0,1\}%%"`
    SHLIB_PATH=`echo "${SHLIB_PATH}" | sed -e "s%:${GLOBUS_PATH}[^:]*%%g" -e "s%^${GLOBUS_PATH}[^:]*:\{0,1\}%%"`
    if [ -n "${SASL_PATH}" ]; then
        SASL_PATH=`echo "${SASL_PATH}" | sed -e "s%:${GLOBUS_PATH}[^:]*%%g" -e "s%^${GLOBUS_PATH}[^:]*:\{0,1\}%%"`
    fi
    if [ -n "${MANPATH}" ]; then
        MANPATH=`echo "${MANPATH}" | sed -e "s%:${GLOBUS_PATH}[^:]*%%g" -e "s%^${GLOBUS_PATH}[^:]*:\{0,1\}%%"`
    fi
    if [ -n "${LD_LIBRARYN32_PATH}" ]; then
        LD_LIBRARYN32_PATH=`echo "${LD_LIBRARYN32_PATH}" | sed -e "s%:${GLOBUS_PATH}[^:]*%%g" -e "s%^${GLOBUS_PATH}[^:]*:\{0,1\}%%"`
    fi
    if [ -n "${LD_LIBRARY64_PATH}" ]; then
        LD_LIBRARY64_PATH=`echo "${LD_LIBRARY64_PATH}" | sed -e "s%:${GLOBUS_PATH}[^:]*%%g" -e "s%^${GLOBUS_PATH}[^:]*:\{0,1\}%%"`
    fi
    if [ -n "${PERL5LIB}" ]; then
        PERL5LIB=`echo "${PERL5LIB}" | sed -e "s%:${GLOBUS_PATH}[^:]*%%g" -e "s%^${GLOBUS_PATH}[^:]*:\{0,1\}%%"`
    fi
fi

PATH=`echo "${PATH}" | sed -e "s%:${GLOBUS_LOCATION}[^:]*%%g" -e "s%^${GLOBUS_LOCATION}[^:]*:\{0,1\}%%"`
DYLD_LIBRARY_PATH=`echo "${DYLD_LIBRARY_PATH}" | sed -e "s%:${GLOBUS_LOCATION}[^:]*%%g" -e "s%^${GLOBUS_LOCATION}[^:]*:\{0,1\}%%"`
LIBPATH=`echo "${LIBPATH}" | sed -e "s%:${GLOBUS_LOCATION}[^:]*%%g" -e "s%^${GLOBUS_LOCATION}[^:]*:\{0,1\}%%"`
SHLIB_PATH=`echo "${SHLIB_PATH}" | sed -e "s%:${GLOBUS_LOCATION}[^:]*%%g" -e "s%^${GLOBUS_LOCATION}[^:]*:\{0,1\}%%"`
if [ -n "${SASL_PATH}" ]; then
    SASL_PATH=`echo "${SASL_PATH}" | sed -e "s%:${GLOBUS_LOCATION}[^:]*%%g" -e "s%^${GLOBUS_LOCATION}[^:]*:\{0,1\}%%"`
fi
if [ -n "${MANPATH}" ]; then
    MANPATH=`echo "${MANPATH}" | sed -e "s%:${GLOBUS_LOCATION}[^:]*%%g" -e "s%^${GLOBUS_LOCATION}[^:]*:\{0,1\}%%"`
fi
if [ -n "${LD_LIBRARYN32_PATH}" ]; then
    LD_LIBRARYN32_PATH=`echo "${LD_LIBRARYN32_PATH}" | sed -e "s%:${GLOBUS_LOCATION}[^:]*%%g" -e "s%^${GLOBUS_LOCATION}[^:]*:\{0,1\}%%"`
fi
if [ -n "${LD_LIBRARY64_PATH}" ]; then
    LD_LIBRARY64_PATH=`echo "${LD_LIBRARY64_PATH}" | sed -e "s%:${GLOBUS_LOCATION}[^:]*%%g" -e "s%^${GLOBUS_LOCATION}[^:]*:\{0,1\}%%"`
fi
if [ -n "${PERL5LIB}" ]; then
    PERL5LIB=`echo "${PERL5LIB}" | sed -e "s%:${GLOBUS_LOCATION}[^:]*%%g" -e "s%^${GLOBUS_LOCATION}[^:]*:\{0,1\}%%"`
fi


GLOBUS_PATH=${GLOBUS_LOCATION}
PATH="${GLOBUS_LOCATION}/bin:${GLOBUS_LOCATION}/sbin:${PATH}";

if [ -n "${MANPATH}" ]; then
    MANPATH="${GLOBUS_LOCATION}/man:${MANPATH}"
fi

DELIM=
if [ -n "${LD_LIBRARY_PATH}" ]; then
    DELIM=:
fi
LD_LIBRARY_PATH="${GLOBUS_LOCATION}/lib${DELIM}${LD_LIBRARY_PATH}"

DELIM=
if [ -n "${DYLD_LIBRARY_PATH}" ]; then
    DELIM=:
fi
DYLD_LIBRARY_PATH="${GLOBUS_LOCATION}/lib${DELIM}${DYLD_LIBRARY_PATH}"

if [ -z "${LIBPATH}" ]; then
    LIBPATH="/usr/lib:/lib"
fi
LIBPATH="${GLOBUS_LOCATION}/lib:${LIBPATH}"

DELIM=
if [ -n "${SHLIB_PATH}" ]; then
    DELIM=:
fi
SHLIB_PATH="${GLOBUS_LOCATION}/lib${DELIM}${SHLIB_PATH}"

if [ -d $GLOBUS_LOCATION/lib/sasl ]; then
    DELIM=
    if [ -n "${SASL_PATH}" ]; then
        DELIM=:
    fi
    SASL_PATH="${GLOBUS_LOCATION}/lib/sasl${DELIM}${SASL_PATH}"
fi

export GLOBUS_PATH PATH MANPATH LD_LIBRARY_PATH DYLD_LIBRARY_PATH LIBPATH SHLIB_PATH SASL_PATH

if [ -n "${LD_LIBRARYN32_PATH}" ]; then
    DELIM=""
    if [ "X${LD_LIBRARYN32_PATH}" != "X" ]; then
        DELIM=:
    fi
    LD_LIBRARYN32_PATH="${GLOBUS_LOCATION}/lib${DELIM}${LD_LIBRARYN32_PATH}"
    export LD_LIBRARYN32_PATH
fi

if [ -n "${LD_LIBRARY64_PATH}" ]; then
    DELIM=""
    if [ "X${LD_LIBRARY64_PATH}" != "X" ]; then
        DELIM=:
    fi
    LD_LIBRARY64_PATH="${GLOBUS_LOCATION}/lib${DELIM}${LD_LIBRARY64_PATH}"
    export LD_LIBRARY64_PATH
fi

if [ -n "${PERL5LIB}" ]; then
    DELIM=""
    if [ "X${PERL5LIB}" != "X" ]; then
        DELIM=:
    fi
    PERL5LIB="${GLOBUS_LOCATION}/lib/perl${DELIM}${PERL5LIB}"
    export PERL5LIB
fi


