

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

MP=""
MP_INCLUDES=""
MP_LIBS=""

CC="/usr/bin/gcc"
CPP="/usr/bin/gcc -E"
CPPFLAGS=" -I/tmp/scratch/gt/include -I/tmp/scratch/gt/include/gcc32"
CFLAGS="-O   -Wall"


LDFLAGS=" -L/tmp/scratch/gt/lib"
LIBS=" "
STATIC_LDFLAGS="@STATIC_LDFLAGS@" 

CXX="/usr/bin/g++"
CXXCPP="/usr/bin/g++ -E"
CXXFLAGS="-O  "

INSURE=""

F77="/usr/bin/g77"
F77FLAGS=" "

F90=""
F90FLAGS=" "

AR="/usr/bin/ar"
ARFLAGS="ruv"
RANLIB="/usr/bin/ranlib"

NM="/usr/bin/nm -B"

PERL="/usr/bin/perl"

OBJEXT="o"
EXEEXT=""

OBJECT_MODE=""

CROSS="no"
cross_compiling=${CROSS}

GLOBUS_THREADS="none"
GLOBUS_HOST="i686-pc-linux-gnu"
GLOBUS_DEBUG="no"
