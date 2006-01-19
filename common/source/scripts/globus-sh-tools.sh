

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

if test -z "$GLOBUS_SH_VARIABLES_SET" ; then
    
    . ${GLOBUS_LOCATION}/libexec/globus-sh-tools-vars.sh
    
    # export all commands:

    for _var in `set|${GLOBUS_SH_GREP-grep} "^GLOBUS_SH"| \
        ${GLOBUS_SH_SED} -n '/^GLOBUS_SH/s/=.*$//p' `
    do
        export ${_var}
    done
    GLOBUS_SH_VARIABLES_SET="Y"
    export GLOBUS_SH_VARIABLES_SET


    # end of config file
fi






























