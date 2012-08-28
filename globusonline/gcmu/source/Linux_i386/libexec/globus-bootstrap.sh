 

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


for file in 'globus_automake_pre' \
    'globus_automake_post' \
    'globus_automake_pre_top' \
    'globus_automake_post_top'
do
    if test ! -f "${file}" ; then
        if test -h "${file}" ; then
            rm ${file}
        fi
        echo "installing ${file} link"
        ln -s $GLOBUS_LOCATION/share/globus_aclocal/${file} ${file}
    fi
done

if test -d doxygen ; then

    for file in 'Doxyfile.in' \
	'Doxyfile-internal.in'
    do
	if test ! -h "doxygen/$file" ; then
	    echo "installing doxygen/$file link"
	    ln -s $GLOBUS_LOCATION/share/globus_aclocal/$file doxygen/$file
	fi
    done
    
    if test ! -h doxygen/Makefile.am ; then
	echo "installing Makefile.am link in doxygen"
	ln -s $GLOBUS_LOCATION/share/globus_aclocal/doxygen_Makefile.am \
	    doxygen/Makefile.am
    fi
fi


if test "x$GPT_LOCATION" = "x"; then
    GPT_LOCATION=$GLOBUS_LOCATION
fi

. ${GPT_LOCATION}/libexec/gpt-bootstrap.sh

# update stamp.h.in

if test -f "stamp-h.in" ; then
    touch stamp-h.in
fi
