#!/usr/bin/perl

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


use strict;
require 5.005;
use vars qw(@tests);

my $harness;
BEGIN {
    my $xmlfile = "globus-common-test.xml";

    eval "use TAP::Harness::JUnit";
    if ($@)
    {
        eval "use TAP::Harness;";

        if ($@)
        {
            die "Unable to find JUnit TAP formatter";
        }
        else
        {
            $harness = TAP::Harness->new( {
                formatter_class => 'TAP::Formatter::JUnit',
                merge => 1
            } );
        }
        open(STDOUT, ">$xmlfile");
    }
    else
    {
        $harness = TAP::Harness::JUnit->new({
                                xmlfile => $xmlfile,
                                merge => 1});
    }
}

@tests = qw( globus-common-args-test.pl
	     globus-common-error-test.pl
             globus-common-mem-test.pl
	     globus-common-module-test.pl
	     globus-common-poll-test.pl 
             globus-common-thread-test.pl
	     globus-common-timedwait-test.pl
	     globus-common-url-test.pl
	     globus-common-error-stg-test.pl
	     globus-common-hash-test.pl
	     globus-common-fifo-test.pl
	     globus-common-strptime-test.pl
	     globus-common-handle-table-test.pl
	     globus-common-libcsetenv-test.pl
	     globus-common-list-test.pl
             globus-common-uuid-test.pl
             globus-common-largefile-test.pl
	     );

$harness->runtests(@tests);
