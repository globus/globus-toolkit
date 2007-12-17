#!/usr/bin/env perl

use strict;
require 5.005;

push(@INC, $ENV{GLOBUS_LOCATION} . "/test/globus_gridftp_server_test");

require "gfs_common.pl";

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

my  $subject = gfs_setup_security_env();
my $test_ndx = 0;
my $pid;
my $cs;
my $cnt=0;
($pid,$cs,$test_ndx) = gfs_next_test($test_ndx);
while($test_ndx >= 0)
{
    my $rc = system('./globus-ftp-client-run-tests.pl');
    if($rc != 0)
    {
        exit $rc;
    }
    ($pid,$cs,$test_ndx) = gfs_next_test($test_ndx);
}

exit 0;
