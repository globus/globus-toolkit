#!/usr/bin/env perl

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


BEGIN { push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl"); }

# ------------------------------------------------------------------------
# globus_test_gridftp_remote
# ------------------------------------------------------------------------

use POSIX;
use strict;
use Globus::Testing::Utilities;

if ($ENV{'TEST_REMOTE'}) 
{
    test_gridftp_remote();
}

# ------------------------------------------------------------------------
# Test GridFTP remote
# ------------------------------------------------------------------------
sub test_gridftp_remote 
{
    my $u = new Utilities();
    $u->announce("Testing GridFTP remotely");

    my $output;
    my $remote = $u->remote;
    my $hostname = $u->hostname;
    my $tmpfile = POSIX::tmpnam();
    my $rc;

    $rc = $u->command("globus-url-copy \\
        gsiftp://$remote/etc/group \\
        gsiftp://$hostname$tmpfile",5);
    $rc == 0 ? $u->report("SUCCESS") : $u->report("FAILURE");

    $u->command("rm -f $tmpfile");
}
