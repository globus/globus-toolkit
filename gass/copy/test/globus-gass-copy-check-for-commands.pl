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
# globus_test_check_for_commands
# ------------------------------------------------------------------------

use strict;
use Globus::Testing::Utilities;

check_for_commands();


# ------------------------------------------------------------------------
# Check for commands
# ------------------------------------------------------------------------
sub check_for_commands 
{
    my $rc;
    my $output;
    my $u = new Utilities;
    $u->announce("Checking for commands");
    
    my @commands = 
        qw(
           grid-cert-info
           grid-cert-request
           grid-change-pass-phrase
           grid-proxy-init
           globus-hostname
           globus-url-copy
           grid-proxy-destroy
           grid-proxy-info
           grid-proxy-init
           grid-mapfile-add-entry          
           grid-mapfile-delete-entry
           grid-mapfile-check-consistency
           globus-gridftp-server
           );
    
    foreach my $command (@commands) 
    {
        ($rc, $output) = $u->command("which $command");
        if (-x "$output") 
        {
            $u->report("SUCCESS");
        }
        else 
        {
            $u->report("FAILURE");
        }
    }
}   
