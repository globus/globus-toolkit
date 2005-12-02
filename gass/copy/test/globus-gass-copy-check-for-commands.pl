#!/usr/bin/env perl

#
# Portions of this file Copyright 1999-2005 University of Chicago
# Portions of this file Copyright 1999-2005 The University of Southern California.
#
# This file or a portion of this file is licensed under the
# terms of the Globus Toolkit Public License, found at
# http://www.globus.org/toolkit/download/license.html.
# If you redistribute this file, with or without
# modifications, you must include this notice in the file.
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
