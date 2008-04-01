#!/usr/bin/env perl

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
    my $u = new Globus::Testing::Utilities(); 
    $u->announce("Checking for commands");
    
    my @commands = 
        qw(
           grid-proxy-init
           globusrun
           globus-job-run
           globus-job-submit
           globus-hostname
           globus-job-cancel
           globus-job-clean
           globus-job-get-output
           globus-job-status
           globus-personal-gatekeeper
           globus-gatekeeper
           grid-cert-info
           grid-cert-request
           grid-change-pass-phrase
           grid-proxy-destroy
           grid-proxy-info
           grid-proxy-init
           grid-mapfile-add-entry          
           grid-mapfile-delete-entry
           grid-mapfile-check-consistency
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
