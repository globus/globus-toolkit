#!/usr/bin/env perl

# ------------------------------------------------------------------------
# globus_test_gram_remote
# ------------------------------------------------------------------------

use strict;
use Utilities;

if ($ENV{'TEST_REMOTE'}) 
{
    test_gram_remote();
}

# ------------------------------------------------------------------------
# Test GRAM remote
# ------------------------------------------------------------------------
sub test_gram_remote 
{
    my $u = new Utilities();
    $u->announce("Testing GRAM remotely against host: ".$u->remote);

    my $gatekeeper_url = $u->remote;
    my $job_id;
    my $output;
    my $rc;
    my $year = (localtime)[5] + 1900;

    # cleanup

    $u->command("rm -rf \${HOME}/.globus/.gass_cache");

    ($rc, $output) = $u->command("globusrun -a -r \"$gatekeeper_url\"",1);
    $output =~ /GRAM Authentication test successful/ && $rc == 0 ?  
        $u->report("SUCCESS") : $u->report("FAILURE");

    # globus-job-run, no arguments

    ($rc, $output) = 
        $u->command("globus-job-run \"$gatekeeper_url\" /bin/date",1);
    $output =~ /$year/ && $rc == 0 ? 
        $u->report("SUCCESS") : $u->report("FAILURE");

    # globus-job-run, with arguments
    
    ($rc, $output) = 
        $u->command("globus-job-run \"$gatekeeper_url\" /bin/echo I ran",1);
    $output =~ /I ran/ && $rc == 0 ? 
        $u->report("SUCCESS") : $u->report("FAILURE");

    # globus-job-run with staging and arguments
    ($rc, $output) = 
        $u->command("globus-job-run \"$gatekeeper_url\" -s /bin/echo I ran",1);
    $output =~ /I ran/ && $rc == 0 ? 
        $u->report("SUCCESS") : $u->report("FAILURE");

    # globus-job-submit.  Store jobid in $job_id
    ($rc, $job_id) = 
        $u->command("globus-job-submit \"$gatekeeper_url\" /bin/echo I ran",1);

    # globus-job-get-output of stdout from gatekeeper_url of jobid $job_id.
    ($rc, $output) = $u->command("globus-job-get-output -resource " .
                                 "\"$gatekeeper_url\" $job_id", 1);
    $output =~ /I ran/ && $rc == 0 ? 
        $u->report("SUCCESS") : $u->report("FAILURE");

    # globus-job-clean on gatekeeper_url of jobid $job_id.
    ($rc, $output) = $u->command("globus-job-clean -force -resource " .
                                 "\"$gatekeeper_url\" $job_id", 1);
    $rc == 0 ? $u->report("SUCCESS") : $u->report("FAILURE");


    # globus-job-submit.  Store jobid in $job_id
    ($rc, $job_id) = 
        $u->command("globus-job-submit \"$gatekeeper_url\" " .
                    "/bin/sh -c \'/bin/echo I ran 1>&2\'",1);

    # globus-job-get-output of stderr from gatekeeper_url of jobid $job_id.
    ($rc, $output) = $u->command("globus-job-get-output -err -resource " .
                                 "\"$gatekeeper_url\" $job_id", 1);
    $output =~ /I ran/ && $rc == 0 ? 
        $u->report("SUCCESS") : $u->report("FAILURE");

    # globus-job-status from gatekeeper_url of jobid $job_id.
    ($rc, $output) = $u->command("globus-job-status $job_id", 1);
    $output =~ /DONE/ && $rc == 0 ? 
        $u->report("SUCCESS") : $u->report("FAILURE");


    # globus-job-clean on gatekeeper_url of jobid $job_id.
    ($rc, $output) = $u->command("globus-job-clean -force -resource " .
                                 "\"$gatekeeper_url\" $job_id", 1);
    $rc == 0 ? $u->report("SUCCESS") : $u->report("FAILURE");
 
    # globus-job-submit.  Store jobid in $job_id
    ($rc, $job_id) = 
        $u->command("globus-job-submit \"$gatekeeper_url\" " .
                    "/bin/sh -c \'echo I ran;sleep 120\'",1);

    # globus-job-status from gatekeeper_url of jobid $job_id.
    ($rc, $output) = $u->command("globus-job-status $job_id", 1);
    $output =~ /ACTIVE/ && $rc == 0 ? 
        $u->report("SUCCESS") : $u->report("FAILURE");
    
    # globus-job-cancel on gatekeeper_url of jobid $job_id.
    ($rc, $output) = $u->command("globus-job-cancel -force -resource " .
                                 "\"$gatekeeper_url\" $job_id", 1);
    $rc == 0 ? $u->report("SUCCESS") : $u->report("FAILURE");

    # globus-job-get-output of stdout from gatekeeper_url of jobid $job_id.
    ($rc, $output) = $u->command("globus-job-get-output -resource " .
                                 "\"$gatekeeper_url\" $job_id", 1);
    $output =~ /I ran/ && $rc == 0 ? 
        $u->report("SUCCESS") : $u->report("FAILURE");

    # globus-job-clean on gatekeeper_url of jobid $job_id.
    ($rc, $output) = $u->command("globus-job-clean -force -resource " .
                                 "\"$gatekeeper_url\" $job_id", 1);
    $rc == 0 ? $u->report("SUCCESS") : $u->report("FAILURE");
    
    # cleanup
 
    $u->command("rm -rf \${HOME}/.globus/.gass_cache");
}
