#!/usr/bin/env perl

BEGIN { push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl"); }

# ------------------------------------------------------------------------
# globus_test_gram_remote
# ------------------------------------------------------------------------

use strict;
use Globus::Testing::Utilities;

my $rc = 0;

if ($ENV{'TEST_REMOTE'}) 
{
    $rc = test_gram_remote();
}

exit (0 != $rc);

# ------------------------------------------------------------------------
# Test GRAM remote
# ------------------------------------------------------------------------
sub test_gram_remote 
{
    my $u = new Globus::Testing::Utilities();
    $u->announce("Testing GRAM remotely against host: ".$u->remote);

    my $gatekeeper_url = $u->remote;
    my $job_id;
    my $output;
    my $rc = 0;
    my $rcx = 0;
    my $year = (localtime)[5] + 1900;

    # cleanup

#    $u->command("rm -rf \${HOME}/.globus/.gass_cache");

    ($rcx, $output) = $u->command("globusrun -a -r \"$gatekeeper_url\"");
    $rc += check($output, "GRAM Authentication test successful",$rcx);

    # globus-job-run, no arguments

    ($rcx, $output) = 
        $u->command("globus-job-run \"$gatekeeper_url\" /bin/date");
    $rc += check($output, "$year", $rcx);

    # globus-job-run, with arguments
    
    ($rcx, $output) = 
        $u->command("globus-job-run \"$gatekeeper_url\" /bin/echo I ran");
    $rc += check($output, "I ran", $rcx);

    # globus-job-run with staging and arguments
    ($rcx, $output) = 
        $u->command("globus-job-run \"$gatekeeper_url\" -s /bin/echo I ran");
    $rc += check($output, "I ran", $rcx);

    # globus-job-submit.  Store jobid in $job_id
    ($rcx, $job_id) = 
        $u->command("globus-job-submit \"$gatekeeper_url\" /bin/echo I ran");
    $rc += check $rcx;
    
    # globus-job-get-output of stdout from gatekeeper_url of jobid $job_id.
    ($rcx, $output) = $u->command("globus-job-get-output -resource " .
                                 "\"$gatekeeper_url\" $job_id");
    $rc += check($output, "I ran", $rcx);

    # globus-job-clean on gatekeeper_url of jobid $job_id.
    ($rcx, $output) = $u->command("globus-job-clean -force -resource " .
                                 "\"$gatekeeper_url\" $job_id");
    $rc += check("", "", $rcx);


    # globus-job-submit.  Store jobid in $job_id
    ($rcx, $job_id) = 
        $u->command("globus-job-submit \"$gatekeeper_url\" " .
                    "/bin/sh -c \'/bin/echo I ran 1>&2\'");
    $rc += check $rcx;

    # globus-job-get-output of stderr from gatekeeper_url of jobid $job_id.
    ($rcx, $output) = $u->command("globus-job-get-output -err -resource " .
                                 "\"$gatekeeper_url\" $job_id");
    $rc += check($output, "I ran", $rcx);

    # globus-job-status from gatekeeper_url of jobid $job_id.
    ($rcx, $output) = $u->command("globus-job-status $job_id");
    $rc += check($output, "DONE", $rcx);


    # globus-job-clean on gatekeeper_url of jobid $job_id.
    ($rcx, $output) = $u->command("globus-job-clean -force -resource " .
                                 "\"$gatekeeper_url\" $job_id");
    $rc += check("", "", $rcx);
 
    # globus-job-submit.  Store jobid in $job_id
    ($rcx, $job_id) = 
        $u->command("globus-job-submit \"$gatekeeper_url\" " .
                    "/bin/sh -c \'echo I ran;sleep 120\'");

    # without sleeping the job status is UNSUBMITTED and not ACTIVE
    sleep(5);

    # globus-job-status from gatekeeper_url of jobid $job_id.
    ($rcx, $output) = $u->command("globus-job-status $job_id");
    $rc += check($output, "ACTIVE", $rcx);
    
    # globus-job-cancel on gatekeeper_url of jobid $job_id.
    ($rcx, $output) = $u->command("globus-job-cancel -force -resource " .
                                 "\"$gatekeeper_url\" $job_id");
    $rc += check("", "", $rcx);

    # globus-job-get-output of stdout from gatekeeper_url of jobid $job_id.
    ($rcx, $output) = $u->command("globus-job-get-output -resource " .
                                 "\"$gatekeeper_url\" $job_id");
    $rc += check($output, "I ran", $rcx);

    # globus-job-clean on gatekeeper_url of jobid $job_id.
    ($rcx, $output) = $u->command("globus-job-clean -force -resource " .
                                 "\"$gatekeeper_url\" $job_id");
    $rc += check("", "", $rcx);
    
    # cleanup
 
    $u->command("rm -rf \${HOME}/.globus/.gass_cache");
    return $rc;
}

sub check
{
    my $stringToCheck = shift;
    my $expectedString = shift;
    my $rcx = shift;
    my $u = new Globus::Testing::Utilities(); 
    if ($stringToCheck =~ /$expectedString/ && $rcx == 0)
    {
        $u->report("SUCCESS")
    }
    else
    {
        $u->report("FAILURE");
        $rcx = 1;
    }
    return $rcx;
}
