#!/usr/bin/env perl

# ------------------------------------------------------------------------
# globus_test_gram_local
# ------------------------------------------------------------------------

use strict;
use Utilities;
use POSIX;

test_gram_local();


# ------------------------------------------------------------------------
# Test GRAM local
# ------------------------------------------------------------------------
sub test_gram_local 
{
    my $u = new Utilities();
    $u->announce("Testing GRAM locally");

    my $gatekeeper_url;
    my $job_id;
    my $output;
    my $rc;
    my $year = (localtime)[5] + 1900;
    my $tmpfile = POSIX::tmpnam();

    # cleanup

    $u->command("globus-personal-gatekeeper -killall");
#    $u->command("rm -rf \${HOME}/.globus/.gass_cache");

    # start new personal gatekeeper

    $u->command("globus-personal-gatekeeper -start");
    ($rc, $gatekeeper_url) = $u->command("globus-personal-gatekeeper -list",1);

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
 
    my ($server_pid, $server_fd) = 
        $u->command_blocking("globus-gass-server -c");
    my $server_rc;
    my $server_output;
    my $server_url;
    
    while(<$server_fd>)
    {
        $server_output .= $_;
        if($_ =~ /^https/)
        {
            $server_url = $_;
            chomp($server_url);
            last;
        }
    }

    ($rc, $output) = 
        $u->command("globus-url-copy file:/etc/group $server_url$tmpfile",1);
    $rc == 0 ? $u->report("SUCCESS") : $u->report("FAILURE");

    ($rc, $output) = $u->command("diff /etc/group $tmpfile",1);
    $output eq "" && $rc == 0 ? $u->report("SUCCESS") : $u->report("FAILURE");

    # server-shutdown is stupid, it always returns non zero

    $u->command("globus-gass-server-shutdown $server_url");

    # the below will kill the server after 5 minutes

    ($server_rc, $server_output) .= $u->wait_command($server_pid,
                                                     $server_fd);
    if($server_rc != 0)
    {
        $u->report("FAILURE");
    }
    else
    {
        $u->report("SUCCESS");
    }

    # Cleanup

    $u->command("globus-personal-gatekeeper -killall");
 #   $u->command("rm -rf \${HOME}/.globus/.gass_cache");
}
