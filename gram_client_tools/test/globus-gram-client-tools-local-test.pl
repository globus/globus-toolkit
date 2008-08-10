#!/usr/bin/env perl

BEGIN { push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl"); }

# ------------------------------------------------------------------------
# globus_test_gram_local
# ------------------------------------------------------------------------

use strict;
use Globus::Testing::Utilities;
use POSIX;
use IO::File;

my $u = new Globus::Testing::Utilities(); 

exit (0 != test_gram_local());

# ------------------------------------------------------------------------
# Test GRAM local
# ------------------------------------------------------------------------
sub test_gram_local 
{
    $u->announce("Testing GRAM locally");

    my $gatekeeper_url;
    my $gk_pid;
    my $gk_fd;
    my $job_id;
    my $output;
    my $rc = 0;
    my $rcx = 0;
    my $year = (localtime)[5] + 1900;
    my $tmpfile = POSIX::tmpnam();
    my $arg_file;

    # cleanup

    $u->command("globus-personal-gatekeeper -killall");
#    $u->command("rm -rf \${HOME}/.globus/.gass_cache");

    # start new personal gatekeeper

    ($gk_pid, $gk_fd) = 
        $u->command_blocking("globus-personal-gatekeeper -start");

    sleep(5);
    
    ($rcx, $gatekeeper_url) = $u->command("globus-personal-gatekeeper -list");
    $rc += check("", "", $rcx);

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

    # globus-job-run, with arguments from a file
    $arg_file = new IO::File(">$tmpfile");
    $arg_file->print("\"$gatekeeper_url\" /bin/echo I ran\n");
    $arg_file->close();

    ($rcx, $output) = 
        $u->command("globus-job-run -file \"$tmpfile\"\n");
    $rc += check($output, "I ran", $rcx);

    # truncate temp file
    $arg_file = new IO::File(">$tmpfile");
    $arg_file->close();

    # globus-job-run with staging and arguments
    ($rcx, $output) = 
        $u->command("globus-job-run \"$gatekeeper_url\" -s /bin/echo I ran");
    $rc += check($output, "I ran", $rcx);
    
    # globus-job-submit.  Store jobid in $job_id
    ($rcx, $job_id) = 
        $u->command("globus-job-submit \"$gatekeeper_url\" /bin/echo I ran");

    if($rcx == 0)
    {
        # globus-job-get-output of stdout from gatekeeper_url of jobid $job_id.
        ($rcx, $output) = $u->command("globus-job-get-output -resource " .
                                     "\"$gatekeeper_url\" $job_id");
        $rc += check($output, "I ran", $rcx);
        
        # globus-job-clean on gatekeeper_url of jobid $job_id.
        ($rcx, $output) = $u->command("globus-job-clean -force -resource " .
                                     "\"$gatekeeper_url\" $job_id");
        $rc += check("", "", $rcx);
    }
    else
    {
        $u->report("FAILURE");
        $rc += $rcx;
    }
        
    # globus-job-submit.  Store jobid in $job_id
    ($rcx, $job_id) = 
        $u->command("globus-job-submit \"$gatekeeper_url\" " .
                    "/bin/sh -c \'/bin/echo I ran 1>&2\'");
    if($rcx == 0)
    {   
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
    }
    else
    {
        $u->report("FAILURE");
        $rc += $rcx;
    }
  
    # globus-job-submit.  Store jobid in $job_id
    ($rcx, $job_id) = 
        $u->command("globus-job-submit \"$gatekeeper_url\" " .
                    "/bin/sh -c \'echo I ran;sleep 120\'");

    if($rcx == 0)
    {
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
    }
    else
    {
        $u->report("FAILURE");
        $rc += $rcx;
    }
 
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

    ($rcx, $output) = 
        $u->command("globus-url-copy file:/etc/group $server_url$tmpfile");
    
    if($rcx == 0)
    {
        $u->report("SUCCESS");

        ($rcx, $output) = $u->command("diff /etc/group $tmpfile");
        $rc += check($output, "", $rcx);
        
        $u->command("rm -rf $tmpfile");
        
        # server-shutdown is stupid, it always returns non zero
        $u->command("globus-gass-server-shutdown $server_url");
    }
    else
    {
        $u->report("FAILURE");
        $rc += $rcx;
    }

    # the below will kill the server after 5 minutes
    ($server_rc, $server_output) .= $u->wait_command($server_pid,
                                                     $server_fd);
    if($server_rc != 0)
    {
        $u->report("FAILURE");
        $rc += $server_rc;
    }
    else
    {
        $u->report("SUCCESS");
    }
 
    # Cleanup
    $u->command("globus-personal-gatekeeper -killall");
    waitpid($gk_pid,0);
    close($gk_fd);

 #   $u->command("rm -rf \${HOME}/.globus/.gass_cache");
    return $rc;
}

sub check
{
    my $stringToCheck = shift;
    my $expectedString = shift;
    my $rcx = shift;
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