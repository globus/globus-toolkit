#!/usr/bin/env perl

BEGIN { push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl"); }

# ------------------------------------------------------------------------
# globus_test_gram_local
# ------------------------------------------------------------------------

use strict;
use Globus::Testing::Utilities;
use Globus::Core::Paths;
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
    my $job_id;
    my $output;
    my $rc = 0;
    my $rcx = 0;
    my $year = (localtime)[5] + 1900;
    my $tmpfile = POSIX::tmpnam();
    my $personal_gatekeeper = $Globus::Core::Paths::bindir
            . '/globus-personal-gatekeeper';
    my $arg_file;

    # start new personal gatekeeper
    $gatekeeper_url = `$personal_gatekeeper -start`;
    chomp $gatekeeper_url;
    $gatekeeper_url =~ s/GRAM contact: //;
    
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
    system {$personal_gatekeeper}
        ($personal_gatekeeper, '-kill', $gatekeeper_url);

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
