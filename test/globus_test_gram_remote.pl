#!/usr/bin/env perl

# ------------------------------------------------------------------------
# globus_test_gram_remote
# ------------------------------------------------------------------------

use strict;
use Utilities;

if ($ENV{'TEST_REMOTE'}) {
    test_gram_remote();
}

# ------------------------------------------------------------------------
# Test GRAM remote
# ------------------------------------------------------------------------
sub test_gram_remote {
    my $u = new Utilities();
    $u->announce("Testing GRAM remotely against host: ".$u->remote);

    my $output;
    my $remote = $u->remote;

    $u->command(". env.sh");

    $output = $u->command("globusrun -a -r $remote",1);
    $output =~ /GRAM Authentication test successful/ ?  $u->report("SUCCESS") : $u->report("FAILURE");

    $output = $u->command("globusrun -a -r \"$remote\"",1);
    $output =~ /GRAM Authentication test successful/ ?  $u->report("SUCCESS") : $u->report("FAILURE"); 

    # globus-job-run, no arguments
    # XXX Don't look for the current year!
    $output = $u->command("globus-job-run \"$remote\" /bin/date",1);
    $output =~ /2002/ ? $u->report("SUCCESS") : $u->report("FAILURE");

    # globus-job-run, with arguments
    $output = $u->command("globus-job-run \"$remote\" /bin/echo I ran",1);
    $output =~ /I ran/ ? $u->report("SUCCESS") : $u->report("FAILURE");

    # globus-job-run with staging and arguments
    $output = $u->command("globus-job-run \"$remote\" -s /bin/echo I ran",1);
    $output =~ /I ran/ ? $u->report("SUCCESS") : $u->report("FAILURE");

    # globus-job-submit.  Store jobid in $output
    $output = $u->command("globus-job-submit \"$remote\" /bin/echo I ran",1);

    # globus-job-get-output from u->remote of jobid $output.
    $output = $u->command("globus-job-get-output -resource \"$remote\" $output", 1);
    $output =~ /I ran/ ? $u->report("SUCCESS") : $u->report("FAILURE");
 
    #Consider changing this to not use a temp file, if possible.
    #$u->command("globus-gass-server 1> /tmp/g-g-s-test &");
    #$u->command("sleep 1");
    #$output = $u->command("grep https /tmp/g-g-s-test",1);
}
