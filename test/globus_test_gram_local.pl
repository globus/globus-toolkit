#!/usr/bin/env perl

# ------------------------------------------------------------------------
# globus_test_gram_local
# ------------------------------------------------------------------------

use strict;
use Utilities;

test_gram_local();


# ------------------------------------------------------------------------
# Test GRAM local
# ------------------------------------------------------------------------
sub test_gram_local {
    my $u = new Utilities();
    $u->announce("Testing GRAM locally");

    my $gatekeeper_url;
    my $output;

#    $u->command(". env.sh");

    $u->command("globus-personal-gatekeeper -killall");
    $u->command("globus-personal-gatekeeper -start");
    $gatekeeper_url = $u->command("globus-personal-gatekeeper -list",1);

    $output = $u->command("globusrun -a -r \"$gatekeeper_url\"",1);
    $output =~ /GRAM Authentication test successful/ ?  $u->report("SUCCESS") : $u->report("FAILURE");

    # globus-job-run, no arguments
    # XXX Don't look for the current year!
    $output = $u->command("globus-job-run \"$gatekeeper_url\" /bin/date",1);
    $output =~ /2002/ ? $u->report("SUCCESS") : $u->report("FAILURE");

    # globus-job-run, with arguments
    $output = $u->command("globus-job-run \"$gatekeeper_url\" /bin/echo I ran",1);
    $output =~ /I ran/ ? $u->report("SUCCESS") : $u->report("FAILURE");

    # globus-job-run with staging and arguments
    $output = $u->command("globus-job-run \"$gatekeeper_url\" -s /bin/echo I ran",1);
    $output =~ /I ran/ ? $u->report("SUCCESS") : $u->report("FAILURE");

    # globus-job-submit.  Store jobid in $output
    $output = $u->command("globus-job-submit \"$gatekeeper_url\" /bin/echo I ran",1);

    # globus-job-get-output from gatekeeper_url of jobid $output.
    $output = $u->command("globus-job-get-output -resource \"$gatekeeper_url\" $output", 1);
    $output =~ /I ran/ ? $u->report("SUCCESS") : $u->report("FAILURE");
 
    #Consider changing this to not use a temp file, if possible.
    $u->command("globus-gass-server 1> /tmp/g-g-s-test &");
    $u->command("sleep 1");
    $output = $u->command("grep https /tmp/g-g-s-test",1);

    $u->command("globus-url-copy file:///etc/termcap $output/tmp/termcap");
    $output = $u->command("diff /etc/termcap /tmp/termcap",1);
    $output eq "" ? $u->report("SUCCESS") : $u->report("FAILURE");

    # Do I actually care here?  If it wasn't running, above will error
    # anyway
    $u->command("killall globus-gass-server",0,1);
    $u->command("globus-personal-gatekeeper -killall");
}
