#! /usr/bin/perl
#
# Copyright 1999-2010 University of Chicago
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


use strict;
use Globus::Core::Paths;

require 5.005;
use vars qw(@tests);

my $harness;
BEGIN {
    my $xmlfile;
    if (exists $ENV{CONTACT_LRM})
    {
        $xmlfile = "globus-gram-client-test-$ENV{CONTACT_LRM}.xml"
    }
    else
    {
        $xmlfile = "globus-gram-client-test.xml"
    }
    eval "use TAP::Harness::JUnit";
    if ($@)
    {
        eval "use TAP::Harness;";

        if ($@)
        {
            die "Unable to find JUnit TAP formatter";
        }
        else
        {
            $harness = TAP::Harness->new( {
                formatter_class => 'TAP::Formatter::JUnit',
                merge => 1
            } );
        }
        open(STDOUT, ">$xmlfile");
    }
    else
    {
        $harness = TAP::Harness::JUnit->new({
                                xmlfile => $xmlfile,
                                merge => 1});
    }
}

$|=1;

my $contact;
my $test_result=1;
my $kill_gatekeeper=0;
my $personal_gatekeeper = $Globus::Core::Paths::bindir
                        . "/globus-personal-gatekeeper";
@tests = qw(
    failed-job-two-phase-commit.pl
    globus-gram-client-activate-test.pl
    globus-gram-client-callback-contact-test.pl
    globus-gram-client-cancel-test.pl
    globus-gram-client-nonblocking-register-test.pl
    globus-gram-client-refresh-credentials-test.pl
    globus-gram-client-register-test.pl
    globus-gram-client-register-callback-test.pl
    globus-gram-client-register-cancel-test.pl
    globus-gram-client-ping-test.pl
    globus-gram-client-status-test.pl
    globus-gram-client-two-phase-commit-test.pl
    globus-gram-client-register-ping-test.pl
    globus-gram-client-stdio-size-test.pl
    job-status-with-info-test.pl
    register-version-test.pl
    restart-to-new-url-test.pl
    stdio-update-test.pl
    version-test.pl
    local-stdio-size-test.pl
    stdio-update-after-failure-test.pl
);

if(0 != system("$Globus::Core::Paths::bindir/grid-proxy-info -exists -hours 2 2>/dev/null") / 255)
{
    print STDERR "Unable to run tests: No Security Proxy\n";
}

if(exists($ENV{CONTACT_STRING}))
{
    print STDERR "Using gatekeeper at " . $ENV{CONTACT_STRING} . "\n";
    $kill_gatekeeper = 0;
}
else
{

    $contact = `$personal_gatekeeper -start -log never -disable-usagestats`;
    if($? != 0)
    {
	print STDERR "Could not start gatekeeper\n";
	exit 1;
    }
    chomp($contact);
    $contact =~ s/^GRAM contact: //;
    $ENV{CONTACT_STRING} = $contact;
    $kill_gatekeeper = 1;
}


$test_result = $harness->runtests(@tests);

sub END {
    if($kill_gatekeeper)
    {
        open(STDOUT, ">/dev/null");
	system {$personal_gatekeeper} ($personal_gatekeeper, '-kill', $contact);
    }
    exit 0
}
