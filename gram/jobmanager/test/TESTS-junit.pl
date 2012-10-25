#! /usr/bin/perl

require 5.005;

use strict;
use Globus::Core::Paths;
use vars qw(@tests);

my $harness;
BEGIN {
    my $xmlfile;

    if (exists $ENV{CONTACT_LRM})
    {
        $xmlfile = "globus-gram-job-manager-test-$ENV{CONTACT_LRM}.xml",
    }
    else
    {
        $xmlfile = "globus-gram-job-manager-test.xml",
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

my $test_result = 1;
my $kill_gatekeeper = 0;
my $personal_gatekeeper = $Globus::Core::Paths::bindir
                        . "/globus-personal-gatekeeper";
$|=1;

my $contact;
my @startargs = qw(-log never -disable-usagestats);

my $testdir = $0;
if ($testdir =~ m|/|)
{
    $testdir =~ s|/+[^/]*$||;
}
else
{
    $testdir = ".";
}
chdir $testdir;

@tests = qw(job-manager-script-test.pl);

if (-d 'stdio_test')
{
    push(@tests, 'stdio_test/globus-gram-job-manager-stdio-test.pl');
}
else
{
    push(@tests, 'globus-gram-job-manager-stdio-test.pl');
}

if (-d 'submit_test')
{
    push(@tests, 'submit_test/globus-gram-job-manager-submit-test.pl');
}
else
{
    push(@tests, 'globus-gram-job-manager-submit-test.pl');
}
if (-d 'failure_test')
{
    push(@tests, 'failure_test/globus-gram-job-manager-failure-test.pl');
}
else
{
    push(@tests, 'globus-gram-job-manager-failure-test.pl');
}

if (-d 'rsl_size_test')
{
    push(@tests, 'rsl_size_test/globus-gram-job-manager-rsl-size-test.pl');
}
else
{
    push(@tests, 'globus-gram-job-manager-rsl-size-test.pl');
}

if (-d 'user_test')
{
    push(@tests, 'user_test/globus-gram-job-manager-user-test.pl');
}
else
{
    push(@tests, 'globus-gram-job-manager-user-test.pl');
}

if(0 != system("$Globus::Core::Paths::bindir/grid-proxy-info -exists -hours 2 2>/dev/null") / 255)
{
    print STDERR "No valid proxy---unable to run tests.\n";
    exit 1;
}

if(@ARGV)
{
    push(@startargs, @ARGV);
}

if(exists($ENV{CONTACT_STRING}))
{
    print "Using gatekeeper at " . $ENV{CONTACT_STRING} . "\n";
    $kill_gatekeeper = 0;
}
else
{
    local(*PG);
    open(PG, "-|", $personal_gatekeeper, '-start', @startargs);
    $contact = <PG>;
    close(PG);
    if($? != 0)
    {
	print "Could not start gatekeeper\n";
	exit 1;
    }
    chomp($contact);
    $contact =~ s/^GRAM contact:\s*//;
    $ENV{CONTACT_STRING} = $contact;
    $kill_gatekeeper = 1;
}

$harness->runtests(@tests);

sub END {
    if($kill_gatekeeper)
    {
        open(STDOUT, '>/dev/null'); 
        system { $personal_gatekeeper } ($personal_gatekeeper, '-kill', $contact);
    }
}
