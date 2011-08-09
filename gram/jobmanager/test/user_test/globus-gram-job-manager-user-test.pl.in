#! /usr/bin/perl

@GLOBUS_PERL_INITIALIZER@

use Globus::GRAM::Error;
use Globus::Core::Paths;
use IO::File;
use Test::More;

my (@tests) = ();
my $contact = $ENV{CONTACT_STRING};
my $testdatadir = $0;
if ($testdatadir =~ m|/|)
{
    $testdatadir =~ s|/+[^/]*$||;
}
else
{
    $testdatadir = '.';
}
my $verbose = 0;
my $me = (getpwuid($<))[0];

sub test_user
{
    my $username = shift;
    my $result = shift;
    my $rc;
    my $rsl = '&(executable=/usr/bin/whoami)';
    my $output;

    if ($username ne '') {
        $rsl .= "(username=$username)";
    } else {
        $username = $me;
    }
    if($verbose)
    {
	print "# Submitting job: $rsl\n";
    }

    {
        local(*OLDERR, *PIPE);
        local($/);

        open(OLDERR, ">&STDERR");
        open(STDERR, ">/dev/null");

        open(PIPE, "-|",
                "$Globus::Core::Paths::bindir/globusrun",
                "-s", "-r", $contact, $rsl);
        $output = <PIPE>;
        open(STDERR, ">&OLDERR");
        close(OLDERR);
        close(PIPE);
    }
    chomp($output);

    $rc = $? >> 8;

    if ($rc != 0) {
        $username = '';
    }

    ok("$output:$rc" eq "$username:$result", "test_user_$me");
}

push(@tests, "test_user('', 0)");
push(@tests, "test_user('$me', 0)"),
push(@tests, "test_user('$me'.'x',
                    Globus::GRAM::Error::AUTHORIZATION->value)");

if(@ARGV)
{
    my @doit;

    $verbose = 1;

    foreach(@ARGV)
    {
        if(/^(\d+)-(\d+)$/)
        {
            foreach($1 .. $2)
            {
               push(@doit, $_);
            }
        }
        elsif(/^(\d+)$/)
        {
            push(@doit, $1);
        }
    }
    plan tests => scalar(@doit);

    foreach (@doit)
    {
        eval "&$tests[$_-1]";
    }
}
else
{
    plan tests => scalar(@tests);

    foreach (@tests)
    {
	eval "&$_";
    }
}
