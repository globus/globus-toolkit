#! /usr/bin/env perl 

=head1 globus-ftp-client-exist-test

Tests to exercise the existence checking of the client library.

=cut

use strict;
use POSIX;
use Test;

my $test_exec = $ENV{GLOBUS_LOCATION} . '/test/' . 'globus-ftp-client-exist-test';
my @tests;

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

sub check_existence
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);
    my ($old_proxy);
    my $src_url = shift;
    my $existence_rc = shift;

    unlink('core', $tmpname);

    $rc = system("$test_exec -s $src_url 2>/dev/null") / 256;
    if($rc != $existence_rc)
    {
        $errors .= "Test exited with $rc. ";
    }
    if(-r 'core')
    {
        $errors .= "\n# Core file generated.";
    }

    if($errors eq "")
    {
        ok('success', 'success');
    }
    else
    {
        ok($errors, 'success');
    }
    unlink($tmpname);
}
my $emptydir = POSIX::tmpnam();

mkdir $emptydir, 0755;

foreach('/etc/group', '/', '/etc', '/no-such-file', $emptydir)
{
    my $exists_rc = stat($_) ? 0 : 1;

    push(@tests, "check_existence('gsiftp://localhost$_', $exists_rc);");
}

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests);

# And run them all.
foreach (@tests)
{
    eval "&$_";
}
rmdir $emptydir
