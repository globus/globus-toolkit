#! /usr/bin/env perl 

=head1 globus-ftp-client-size-test

Tests to exercise the size checking of the client library.

=cut

use strict;
use POSIX;
use Test;

my $test_exec = $ENV{GLOBUS_LOCATION} . '/test/' . 'globus-ftp-client-size-test';
my @tests;

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

sub check_size
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);
    my ($old_proxy);
    my $src_url = shift;
    my $size = shift;
    my $checked_size;

    unlink('core', $tmpname);

    $checked_size = `$test_exec -s $src_url 2>/dev/null`;
    chomp($checked_size);
    $rc = $? / 256;
    if($rc != 0 && $size >= 0)
    {
        $errors .= "Test exited with $rc. ";
    }
    if(-r 'core')
    {
        $errors .= "\n# Core file generated.";
    }
    if($size != -1 && $checked_size != $size)
    {
	$errors .= "\n# Size mismatch.";
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
foreach('/etc/group', '/bin/sh', '/adsfadsfa')
{
    my $size = (stat($_))[7];
    if(!defined($size))
    {
	$size = -1;
    }

    push(@tests, "check_size('gsiftp://localhost/$_', $size);");
}

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests);

# And run them all.
foreach (@tests)
{
    eval "&$_";
}
