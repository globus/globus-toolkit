#! /usr/bin/env perl
#
# Test to exercise the "3rd party transfer" functionality of the Globus
# FTP client library.
#

use strict;
use POSIX;
use Test;

my $test_exec = $ENV{GLOBUS_LOCATION} . '/test/' . 'globus-ftp-client-extended-transfer-test';
my $testfile = "/etc/group";
my @tests;
my @todo;

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

# Test #1-10. Basic functionality: Do a transfer of $testfile to/from
# localhost, varying parallelism level.
# Compare the resulting file with the real file
# Success if program returns 0, files compare,
# and no core file is generated.
sub basic_func
{
    my ($parallelism) = (shift);
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);

    unlink('core', $tmpname);

    $rc = system("$test_exec -P $parallelism -s gsiftp://localhost$testfile -d gsiftp://localhost/$tmpname 2/dev/null 2>&1") / 256;
    if($rc != 0)
    {
        $errors .= "Test exited with $rc. ";
    }
    if(-r 'core')
    {
        $errors .= "\n# Core file generated.";
    }

    my $diffs = `diff $testfile $tmpname 2>&1 | sed -e 's/^/# /'`;

    if($diffs ne "")
    {
	$errors .= "\n# Differences between /etc/group and output.";
	$errors .= "$diffs";
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
for(my $par = 1; $par <= 10; $par++)
{
    push(@tests, "basic_func($par);");
}

# Test #11: Bad URL Source: Do a 3rd party transfer of a non-existent
# file from localhost.
# Success if program returns 1 and no core file is generated.
sub bad_url_src
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);

    unlink('core', $tmpname);

    $rc = system("$test_exec -s 'gsiftp://localhost/no-such-file-here' -d gsiftp://localhost$tmpname >/dev/null 2>&1") / 256;
    if($rc != 1)
    {
        $errors .= "\n# Test exited with $rc.";
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
push(@tests, "bad_url_src");

# Test #12: Bad URL: Do a 3rd party transfer of an unwritable location as the
# destination
# Success if program returns 1 and no core file is generated.
sub bad_url_dest
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);

    unlink('core', $tmpname);

    $rc = system("$test_exec -s gsiftp://localhost$testfile -d gsiftp://localhost/no-such-file-here >/dev/null 2>&1") / 256;
    if($rc != 1)
    {
        $errors .= "\n# Test exited with $rc.";
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
push(@tests, "bad_url_dest");

# Test #13-422: Do a transfer of $testfile to/from localhost, aborting
# at each possible position. Note that not all aborts may be reached.
# Success if no core file is generated for all abort points. (we could use
# a stronger measure of success here)
sub abort_test
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("", 0);
    my ($abort_point) = shift;
    my ($par) = shift;

    unlink('core', $tmpname);

    $rc = system("$test_exec -P $par -a $abort_point -s gsiftp://localhost$testfile -d gsiftp://localhost$tmpname >/dev/null 2>&1") / 256;
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
        ok("\n# $test_exec -P $par -a $abort_point\n#$errors", 'success');
    }
    unlink($tmpname);
}
for(my $i = 1; $i <= 41; $i++)
{
    for(my $j = 1; $j <= 10; $j++)
    {
        push(@tests, "abort_test($i, $j);");
    }
}

# Test #422-831. Restart functionality: Do a transfer of $testfile
# to/from localhost, restarting at each plugin-possible point.
# Compare the resulting file with the real file
# Success if program returns 0, files compare,
# and no core file is generated.
sub restart_test
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);
    my ($restart_point) = shift;
    my ($par) = shift;

    unlink('core', $tmpname);

    $rc = system("$test_exec -P $par -r $restart_point -s gsiftp://localhost$testfile -d gsiftp://localhost$tmpname >/dev/null 2>&1") / 256;
    if($rc != 0)
    {
        $errors .= "Test exited with $rc. ";
    }
    if(-r 'core')
    {
        $errors .= "\n# Core file generated.";
    }
    my $diffs = `diff $testfile $tmpname 2>&1 | sed -e 's/^/#/'`;
    if($diffs ne "")
    {
        $errors .= "\n# Differences between $testfile output.";
    }

    if($errors eq "")
    {
        ok('success', 'success');
    }
    else
    {
        ok("\n# $test_exec -P $par -r $restart_point -d gsiftp://localhost$tmpname\n#$errors", 'success');
    }
    unlink($tmpname);
}
for(my $i = 1; $i <= 41; $i++)
{
    for(my $j = 1; $j <= 10; $j++)
    {
      push(@tests, "restart_test($i, $j);");
    }
}


=head2 I<perf_test> (Test 832)

Do an extended put of $testfile, enabling perf_plugin

=back

=cut
sub perf_test
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);

    unlink('core');

    $rc = system("$test_exec -M -s gsiftp://localhost$testfile -d gsiftp://localhost$tmpname >/dev/null 2>&1") / 256;
    if($rc != 0)
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
        ok("\n# $test_exec -M \n#$errors", 'success');
    }
    unlink($tmpname);
}

push(@tests, "perf_test();");

=head2 I<throughput_test> (Test 833)

Do an extended put of $testfile, enabling throughput_plugin

=back

=cut
sub throughput_test
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);

    unlink('core');

    $rc = system("$test_exec -T -s gsiftp://localhost$testfile -d gsiftp://localhost$tmpname >/dev/null 2>&1") / 256;
    if($rc != 0)
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
        ok("\n# $test_exec -T\n#$errors", 'success');
    }
    unlink($tmpname);
}

push(@tests, "throughput_test();");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

# And run them all.
foreach (@tests)
{
    eval "&$_";
}
