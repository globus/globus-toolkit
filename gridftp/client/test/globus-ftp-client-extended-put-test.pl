#! /usr/bin/env perl
#
# Test to exercise the "put" functionality of the Globus FTP client library
# in extended block mode

use strict;
use POSIX;
use Test;

my $test_exec = $ENV{GLOBUS_LOCATION} . '/test/' . 'globus-ftp-client-extended-put-test';
my $test_file = '/bin/sh';

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

my @tests;
my @todo;

# Test #1-11. Basic functionality: Do a put of $test_file to
# a new unique file name on localhost, varying parallelism level.
# Compare the resulting file with the real file
# Success if program returns 0, files compare,
# and no core file is generated.
sub basic_func
{
    my ($parallelism) = (shift);
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);

    unlink('core', $tmpname);

    $rc = system("$test_exec -d 'gsiftp://localhost/$tmpname' -P $parallelism < $test_file 2>/dev/null") / 256;
    if($rc != 0)
    {
        $errors .= "\n#Test exited with $rc. ";
    }
    if(-r 'core')
    {
        $errors .= "\n# Core file generated.";
    }

    my $diffs = `diff $test_file $tmpname 2>&1 | sed -e 's/^/# /'`;

    if($diffs ne "")
    {
	$errors .= "\n# Differences between $test_file and output.";
	$errors .= "$diffs";
    }

    if($errors eq "")
    {
        ok('success', 'success');
    }
    else
    {
        ok("\n#$test_exec -d 'gsiftp://localhost$tmpname' -P $parallelism < $test_file\n#$errors", 'success');
    }
    unlink($tmpname);
}
for(my $par = 0; $par <= 10; $par++)
{
    push(@tests, "basic_func($par);");
}

# Test #12: Bad URL: Do a simple put to a bad location on the ftp server.
# Success if program returns 1 and no core file is generated.
sub bad_url
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);

    unlink('core', $tmpname);

    $rc = system("$test_exec -d 'gsiftp://localhost/no/such/file/here' < $test_file >/dev/null 2>/dev/null") / 256;
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
push(@tests, "bad_url");

# Test #13-53: Do a simple put of $test_file to localhost, aborting
# at each possible position. Note that not all aborts may be reached.
# Success if no core file is generated for all abort points. (we could use
# a stronger measure of success here)
sub abort_test
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("", 0);
    my ($abort_point) = shift;

    unlink('core', $tmpname);

    $rc = system("$test_exec -a $abort_point -d 'gsiftp://localhost/$tmpname' <$test_file >/dev/null 2>/dev/null") / 256;
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
for(my $i = 1; $i <= 41; $i++)
{
    push(@tests, "abort_test($i);");
}

# Test #54-94. Restart functionality: Do a simple put of $test_file to
# localhost, restarting at each plugin-possible point.
# Compare the resulting file with the real file
# Success if program returns 0, files compare,
# and no core file is generated.
sub restart_test
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);
    my ($restart_point) = shift;

    unlink('core', $tmpname);

    $rc = system("$test_exec -r $restart_point -d 'gsiftp://localhost/$tmpname' < $test_file >/dev/null 2>&1") / 256;
    if($rc != 0)
    {
        $errors .= "Test exited with $rc. ";
    }
    if(-r 'core')
    {
        $errors .= "\n# Core file generated.";
    }
    my $diffs = `sed -e 's/\\[restart plugin\\].*\$//' $tmpname | diff $test_file - 2>&1 | sed -e 's/^/#/'`;
    if($diffs ne "")
    {
        $errors .= "\n# Differences between $test_file and output.";
	$errors .= "$diffs"
    }

    if($errors eq "")
    {
        ok('success', 'success');
    }
    else
    {
        ok("\n# $test_exec -r $restart_point\n#$errors", 'success');
    }
    unlink($tmpname);
}
for(my $i = 1; $i <= 41; $i++)
{
    push(@tests, "restart_test($i);");

    if($i == 38)
    {
	push(@todo, 54 + $i);
    }
}


=head2 I<perf_test> (Test 95)

Do an extended put of $testfile, enabling perf_plugin

=back

=cut
sub perf_test
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);

    unlink('core');

    $rc = system("$test_exec -d 'gsiftp://localhost/$tmpname' -M < $test_file >/dev/null 2>&1") / 256;
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

=head2 I<throughput_test> (Test 96)

Do an extended put of $testfile, enabling throughput_plugin

=back

=cut
sub throughput_test
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);

    unlink('core');

    $rc = system("$test_exec -d 'gsiftp://localhost/$tmpname' -T < $test_file >/dev/null 2>&1") / 256;
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
