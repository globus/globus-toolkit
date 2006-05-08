#! /usr/bin/env perl

#
# Portions of this file Copyright 1999-2005 University of Chicago
# Portions of this file Copyright 1999-2005 The University of Southern California.
#
# This file or a portion of this file is licensed under the
# terms of the Globus Toolkit Public License, found at
# http://www.globus.org/toolkit/download/license.html.
# If you redistribute this file, with or without
# modifications, you must include this notice in the file.
#



=head1 Get Tests

Tests to exercise the "get" functionality of the Globus FTP client library.

=cut
use strict;
use POSIX;
use Test;
use FtpTestLib;
use File::Spec;
use Globus::URL;

my $test_exec = './globus-ftp-client-get-test';
my @tests;
my @todo;

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

my ($proto) = setup_proto();
my ($source_host, $source_file, $local_copy) = setup_remote_source();

=head2 I<basic_func> (Test 1-2)

Do a simple get of $test_url. Compare the resulting file with the real file.

=over 4

=item Test 1

Transfer file without a valid proxy. Success if test program returns 1,
and no core dump is generated.

=item Test 2

Transfer file with a valid proxy. Success if test program returns 0 and
files compare.

=back

=cut
sub basic_func
{
    my ($use_proxy) = (shift);
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);

    if($use_proxy == 0)
    {
        FtpTestLib::push_proxy(File::Spec::->devnull());
    }
    my $command = "$test_exec -s '$proto$source_host$source_file'";
    $errors = run_command($command, $use_proxy ? 0 : -1, $tmpname);
    if($errors eq "" && $use_proxy)
    {
        $errors .= compare_local_files($local_copy, $tmpname);
    }

    if($errors eq "")
    {
        ok('success', 'success');
    }
    else
    {
        $errors = "\n# Test failed\n# $command\n# " . $errors;
        ok($errors, 'success');
    }
    unlink($tmpname);
    if($use_proxy == 0)
    {
        FtpTestLib::pop_proxy();
    }
}
push(@tests, "basic_func" . "(0);") unless $proto ne "gsiftp://";
push(@tests, "basic_func" . "(1);");


=head2 I<bad_url> (Test 3)

Do a simple get of a non-existent file.

=over 4

=item Test 3

Attempt to retrieve a non-existent file. Success if program returns 1
and no core file is generated.

=back

=cut
sub bad_url
{
    my ($errors,$rc) = ("",0);
    my ($bogus_url) = new Globus::URL("$proto$source_host$source_file");

    $bogus_url->{path} = "/no-such-file-here";
    my $command = "$test_exec -s ".$bogus_url->to_string();
    $errors = run_command($command, 1);
    if($errors eq "")
    {
        ok('success', 'success');
    }
    else
    {
        $errors = "\n# Test failed\n# $command\n# " . $errors;
        ok($errors, 'success');
    }
}

push(@tests, "bad_url");

=head2 I<abort_test> (Test 4-44)

Do a simple get of $test_url, aborting at each possible state abort
machine. Note that not all aborts will be reached for the "get"
operation.

Success if no core file is generated for all abort points. (we could
use a stronger measure of success here)

=cut
sub abort_test
{
    my ($errors,$rc) = ("", 0);
    my ($abort_point) = shift;

    my $command = "$test_exec -a $abort_point -s '$proto$source_host$source_file'";
    $errors = run_command($command, -2);
    if($errors eq "")
    {
        ok('success', 'success');
    }
    else
    {
        $errors = "\n# Test failed\n# $command\n# " . $errors;
        ok($errors, 'success');
    }
}
for(my $i = 1; $i <= 43; $i++)
{
    push(@tests, "abort_test($i);");
}

=head2 I<restart_test> (Test 45-85)

Do a simple get of $test_url, restarting at each plugin-possible
point.  Compare the resulting file with the real file. Success if
program returns 0, files compare, and no core file is generated.

=cut
sub restart_test
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);
    my ($restart_point) = shift;

    my $command = "$test_exec -r $restart_point -s '$proto$source_host$source_file'";
    $errors = run_command($command, 0, $tmpname);
    if($errors eq "")
    {
        $errors .= compare_local_files($local_copy, $tmpname);
    }

    if($errors eq "")
    {
        ok('success', 'success');
    }
    else
    {
        $errors = "\n# Test failed\n# $command\n# " . $errors;
        ok($errors, 'success');
    }
    unlink($tmpname);
}

for(my $i = 1; $i <= 43; $i++)
{
    push(@tests, "restart_test($i);");
}

=head2 I<dcau_test> (Test 86-89)

Do a simple get of $test_url, using each of the possible DCAU modes,
including subject authorization with a bad subject name.

=over 4

=item Test 86

DCAU with no authorization.

=item Test 87

DCAU with "self" authorization.

=item Test 88

DCAU with subject authorization for our subject

=item Test 89

DCAU with subject authorization with an invalid subject.

=back

=cut
sub dcau_test
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);
    my ($dcau, $desired_rc) = @_;

    my $command = "$test_exec -c $dcau -s '$proto$source_host$source_file'";
    $errors = run_command($command, $desired_rc, $tmpname);
    if($errors eq "" && $desired_rc == 0)
    {
        $errors .= compare_local_files($local_copy, $tmpname);
    }

    if($errors eq "")
    {
        ok('success', 'success');
    }
    else
    {
        $errors = "\n# Test failed\n# $command\n# " . $errors;
        ok($errors, 'success');
    }
    unlink($tmpname);
}

my $subject;

if($ENV{GLOBUS_FTP_CLIENT_TEST_SUBJECT})
{
    $subject = $ENV{GLOBUS_FTP_CLIENT_TEST_SUBJECT};
}
else
{
    chomp($subject = `grid-cert-info -subject`);   
    $subject =~ s/^ *//;
}


push(@tests, "dcau_test('none', 0);");
push(@tests, "dcau_test('self', 0);");
push(@tests, "dcau_test(\"'$subject'\", 0);");
push(@tests, "dcau_test(\"'/O=Grid/O=Globus/CN=bogus'\", 1);") unless $proto ne "gsiftp://";

=head2 I<prot_test> (Test 90-92)

Do a simple get of $test_url, using DCAU self with clear, safe, and
private data channel protection.

=over 4

=item Test 90

PROT with clear protection

=item Test 91

PROT with safe protection

=item Test 92

PROT with private protection

=back

=cut
sub prot_test
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);
    my ($prot, $desired_rc) = @_;

    my $command = "$test_exec -c self -t $prot -s '$proto$source_host$source_file'";
    $errors = run_command($command, $desired_rc, $tmpname);
    if($errors eq "" && $desired_rc == 0)
    {
        $errors .= compare_local_files($local_copy, $tmpname);
    }

    if($errors eq "")
    {
        ok('success', 'success');
    }
    else
    {
        $errors = "\n# Test failed\n# $command\n# " . $errors;
        ok($errors, 'success');
    }
    unlink($tmpname);
}

push(@tests, "prot_test('clear', 0);");
push(@tests, "prot_test('safe', 0);");
push(@tests, "prot_test('private', 0);");

=head2 I<perf_test> (Test 93)

Do a simple get of $test_url, enabling perf_plugin

=back

=cut
sub perf_test
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);

    my $command = "$test_exec -M -s '$proto$source_host$source_file'";
    $errors = run_command($command, 0, $tmpname);
    if($errors eq "")
    {
        $errors .= compare_local_files($local_copy, $tmpname);
    }

    if($errors eq "")
    {
        ok('success', 'success');
    }
    else
    {
        $errors = "\n# Test failed\n# $command\n# " . $errors;
        ok($errors, 'success');
    }
    unlink($tmpname);
}

push(@tests, "perf_test();");

=head2 I<throughput_test> (Test 94)

Do a simple get of $test_url, enabling throughput_plugin

=back

=cut
sub throughput_test
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);

    my $command = "$test_exec -T -s '$proto$source_host$source_file'";
    $errors = run_command($command, 0, $tmpname);
    if($errors eq "")
    {
        $errors .= compare_local_files($local_copy, $tmpname);
    }

    if($errors eq "")
    {
        ok('success', 'success');
    }
    else
    {
        $errors = "\n# Test failed\n# $command\n# " . $errors;
        ok($errors, 'success');
    }
    unlink($tmpname);
}

push(@tests, "throughput_test();");

=head2 I<restart_plugin_test> (Test 95-?)

Do a get of $test_url, triggering server-side faults, and using
the default restart plugin to cope with them.

=back

=cut
sub restart_plugin_test
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);
    my $other_args;

    $ENV{GLOBUS_FTP_CLIENT_FAULT_MODE} = shift;
    $other_args = shift;
    if(!defined($other_args))
    {
	$other_args = "";
    }

    my $command = "$test_exec -s '$proto$source_host$source_file' -f 0,0,0,0 $other_args";
    $errors = run_command($command, 0, $tmpname);
    if($errors eq "")
    {
        $errors .= compare_local_files($local_copy, $tmpname);
    }

    if($errors eq "")
    {
        ok('success', 'success');
    }
    else
    {
        $errors = "\n# Test failed\n# $command\n# " . $errors;
        ok($errors, 'success');
    }
    delete $ENV{GLOBUS_FTP_CLIENT_FAULT_MODE};
    unlink($tmpname);
}
foreach (&FtpTestLib::ftp_commands())
{
    push(@tests, "restart_plugin_test('$_');");
}

push(@tests, "restart_plugin_test('PROT', '-c self -t safe')");
push(@tests, "restart_plugin_test('DCAU', '-c self -t safe')");
push(@tests, "restart_plugin_test('PBSZ', '-c self -t safe')");

if(defined($ENV{FTP_TEST_RANDOMIZE}))
{
    shuffle(\@tests);
}

if(@ARGV)
{
    plan tests => scalar(@ARGV);

    foreach (@ARGV)
    {
        eval "&$tests[$_-1]";
    }
}
else
{
    plan tests => scalar(@tests), todo => \@todo;

    foreach (@tests)
    {
        eval "&$_";
    }
}


unlink($local_copy);

