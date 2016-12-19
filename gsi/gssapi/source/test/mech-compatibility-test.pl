#! /usr/bin/perl

use Test::More;
our @tests = qw (mic_v1_v1 mic_v1_v2 mic_v2_v1 mic_v2_v2);
plan tests => scalar(@tests);
my $test_old = "./mech-compatibility-test";
my $test_new = "$test_old -n";

sub mic_v1_v1
{
    my $rc;
    my $output;

    $ENV{GLOBUS_GSSAPI_BACKWARD_COMPATIBLE_MIC} = 'true';
    $ENV{GLOBUS_GSSAPI_ACCEPT_BACKWARD_COMPATIBLE_MIC} = 'true';

    $output = `$test_old`;
    $rc = $? >> 8;

    diag($output);

    SKIP: {
        skip "v1 mic not supported", 1 unless ($rc != 77);
        ok($rc == 0, "mic_v1_v1");
    }
}

sub mic_v1_v2
{
    my $rc;
    my $output;

    $ENV{GLOBUS_GSSAPI_BACKWARD_COMPATIBLE_MIC} = 'false';
    $ENV{GLOBUS_GSSAPI_ACCEPT_BACKWARD_COMPATIBLE_MIC} = 'true';

    $output = `$test_old`;
    $rc = $? >> 8;

    diag($output);

    SKIP: {
        skip "v1 mic not supported", 1 unless ($rc != 77);
        ok($rc == 0, "mic_v1_v2");
    }
}

sub mic_v2_v1
{
    my $rc;
    my $output;

    $ENV{GLOBUS_GSSAPI_BACKWARD_COMPATIBLE_MIC} = 'true';
    $ENV{GLOBUS_GSSAPI_ACCEPT_BACKWARD_COMPATIBLE_MIC} = 'true';

    $output = `$test_new`;
    $rc = $? >> 8;

    diag($output);

    SKIP: {
        skip "v1 mic not supported", 1 unless ($rc != 77);
        ok($rc == 0, "mic_v2_v1");
    }
}

sub mic_v2_v2
{
    my $rc;
    my $output;

    $ENV{GLOBUS_GSSAPI_BACKWARD_COMPATIBLE_MIC} = 'false';
    $ENV{GLOBUS_GSSAPI_ACCEPT_BACKWARD_COMPATIBLE_MIC} = 'false';

    $output = `$test_new`;
    $rc = $?;

    diag($output);

    ok($rc == 0, "mic_v2_v2");
}

foreach (@tests) {
    eval $_;
}
