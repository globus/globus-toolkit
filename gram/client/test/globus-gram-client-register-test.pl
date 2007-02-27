#! /usr/bin/env perl
#
# Ping a valid and invalid gatekeeper contact.

use strict;
use POSIX;
use Test;

my $test_exec = './globus-gram-client-register-test';

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}
if ($ENV{CONTACT_STRING} eq "")
{
    die "CONTACT_STRING not set";
}

@INC = (@INC, "$gpath/lib/perl");

my @tests;
my @todo;

sub register_test
{
    my ($errors,$rc) = ("",0);
    my ($output);
    my ($contact, $rsl, $result, $fullarg) = @_;

    if (! defined($fullarg))
    {
        $fullarg='';
    }

    system("$test_exec '$contact' '$rsl' $fullarg >/dev/null 2>/dev/null");
    $rc = $?>> 8;
    if($rc != $result)
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
}
push(@tests, "register_test('$ENV{CONTACT_STRING}', '&(executable=/bin/sleep)(arguments=1)', 0);");
push(@tests, "register_test('$ENV{CONTACT_STRING}X', '&(executable=/bin/sleep)(arguments=1)', 7);");
push(@tests, "register_test('$ENV{CONTACT_STRING}', '&(executable=/no-such-bin/sleep)(arguments=1)', 5);");
# Explanation for these test cases:
# Both attempt to run the command
# grid-proxy-info -type | grep limited && globusrun -k $GLOBUS_GRAM_JOB_CONTACT
# In the 1st case, the credential is a limited proxy, so the job is canceled,
# causing the client to receive a FAILED notification.
# In the 2nd case, the credential is a full proxy, so the job is not canceled
# and the job terminates normally
push(@tests, "register_test('$ENV{CONTACT_STRING}', '&(executable=/bin/sh)(arguments = -c \"eval \"\"\$GLOBUS_LOCATION/bin/grid-proxy-info -type | grep limited && \$GLOBUS_LOCATION/bin/globusrun -k \$GLOBUS_GRAM_JOB_CONTACT; sleep 30 \"\"\")(environment = (GLOBUS_LOCATION \$(GLOBUS_LOCATION)) (PATH \"/bin:/usr/bin\"))', 8);");
push(@tests, "register_test('$ENV{CONTACT_STRING}', '&(executable=/bin/sh)(arguments = -c \"eval \"\"\$GLOBUS_LOCATION/bin/grid-proxy-info -type | grep limited && \$GLOBUS_LOCATION/bin/globusrun -k \$GLOBUS_GRAM_JOB_CONTACT; sleep 30\"\"\")(environment = (GLOBUS_LOCATION \$(GLOBUS_LOCATION))(PATH \"/bin:/usr/bin\"))', 0, '-f');");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

foreach (@tests)
{
    eval "&$_";
}
