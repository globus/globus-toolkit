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
#
# Ping a valid and invalid gatekeeper contact.

my $prefix;
my $exec_prefix;
my $sbindir;
my $bindir;
my $includedir;
my $datarootdir;
my $datadir;
my $libdir;
my $libexecdir;
my $sysconfdir;
my $sharedstatedir;
my $localstatedir;
my $perlmoduledir;

BEGIN
{
    $prefix = '@prefix@';
    if ($ENV{GLOBUS_LOCATION})
    {
        $prefix = $ENV{GLOBUS_LOCATION};
    }
    $exec_prefix="@exec_prefix@";
    $sbindir="@sbindir@";
    $bindir="@bindir@";
    $includedir="@includedir@";
    $datarootdir="@datarootdir@";
    $datadir="@datadir@";
    $libdir="@libdir@";
    $libexecdir="@libexecdir@";
    $sysconfdir="@sysconfdir@";
    $sharedstatedir="@sharedstatedir@";
    $localstatedir="@localstatedir@";
    $perlmoduledir="@perlmoduledir@";

    unshift(@INC, $perlmoduledir);
}

use strict;
use Test::More;

my $test_exec = './register-ping-test';

if ($ENV{CONTACT_STRING} eq "")
{
    die "CONTACT_STRING not set";
}

my @tests;
my @todo;
my $testno = 1;

sub register_test
{
    my ($contact, $credential, $result) = @_;
    my $rc;
    my $cmdline;
    my $errors='';
    my $valgrind = "";

    if (exists $ENV{VALGRIND})
    {
        $valgrind = "valgrind --log-file=VALGRIND-globus_gram_client_register_ping_test_" . $testno++ . ".log";
        if (exists $ENV{VALGRIND_OPTIONS})
        {
            $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
        }
    }

    if($contact ne '')
    {

        $cmdline = "$test_exec '$contact' ";
        if($credential ne '')
        {
            $cmdline .= "'$credential'";
        }

        system("$valgrind $cmdline >/dev/null");
        $rc = $?>> 8;
        if($rc != $result)
        {
            $errors .= "Test exited with $rc. ";
        }
        ok($errors eq "", $cmdline );
    }
    else
    {
        skip($contact eq '', "Can't tweak contact", 0);
    }
}

my $x509_user_proxy;

if (exists $ENV{X509_USER_PROXY})
{
    $x509_user_proxy = $ENV{X509_USER_PROXY};
}
else
{
    chomp($x509_user_proxy = `$bindir/grid-proxy-info -path`);
}
push(@tests, "register_test('$ENV{CONTACT_STRING}', '', 0);");
push(@tests, "register_test('$ENV{CONTACT_STRING}', '$x509_user_proxy', 0);");

my $bad_contact;
if($ENV{CONTACT_STRING} =~ m/:(.*):/)
{
    my $replacement = $1 . "/bogus";

    $bad_contact=$ENV{CONTACT_STRING};
    $bad_contact=~s/:(.*):/:$replacement:/;
}

push(@tests, "register_test('$bad_contact', '', 93);");
push(@tests, "register_test('$bad_contact', '$x509_user_proxy', 93);");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

foreach (@tests)
{
    eval "&$_";
}
