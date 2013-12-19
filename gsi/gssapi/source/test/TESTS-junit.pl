#!/usr/bin/perl
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

require 5.005;

use warnings;
use strict;
use vars qw(@tests);

my $harness;
BEGIN {
    my $xmlfile = 'globus-gssapi-gsi-test.xml';

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
if (system("grid-proxy-info -exists") != 0)
{
    print STDERR "Unable to run tests without a proxy\n";
    exit(1);
}
@tests = qw(
            gssapi-acquire-test.pl
            gssapi-anonymous-test.pl
            gssapi-context-test.pl 
            gssapi-delegation-test.pl
            gssapi-expimp-test.pl
            gssapi-inquire-sec-ctx-by-oid-test.pl
            gssapi-limited-delegation-test.pl
            gssapi-delegation-compat-test.pl
            compare-name-test.pl
            compare-name-test-rfc2818.pl
            compare-name-test-gt2.pl
            duplicate-name-test.pl
            indicate-mechs-test.pl
            inquire-names-for-mech-test.pl
            gssapi-import-name.pl
            nonterminated-export-cred-test.pl
            release-name-test.pl
           );

$harness->runtests(@tests);
