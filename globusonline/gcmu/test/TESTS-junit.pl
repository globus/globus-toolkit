#! /usr/bin/perl
#
# Copyright 1999-2013 University of Chicago
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


use strict;

require 5.005;
use vars qw(@tests);
$ENV{PATH} .= ":.";

my $harness;
BEGIN {
    my $xmlfile = "gcmu-test.xml";
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

$|=1;
@tests = qw(
    command-line-options.pl
    id-setup-and-cleanup.pl
    id-setup-and-cleanup-generic.pl
    web-setup-and-cleanup.pl
    web-setup-and-cleanup-generic.pl
    io-setup-and-cleanup.pl
    io-setup-and-cleanup-generic.pl
    endpoint-options.pl
    security-options.pl
    gridftp-options.pl
    myproxy-options.pl
    oauth-options.pl
    reset-endpoint.pl
    double-server-config.pl
    activation-test.pl
);

my $test_result = $harness->runtests(@tests);
exit($test_result)
