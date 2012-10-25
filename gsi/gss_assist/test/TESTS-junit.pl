#! /usr/bin/perl

use strict;
use warnings;
require 5.005;
use vars qw(@tests);

my $harness;
BEGIN {
    my $xmlfile = 'globus-gss-assist-test.xml';

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
    print "Cannot run tests without a GSI proxy\n";
}

@tests = qw(gss-assist-impexp-test.pl
            gss-assist-auth-test.pl
            gss-assist-gridmap-test.pl
            gridmap-test.pl
            gridmap-tools-test.pl
            );

$harness->runtests(@tests);
