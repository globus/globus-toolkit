#! /usr/bin/perl

require 5.005;

use warnings;
use strict;

use vars qw(@tests);

my $harness;
BEGIN {
    my $xmlfile = 'globus-proxy-ssl-test.xml';

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
    $ENV{PATH} = ".:" . $ENV{PATH};
}

@tests = qw(test_pci.pl);

$harness->runtests(@tests);
