#!/usr/bin/perl

use strict;
require 5.005;
use vars qw(@tests);

my $harness;
BEGIN {
    my $xmlfile = 'globus-openssl-error-test.xml';

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

@tests = qw( globus-openssl-error-test.pl
	     );

$harness->runtests(@tests);
