#!/usr/bin/env perl

$cvsroot = $ENV{'CVSROOT'};
$webroot = "/mcs/www-unix.globus.org/toolkit/web";
@args = split(/ /, $ARGV[0]);

for my $filename ( @args )
{
    print "I would copy $filename to $webroot/$filename.\n";
}
