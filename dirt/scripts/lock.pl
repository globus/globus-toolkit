#!/usr/local/bin/perl

use strict;

my $Tag					= "CVS/Tag";
my $message 				= 
    "ERROR: Sorry, this branch has been closed against commits.\nERROR: Please contact Stu at smartin\@mcs.anl.gov for more information\n";


my %locked = (
    'globus-beta-branch' => 1,
    'globus-beta-branch-sub-versions' => 1);

# no tag file means its from trunk
exit(0) if(!-f $Tag); 

open(TAGFILE, $Tag) || die("Could not open $Tag");

my $tag = <TAGFILE>;

# should never happen, but...
exit(0) if(!defined($tag));

if($tag =~ s/^T(.*)\n$/$1/)
{
    if(defined($locked{$tag}))
    {
        print STDERR $message;
        exit(1);
    }
}
else
{
    # some unknown type of entry, definitely not a branch tag
}

exit(0);

