#!/usr/local/bin/perl

use strict;

my $Tag					= "CVS/Tag";
my $message 				= 
    "ERROR: Sorry, this branch has been closed against commits.\nERROR: If you need to commit to this branch please send a \nERROR: unified diff attached to a email containing the log \nERROR: message to meder\@mcs.anl.gov\n";


my %locked = (
    'globus_2_2_branch' => 1);

# no tag file means its from trunk
exit(0) if(!-f $Tag); 

open(TAGFILE, $Tag) || die("Could not open $Tag");

my $tag = <TAGFILE>;

# should never happen, but...
exit(0) if(!defined($tag));

if($tag =~ s/^T(.*)\n$/$1/)
{
    if(defined($locked{$tag}) && ($ENV{'USER'} ne 'meder'))
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

