#!/bin/env perl
use Cwd;

  open(PKG, "etc/package-list-spec");
  chdir "./source-trees";
  my $topsrcdir=cwd();
    while ( <PKG> )
    {
	my $log;
        my ($pkg, $subdir, $custom, $pnb, $pkgtag) = split(' ', $_);
	print cwd()."\n";
	print $subdir."\n";
	system("cvs -d blau\@cvs.globus.org:/home/globdev/CVS/globus-packages co $subdir ");
    }




