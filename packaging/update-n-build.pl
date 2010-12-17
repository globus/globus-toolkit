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
	chdir "./$subdir";
	system("cvs update -r RIC-92_branch ");
	chdir "$topsrcdir";
    }




