#!/usr/bin/perl -w
use strict;
use vars qw($top %globus_sh_vars);
use File::Find;

$top = ".";
$top = $ARGV[0] if (defined($ARGV[0]));

find(\&globus_sh, $top);

for (sort keys(%globus_sh_vars)) {
  my $program;
  /GLOBUS_SH_(\w+)/;
  $program = lc $1;
  print qq(AC_PATH_PROG\($_\,$program\)\n);
}

sub globus_sh
  {
    if (! -f "$_") {
      return;
    }
    if (! -T "$_") {
      return;
    }
    my $save = $_;
    open (FILE,"<$_");
    my $line_continuation = "no";
    while (<FILE>) {
      my $macro_buffer="";
      if ($line_continuation eq "yes") {
	$macro_buffer .= $_;
	$line_continuation = "no";
      }
      if (/^\s*\#if/) {
	if (m!\$!) {
	  $line_continuation = "yes";
	}
	$mac
      }
    }
    close FILE;
    $_ = $save;
  }

