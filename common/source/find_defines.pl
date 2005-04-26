#!/usr/bin/perl -w

#
# Portions of this file Copyright 1999-2005 University of Chicago
# Portions of this file Copyright 1999-2005 The University of Southern California.
#
# This file or a portion of this file is licensed under the
# terms of the Globus Toolkit Public License, found at
# http://www.globus.org/toolkit/download/license.html.
# If you redistribute this file, with or without
# modifications, you must include this notice in the file.
#

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

