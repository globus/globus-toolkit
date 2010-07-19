#!/usr/bin/perl -w

# 
# Copyright 1999-2006 University of Chicago
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
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

