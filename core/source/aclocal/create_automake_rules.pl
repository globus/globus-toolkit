my $aclocal = $ARGV[0];

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


# target types defined by automake
my @target_types = ("PROGRAMS", "LTLIBRARIES", "LIBRARIES","SCRIPTS", "HEADERS","DATA");

# install directories defined by automake
my @installdirs = ("lib", "libexec", "etc", "bin", "sbin", "include", "share");

my %installdir_target_list;

# Set up tailored list for automake installdirs

$installdir_target_list{"lib"} = ["LTLIBRARIES", "LIBRARIES"];
$installdir_target_list{"libexec"} = ["PROGRAMS", "SCRIPTS"];
$installdir_target_list{"etc"} = ["DATA"];
$installdir_target_list{"bin"} = ["PROGRAMS", "SCRIPTS"];
$installdir_target_list{"sbin"} = ["PROGRAMS", "SCRIPTS"];
$installdir_target_list{"include"} = ["HEADERS"];
$installdir_target_list{"share"} = ["DATA"];

if (! -f "$aclocal/automake_targets" ) {
  print "ERROR: automake_targets not found!\n";
  usage();
  die;
}

open( TARGETS, "$aclocal/automake_targets");

while (<TARGETS>) {

# Scan for an installdirs name
  if (/(\w+)dir\s+=/) {
    push @installdirs, $1;
  }

# Scan for a list of targets for an installdir
  if (/\#\#\s+(\w+)\s+=\s+\[([^\]]+)\]/) {
    my $idir = $1;
    my $tline = $2;
    my @targets = split(/,/,$tline);
    for (@targets) {
      s/\s+//g;
    }
    $installdir_target_list{$idir} = \@targets;
  }
}

close(TARGETS);

#for (@installdirs) {
#  my @targets = @{$installdir_target_list{$_}};
#  print "$_:\n";
#  print @targets, "\n\n";
#}


opendir(ACLOCAL, $aclocal);

# Suck up all of the *.am files in the directory other than Makefile.am
my @allfiles = 
  grep { ! /Makefile/ }
  grep { /\.am/ }
  readdir(ACLOCAL);

closedir(ACLOCAL);

open (OUTPUT, ">$aclocal/automake_rules");

my ($d, $t);
my ($link, $unlink, $rules, $filelist, $phony) = ("link: link-recursive ","unlink: unlink-recursive ","", "filelist: filelist-recursive ",".PHONY: link unlink link-recursive unlink-recursive link-am unlink-am filelist-am");
for $d (@installdirs) {
  my @targets = @{$installdir_target_list{$d}};
  for $t (@targets) {
    $link .= "link-$d$t ";
    $unlink .= "unlink-$d$t ";
    $filelist .= "filelist-$d$t ";
    $phony .= "link-$d$t unlink-$d$t filelist-$d$t ";
    $rules .= generate_rule($t, $d);
  }
}
print OUTPUT "link-am:\n\nunlink-am:\n\nfilelist-am:\n\n";
print OUTPUT "$link\n\t:\n\n";
print OUTPUT "$unlink\n\t:\n\n";

print OUTPUT "$phony\n\n";

print OUTPUT "$filelist\n\t:\n\n";

print OUTPUT $rules;
close OUTPUT;

my $result = `cat $aclocal/subdirs.am >> $aclocal/automake_rules`;
my $result = `cat $aclocal/filelist.am > $aclocal/automake_top_rules`;


sub generate_rule
  {
    my ($target, $installdir) = @_;
    my $target2file = {
		       PROGRAMS => "progs.am",
		       LTLIBRARIES => "ltlib.am",
		       LIBRARIES => "libs.am",
		       SCRIPTS => "scripts.am",
		       HEADERS => "header.am",
		       DATA => "data.am",
		      };

    if (!defined($target2file->{$target})) {
      die "ERROR: I have no rules file for $target\n";
    }
    open (RULES, "$aclocal/$target2file->{$target}");

#    print "$target $installdir $target2file->{$target}\n";

    my $result = "";
    while (<RULES>) {
      s/\@DIR\@/$installdir/g;
      $result .= $_ if (!/^\#\#/);
    }

    close(RULES);
    $result .="\n";
    return $result;      
}

sub usage {
  print "perl create_automake_rules <directory containing automake_targets>\n";
}
