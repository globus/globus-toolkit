my $gpath = $ENV{GPT_LOCATION};

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


if (!defined($gpath))
{
  $gpath = $ENV{GLOBUS_LOCATION};

}

if (!defined($gpath))
{
   die "GPT_LOCATION or GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

require Grid::GPT::Setup;

my $metadata = new Grid::GPT::Setup(package_name => "globus_common_setup");

my $globusdir = $ENV{GLOBUS_LOCATION};

if((!defined($globusdir)))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

my $setupdir = "$globusdir/setup/globus/";

print "creating globus-sh-tools-vars.sh\n";
my $result = `$setupdir/findshelltools`;

print "creating globus-script-initializer\n";
print "creating Globus::Core::Paths\n";

$result = `$setupdir/setup-tmpdirs`;

for my $setupfile ('globus-script-initializer', 'globus-sh-tools-vars.sh')
{
    $result = system("cp $setupdir/$setupfile $globusdir/libexec");
    $result = system("chmod 0755 $globusdir/libexec/$setupfile");

}

system("mkdir -p $globusdir/lib/perl/Globus/Core");
system("cp $setupdir/Paths.pm $globusdir/lib/perl/Globus/Core/");
system("chmod 0644 $globusdir/lib/perl/Globus/Core/Paths.pm");

print "checking globus-hostname\n";

my $hostname = `$globusdir/bin/globus-hostname`;

$hostname =~ s/\w//g; #strip whitespace

if( ("$hostname" eq "localhost.") || 
	("$hostname" eq "localhost.localdomain") ||
	("$hostname" eq "."))
{
   print "WARNING: globus-hostname was unable to determine a valid hostname\n";
   print "WARNING: this may lead to problems with other programs that\n";
   print "WARNING: depend on globus-hostname. To avoid this please set the\n";
   print "WARNING: GLOBUS_HOSTNAME environment variable\n";
}

print "Done\n";

$metadata->finish();
