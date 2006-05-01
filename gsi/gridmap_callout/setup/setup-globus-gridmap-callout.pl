use Grid::GPT::Setup;

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

use Getopt::Long;
use English;
use File::Path;

if(!&GetOptions("nonroot|d:s","help|h","force|f")) 
{
    usage(1);
}

if(defined($opt_help))
{
    usage(0);
}

my $target_dir;

my $metadata =
    new Grid::GPT::Setup(package_name => "globus_gridmap_callout_setup");

my $globusdir = $ENV{GLOBUS_LOCATION};
my @libs = glob("$globusdir/lib/libglobus_gridmap_callout_*.a");
my $config = "";
my $found = 0;
my $lib;

foreach (@libs)
{
    if($_ =~ m/.*libglobus_gridmap_callout_[^_]*$/)
    {
        $lib = $_;
        last;
    }
}

if(!$lib)
{
    die("Could not find callout library\n");
} 

$lib =~ s/\.a$//;

if(defined($opt_nonroot))
{
    if($opt_nonroot eq "") 
    {
	$target_dir = $globusdir . "/etc/";
    } 
    else 
    {
	$target_dir = "$opt_nonroot";
    }
}
else
{
   $target_dir = "/etc/grid-security";
}

umask(022);
open(CONF, "+>> $target_dir/gsi-authz.conf") ||
    die("Error while trying to open $target_dir/gsi-authz.conf. Check your permissions\n");

while(<CONF>)
{
    if($_ =~ /^\s*globus_mapping.*/i)
    {
        $found = 1;
        if(defined($opt_force))
        {
            $_ = "globus_mapping $lib globus_gridmap_callout\n";
        }
        else
        {
            print STDERR "Warning: Configuration file already has a entry for the Globus gridmap\n callout. To overwrite re-run this setup script with the -force option\n";
        }
    }
    
    $config .= "$_";
}
    
if($found == 0)
{
    $config .= "globus_mapping $lib globus_gridmap_callout\n";
}

close(CONF);

open(CONF, "> $target_dir/gsi-authz.conf") ||
    die("Error while trying to open $target_dir/gsi-authz.conf. Check your permissions\n");
    
print CONF "$config";

close(CONF);


if($? == 0)
{
    $metadata->finish();
}
else
{
    print STDERR "Error creating setting up the gridmap callout.\n";
}

sub usage
{
    my $ex = shift;
    print "Usage: setup-globus-gridmap-callout [options]\n".
          "Options:  [--nonroot|-d[=path]]\n".
	  "          [--help|-h]\n";
    exit $ex;
}
