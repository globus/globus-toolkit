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

if(!&GetOptions("nonroot|d:s","help|h","force|f","skip_gaa","overwrite_gaa_config")) 
{
    usage(1);
}

if(defined($opt_help))
{
    usage(0);
}

my $target_dir;

my $metadata =
    new Grid::GPT::Setup(package_name => "globus_gaa_authz_callout_setup");

my $globusdir = $ENV{GLOBUS_LOCATION};
my @libs = glob("$globusdir/lib/libglobus_authz_gaa_callout_*.a");
my $config = "";
my $found = 0;
my $lib;

my %callout_names;

$callout_names{"GLOBUS_GSI_AUTHZ_SYSTEM_INIT"} = "globus_gsi_authz_gaa_system_init_callout";
$callout_names{"GLOBUS_GSI_AUTHZ_SYSTEM_DESTROY"} = "globus_gsi_authz_gaa_system_destroy";
$callout_names{"GLOBUS_GSI_AUTHZ_HANDLE_INIT"} = "globus_gsi_authz_gaa_handle_init_callout";
$callout_names{"GLOBUS_GSI_AUTHORIZE_ASYNC"} = "globus_gsi_authz_gaa_authorize_async_callout";
$callout_names{"GLOBUS_GSI_AUTHZ_CANCEL"} = "globus_gsi_authz_gaa_cancel_callout";
$callout_names{"GLOBUS_GSI_AUTHZ_HANDLE_DESTROY"} = "globus_gsi_authz_gaa_handle_destroy_callout";
$callout_names{"GLOBUS_GSI_GET_AUTHORIZATION_IDENTITY"} = "globus_gsi_authz_gaa_get_authorization_identity_callout";

foreach (@libs)
{
    if($_ =~ m/.*libglobus_authz_gaa_callout_[^_]*$/)
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
# Strip flavor
$lib =~ s/_[a-zA-Z0-9]*$//;

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

if (! defined($opt_skip_gaa))
{
    if (-f "$target_dir/gsi-gaa.conf")
    {
	if (! $opt_overwrite_gaa_config)
	{
	    die("$target_dir/gsi-authz.conf already exists (use -overwrite_gaa_config to overwrite");
	}
    }
    open(GAA_TEMPLATE, "<$globusdir/setup/globus/gsi-gaa.conf.tmpl");
 
    open(GAA_CONF, ">$target_dir/gsi-gaa.conf");
    print GAA_CONF "#\n#Globus GAA Configuration File\n#\n";
    print GAA_CONF "libdir $globusdir/lib\n";
    while (<GAA_TEMPLATE>)
    {
	print GAA_CONF $_;
    }
    close(GAA_CONF);
}


open(CONF, "+>> $target_dir/gsi-authz.conf") ||
    die("Error while trying to open $target_dir/gsi-authz.conf. Check your permissions\n");

if (! defined($opt_force))
{
    while(<CONF>)
    {
	foreach $key (keys(%callout_names))
	{
	    if ($_ =~ /^\s*${key}.*/i)
	    {
		print STDERR "Warning: Configuration file already has an entry for at least one\n authorization callout. To overwrite re-run this setup script with the -force option\n";
		exit(1);
	    }
	}
    }
}
seek(CONF, 0, SEEK_SET);
$config = "";
while (<CONF>)
{
    $found = 0;
    foreach $key (keys(%callout_names))
    {
	if ($_ =~ /^\s*${key}.*/i)
	{
	    $found = 1;
	    next;
	}
    }
    if ($found == 0)
    {
	$config .= "$_";
    }
}

close(CONF);

foreach $key (keys(%callout_names))
{
    $config .= $key . " " . $lib . " " . $callout_names{$key} . "\n";
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
    print STDERR "Error creating setting up the GAA authz callout.\n";
}

sub usage
{
    my $ex = shift;
    print "Usage: setup-globus-gridmap-callout [options]\n".
          "Options:  [--nonroot|-d[=path]]\n".
	  "          [--help|-h]\n";
    exit $ex;
}
