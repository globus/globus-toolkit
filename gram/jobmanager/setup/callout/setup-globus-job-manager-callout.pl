use Grid::GPT::Setup;
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
    new Grid::GPT::Setup(package_name => "globus_gram_job_manager_setup_callout");

my $globusdir = $ENV{GLOBUS_LOCATION};
my @libs = glob("$globusdir/lib/libglobus_gram_job_manager_callout_*.a");
my $config = "";
my $found = 0;
my $lib;

foreach (@libs)
{
    if($_ =~ m/.*libglobus_gram_job_manager_callout_[^_]*$/)
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
    if($_ =~ /^\s*globus_gram_jobmanager_authz.*/i)
    {
        $found = 1;
        if(defined($opt_force))
        {
            $_ = "globus_gram_jobmanager_authz $lib globus_gram_callout\n";
        }
        else
        {
            print STDERR "Warning: Configuration file already has a entry for the GRAM authorization\n callout. To overwrite re-run this setup script with the -force option\n";
        }
    }
    
    $config .= "$_";
}
    
if($found == 0)
{
    $config .= "globus_gram_jobmanager_authz $lib globus_gram_callout\n";
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
    print STDERR "Error creating setting up the GRAM authorization callout.\n";
}

sub usage
{
    my $ex = shift;
    print "Usage: setup-globus-job-manager-callout [options]\n".
          "Options:  [--nonroot|-d[=path]]\n".
	  "          [--help|-h]\n";
    exit $ex;
}
