my $gpath = $ENV{GPT_LOCATION};

if (!defined($gpath))
{
    $gpath = $ENV{GLOBUS_LOCATION};
}

if (!defined($gpath))
{
    die "GPT_LOCATION or GLOBUS_LOCATION needs to be set before running this script";
}

@INC = (@INC, "$gpath/lib/perl");

require Grid::GPT::Setup;
use Getopt::Long;

my $name		= 'jobmanager-pbs';
my $manager_type	= 'pbs';
my $force		= 0;
my $cmd;
my $non_cluster		= 0;
my $cpu_per_node	= 1;
my $remote_shell	= 'default';

GetOptions('service-name|s=s' => \$name,
           'non-cluster' => \$non_cluster,
           'cpu-per-node=i' => \$cpu_per_node,
	   'remote-shell=s' => \$remote_shell,
	   'force|f' => \$force,
	   'help|h|?' => \$help);

&usage if $help;

my $metadata =
    new Grid::GPT::Setup(package_name => "globus_gram_job_manager_setup_pbs");

my $globusdir	= $ENV{GLOBUS_LOCATION};
my $libexecdir	= "$globusdir/libexec";

if($force != 0)
{
    $force = '-f';
}
else
{
    $force = '';
}

if($non_cluster != 0)
{
    $non_cluster = "--without-cluster";
}
else
{
    $non_cluster = "--with-cluster";
}

# Do script relocation
print `./find-pbs-tools $non_cluster --with-cpu-per-node=$cpu_per_node --with-remote-shell=$remote_shell --cache-file=/dev/null`;
if($? != 0)
{
    print STDERR "Error locating PBS commands, aborting!\n";
    exit 2;
}

# Create service
$cmd = "$libexecdir/globus-job-manager-service-add -m pbs -s \"$name\" $force";
system("$cmd >/dev/null 2>/dev/null");

if($? == 0)
{
    $metadata->finish();
}
else
{
    print STDERR "Error creating service entry $name. Aborting!\n";
    exit 3;
}

sub usage
{
    print "Usage: $0 [options]\n".
          "Options:  [--service-name|-s service_name]\n".
	  "          [--non-cluster]\n".
	  "          [--cpu-per-node=COUNT]\n".
	  "          [--remote-shell=rsh|ssh]\n".
          "          [--force|-f]\n".
	  "          [--help|-h]\n";
    exit 1;
}
