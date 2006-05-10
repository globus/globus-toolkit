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

my $name		= 'jobmanager-lsf';
my $manager_type	= 'lsf';
my $cmd;
my $validate_queues	= 1;

GetOptions('service-name|s=s' => \$name,
	   'validate-queues=s' => \$validate_queues,
	   'help|h' => \$help);

&usage if $help;

my $metadata =
    new Grid::GPT::Setup(package_name => "globus_gram_job_manager_setup_lsf");

my $globusdir	= $ENV{GLOBUS_LOCATION};
my $libexecdir	= "$globusdir/libexec";
my $setupdir    = "$globusdir/setup/globus";

chdir $setupdir;

if($validate_queues ne 'no')
{
   $validate_queues = 1;
}
else
{
   $validate_queues = 0;
}

# Do script relocation
mkdir $ENV{GLOBUS_LOCATION} . "/lib/perl/Globus/GRAM/JobManager";

$setupdir = $ENV{GLOBUS_LOCATION} . '/setup/globus';

chdir $setupdir;

print `./find-lsf-tools --cache-file=/dev/null`;
if($? != 0)
{
    print STDERR "Error locating LSF commands, aborting!\n";
    exit 2;
}

# Create service
$cmd = "$libexecdir/globus-job-manager-service -add -m lsf -s \"$name\"";
system("$cmd >/dev/null 2>/dev/null");
if($? != 0)
{
    print STDERR "Error creating service entry $name. Aborting!\n";
    exit 3;
}

if($validate_queues)
{
    open(VALIDATION_FILE,
	 ">$ENV{GLOBUS_LOCATION}/share/globus_gram_job_manager/lsf.rvf");    

    # Customize validation file with queue info
    open(BQUEUES, "bqueues -w |");

    # discard header
    $_ = <BQUEUES>;
    my @queues = ();

    while(<BQUEUES>)
    {
	chomp;

	$_ =~ m/^(\S+)/;

	push(@queues, $1);
    }
    close(BQUEUES);

    if(@queues)
    {
	print VALIDATION_FILE "Attribute: queue\n";
	print VALIDATION_FILE join(" ", "Values:", @queues);

    }
    close VALIDATION_FILE;
}

$metadata->finish();

sub usage
{
    print "Usage: $0 [options]\n".
          "Options:  [--service-name|-s service_name]\n".
	  "          [--validate-queues=yes|no]\n".
	  "          [--help|-h]\n";
    exit 1;
}
