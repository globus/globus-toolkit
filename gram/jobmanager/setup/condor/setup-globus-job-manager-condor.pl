use Grid::GPT::Setup;
use Getopt::Long;

my $name		= 'jobmanager-condor';
my $manager_type	= 'condor';
my $condor_os		= '';
my $condor_arch		= '';
my $c_opts		= '';
my $cmd;

GetOptions('service-name|s=s' => \$name,
	   'help|h' => \$help,
	   'condor-os=s' => \$condor_os,
	   'condor-arch=s' => \$condor_arch);

&usage if $help;

my $metadata =
    new Grid::GPT::Setup(package_name => "globus_gram_job_manager_setup_condor");

my $globusdir	= $ENV{GLOBUS_LOCATION};
my $libexecdir	= "$globusdir/libexec";

mkdir $ENV{GLOBUS_LOCATION} . "/lib/perl/Globus/GRAM/JobManager", 0777;

if($condor_os ne '')
{
    $c_opts = ' --with-condor-os=$condor_os';
}
if($condor_arch ne '')
{
    $c_opts .= ' --with-condor-arch=$condor_arch';
}

print `./find-condor-tools $c_opts --cache-file=/dev/null`;
chmod 0755, 'globus-condor-print-config';

my $condor_jm_config = `globus-condor-print-config`;
chomp($condor_jm_config);

$cmd = "$libexecdir/globus-job-manager-service -add -m condor -s \"$name\"";
system("$cmd -extra-config='$condor_jm_config' >/dev/null 2>/dev/null");

if($? == 0)
{
    $metadata->finish();
}
else
{
    print STDERR "Error creating service entry $name.\n";
}

sub usage
{
    print "Usage: $0 [options]\n".
          "Options:  [-service-name|-s service_name]\n".
	  "          [-condor-os=CONDOR OS]\n".
	  "          [-condor-arch=CONDOR ARCH]\n".
	  "          [-help]\n";
    exit 1;
}
