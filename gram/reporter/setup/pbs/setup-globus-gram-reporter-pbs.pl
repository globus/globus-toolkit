use Getopt::Long;

my $name     = 'jobmanager-pbs';
my $type     = 'pbs';
my $action   = 0;

GetOptions( 'service-name|s=s' => \$name,
            'unsetup' => \$action,
            'help' => \$help)
  or pod2usage(1);

pod2usage(0) if $help;

sub pod2usage {
  my $ex = shift;
  print "setup-globus-gram-reporter-${type} [ \\
               -help \\
               -unsetup \\
              ]\n";
  exit $ex;
}

my $gpath = $ENV{GPT_LOCATION};

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

my $metadata = new Grid::GPT::Setup(package_name => "globus_gram_reporter_setup_${type}");

my $globusdir   = $ENV{GLOBUS_LOCATION};
my $libexecdir  = "$globusdir/libexec";

if($action != 0)
{
    $action = "-remove";
    my $action_comment = "removing";
    print "Un-setting up $type gram reporter in MDS\n";
    print "----------------------------------------\n";
    system("rm -f $globusdir/libexec/globus-script-${type}-queue");
}
else
{
    $action = "-add";
    my $action_comment = "adding";
    print "Setting up $type gram reporter in MDS\n";
    print "----------------------------------------\n";
    print `./find-${type}-reporter-tools --cache-file=/dev/null`;
    if($? != 0)
    {
        print STDERR "Error locating ${type} commands, aborting!\n";
        exit 2;
    }
    system("chmod 755 $globusdir/libexec/globus-script-${type}-queue");
}

# un/setup reporter entries in MDS
#----------------------------------------------------------
$cmd = "$libexecdir/globus-job-manager-mds-provider $action -m $type -s \"$name\"";
system("$cmd >/dev/null 2>/dev/null");
if($? != 0)
{
    print STDERR "Error $action_comment $type GRAM reporter entry $name. Aborting!\n";
    exit 3;
}

print "Done\n\n";

$metadata->finish();
