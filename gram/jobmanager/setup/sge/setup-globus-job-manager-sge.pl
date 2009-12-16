##########
# Checking if GPT_LOCATION/GLOBUS_LOCATION is properly set
#
my $gpath = $ENV{GPT_LOCATION};
if (!defined($gpath))
{
    $gpath = $ENV{GLOBUS_LOCATION};
}
if (!defined($gpath))
{
    die "either GPT_LOCATION or GLOBUS_LOCATION needs " .
        "to be set before running this script\n";
}

##########
#
#
@INC = (@INC, "$gpath/lib/perl");

require Grid::GPT::Setup;
use Getopt::Long;

my $name         = 'jobmanager-sge';
my $manager_type = 'sge';
my $cmd;


##########
#
#
GetOptions('service-name=s' => \$name,
           'validate-queues' => \$validate_queues,
           'validate-pes' => \$validate_pes,
           'mpi-pe=s' => \$mpi_pe,
           'disable-sunmpi' => \$disable_sunmpi,
           'help|h' => \$help
          );

&usage if $help;


##########
#
#
my $metadata = new Grid::GPT::Setup(package_name => 
                   "globus_gram_job_manager_setup_sge");

my $globusdir	= $ENV{GLOBUS_LOCATION};
my $libexecdir	= "$globusdir/libexec";


##########
#
#
mkdir $ENV{GLOBUS_LOCATION} . "/lib/perl/Globus/GRAM/JobManager", 0777;


##########
# Check SGE_ROOT and SGE_CELL
#
$ENV{SGE_ROOT} or die "SGE_ROOT must be set before running this script\n";
$ENV{SGE_CELL} or $ENV{SGE_CELL}="default";
my $sge_dir = $ENV{SGE_ROOT} . "/" . $ENV{SGE_CELL};
if( ! -d $sge_dir )
{
    die "$sge_dir must be a directory\n";
}


##########
# Checking for parallel environments supported by Grid Engine
#
if($mpi_pe)
{
    my $match=0;

    open(PE_LIST,"qconf -spl |");
    while(<PE_LIST>)
    {
        chomp;
        if( $mpi_pe eq $_ ){ $match=1; } 
    }
    close(PE_LIST);

    if(!$match){
        print STDERR "ERROR: The parallel environment" .
                     " \"$mpi_pe\" does not exist!\n";
        exit 2;
    } else {
        # MPI pe is OK
        $ENV{MPI_PE}=$mpi_pe;
    }
} else {
    print STDERR "MPI_PE == NONE\n";
    $mpi_pe='';
};


##########
# Choosing an MPI implementation
#   By default, if more than one MPI implementation is available, Sun MPI
#   is used. This flag makes the alternative MPI to be used instead.
#
if($disable_sunmpi) 
{
    $ENV{IGNORE_SUNMPI}="yes";
} else {
    $ENV{IGNORE_SUNMPI}="no";
}


##########
#
#
print `./find-sge-tools --cache-file=/dev/null`;
if($? != 0)
{
    print STDERR "Error locating Grid Engine commands, aborting!\n";
    exit 2;
}


##########
# Create service
#
$cmd = "$libexecdir/globus-job-manager-service -add -m sge -s \"$name\"";
system("$cmd >/dev/null 2>/dev/null");
if($? != 0)
{
    print STDERR "Error creating service entry $name. Aborting!\n";
    exit 3;
}


##########
# Create validation file
#
open(VALIDATION_FILE, ">$ENV{GLOBUS_LOCATION}/share/globus_gram_job_manager/sge.rvf");

##########
# Standard SGE attributes
#
print VALIDATION_FILE <<EOF;
Attribute: email_address
Description: "Sun Grid Engine is capable to notify the user when/if
             certain events occur. Email can be sent at the beginning or
             end of the job, when job is aborted or suspended (see below).
             This attibute specifies where email(s) will be sent"
ValidWhen: GLOBUS_GRAM_JOB_SUBMIT

Attribute: emailonexecution
Description: "Mail is sent at the beginning of the job"
Values: yes no
ValidWhen: GLOBUS_GRAM_JOB_SUBMIT

Attribute: emailontermination
Description: "Mail is sent at the end of the job"
Values: yes no
ValidWhen: GLOBUS_GRAM_JOB_SUBMIT

Attribute: emailonabort
Description: "Mail is sent when job has been aborted"
Values: yes no
ValidWhen: GLOBUS_GRAM_JOB_SUBMIT

Attribute: emailonsuspend
Description: "Mail is sent when job has been suspended"
Values: yes no
ValidWhen: GLOBUS_GRAM_JOB_SUBMIT
EOF

##########
# Validate queues
#
if($validate_queues)
{
    my @queue_list = ();

    print "Validating queues\n";

    open(QLIST,"qselect |");
    while(<QLIST>)
    {
        chomp;
        push(@queue_list,$_);
    }
    close(QLIST);

    if(@queue_list){
        print VALIDATION_FILE "\n";
        print VALIDATION_FILE "Attribute: queue\n";
        print VALIDATION_FILE "Description: \"Available queues\"\n";
        print VALIDATION_FILE join(" ","Values:", @queue_list,"\n");
        print VALIDATION_FILE "ValidWhen: GLOBUS_GRAM_JOB_SUBMIT\n";
    }
}

##########
# Validate Parallel Environments
#
if($validate_pes)
{
    my @pes = ();

    print "Validating Parallel Environments\n";

    open(PE_LIST,"qconf -spl|");
    while(<PE_LIST>)
    {
        chomp;
        ## Get the slot count of the Parallel Environment
        # open(PE_CONF,"qconf -sp " . $_ . "|");
        # close(PE_CONF);
        push(@pes,$_);
        print "---> $_\n";
    }
    close(PE_LIST);

    if(@pes){
        print VALIDATION_FILE "\n";
        print VALIDATION_FILE <<EOF;
Attribute: parallel_environment
Description: "Target the job to a Grid Engine Parallel Environment (class) name
             as defined by the scheduler at the defined (remote) resource."
EOF
        print VALIDATION_FILE join(" ","Values:", @pes, "\n");
        print VALIDATION_FILE "ValidWhen: GLOBUS_GRAM_JOB_SUBMIT\n";
     }
}

##########
# Close validation file
#
close VALIDATION_FILE;


$metadata->finish();


##########
# Usage
#
sub usage
{
    print "Usage:\n\t$0 [options]\n\n" .
          "Options:\n" .
          "\t[--service-name=name]   Sets the service name to other\n" .
          "\t                        than jobmanager-sge\n" .
	  "\t[--validate-queues]     Create a resource validation\n" .
          "\t                        files for the queues\n" .
	  "\t[--validate-pes]        Create a pe resource, with the\n" .
          "\t                        available parallel environment\n" .
	  "\t[--mpi-pe=pe_name]      Grid Engine Parallel Environmenti for MPI\n" .
	  "\t[--disable-sunmpi]      Ignores Sun MPI when installing\n" .
          "\t                        the Grid Engine job manager.\n" .
	  "\t[--help|-h]\n";
    exit 1;
}
