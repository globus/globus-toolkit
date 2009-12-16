#! /usr/bin/env perl

my $gpath = $ENV{GPT_LOCATION};

# [dwm] SGE configuration environment variables
my ($root)		= $ENV{SGE_ROOT};
my ($cell)		= $ENV{SGE_CELL};

if (!defined($gpath))
{
    $gpath = $ENV{GLOBUS_LOCATION};
}

if (!defined($gpath))
{
    die "GPT_LOCATION or GLOBUS_LOCATION needs to be set before running this script";
}

# [dwm] Check that the SGE environment variables are defined; 
#	otherwise, we won't be able to find our reporting data at runtime.
unless (defined($root) && defined($cell)) {
	die 	"The SGE_ROOT and SGE_CELL environment variables need " . 
		"to be set before running this script;\n" .
		"(Try sourcing the settings shell script from your SGE installation.)";
}

@INC = (@INC, "$gpath/lib/perl");

require Grid::GPT::Setup;
use Getopt::Long;

my $path                = "$root/$cell/common/reporting";
my $help		= 0;

GetOptions('path|p=s' => \$path,
	   'help|h' => \$help);

&usage if $help;	# [dwm] This call does not return.

# [dwm] Check that our reporting file exists and is usable.
unless (-e $path && -r $path) {
	die "'$path' is not readable or does not exist! Aborting!";
}

my $metadata =
    new Grid::GPT::Setup(package_name =>
            'globus_scheduler_event_generator_sge_setup');

my $globusdir	= $ENV{GLOBUS_LOCATION};
my $libexecdir	= "$globusdir/libexec";
local(*FP);

open(FP, ">$globusdir/etc/globus-sge.conf");
print FP "log_path=$path\n";
close(FP);

$metadata->finish();

sub usage
{
    print "Usage: $0 [options]\n".
          "Options:  [--path|-p] path to SGE server reporting logfile]\n".
	  "          [--help|-h]\n".
          " default path is $SGE_ROOT/$SGE_CELL/common/reporting\n";
    exit 1;
}
