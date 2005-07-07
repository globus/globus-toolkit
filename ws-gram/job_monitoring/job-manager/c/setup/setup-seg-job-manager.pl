#! /usr/bin/env perl

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

my $help		= 0;
my $globus_location     = $ENV{GLOBUS_LOCATION};
my $pkgdir              = "$globus_location/etc/globus_packages";
my $schedulers          = '';
my @schedulers;

foreach (<$pkgdir/globus_scheduler_event_generator*>)
{
    if(/globus_scheduler_event_generator$/)
    {
        next;
    }
    elsif(/setup$/)
    {
        next;
    }
    else
    {
        s/.*globus_scheduler_event_generator_//;
    }
    push(@schedulers, $_);
}
$schedulers = join(',', @schedulers);

GetOptions('schedulers|s=s' => \$schedulers,
	   'help|h' => \$help);

@schedulers = split(',', $schedulers);

&usage if $help;

my $metadata =
    new Grid::GPT::Setup(package_name =>
            'globus_scheduler_event_generator_fork_setup');

my $globusdir	= $ENV{GLOBUS_LOCATION};
my $libexecdir	= "$globusdir/libexec";
local(*FP);

open(FP, ">$globusdir/etc/globus-job-manager-seg.conf");
foreach (@schedulers)
{
    my $log_path = "$globus_location/var/globus-job-manager-seg-$_";
    print FP $_."_log_path=$log_path\n";

    if (! -d $log_path)
    {
        mkdir $log_path, 0755;
    }
}

close(FP);

$metadata->finish();

sub usage
{
    print "Usage: $0 [options]\n".
          "Options:  [--schedulers SCHEDULERS] \n".
          " SCHEDULERS is a comma-delimited list of schedulers\n".
	  "          [--help|-h]\n";
    exit 1;
}
