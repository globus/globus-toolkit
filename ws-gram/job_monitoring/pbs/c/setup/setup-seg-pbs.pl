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

my $path                = '/var/spool/pbs/server_logs';
my $help		= 0;

GetOptions('path|p=s' => \$path,
	   'help|h' => \$help);

&usage if $help;

if (-e $path)
{
    if (! -d $path)
    {
        print STDERR "$path is not a directory\n";
        exit 1;
    }
    elsif(! -r $path)
    {
        print STDERR "$path cannot be read\n";
        exit 1;
    }
}
else
{
    print STDERR "$path does not exist\n";
    exit 1;
}
my $metadata =
    new Grid::GPT::Setup(package_name =>
            'globus_scheduler_event_generator_pbs_setup');

my $globusdir	= $ENV{GLOBUS_LOCATION};
my $libexecdir	= "$globusdir/libexec";
local(*FP);

open(FP, ">$globusdir/etc/globus-pbs.conf");
print FP "log_path=$path\n";
close(FP);

$metadata->finish();

sub usage
{
    print "Usage: $0 [options]\n".
          "Options:  [--path|-p path to PBS server log]\n".
	  "          [--help|-h]\n".
          " default path is /var/spool/pbs/server_logs\n";
    exit 1;
}
