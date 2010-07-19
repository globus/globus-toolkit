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
use File::Copy;

my $path                = '';
my $help		= 0;

GetOptions('path|p=s' => \$path,
	   'help|h' => \$help);

&usage if $help;


if ($path ne '') {
    system("./find-lsf-logs --with-log-path=$path");
} else {
    system("./find-lsf-logs");
}

if ($? != 0)
{
    exit $?;
}

copy('globus-lsf.conf', "$ENV{GLOBUS_LOCATION}/etc/globus-lsf.conf");

my $metadata =
    new Grid::GPT::Setup(package_name =>
            'globus_scheduler_event_generator_lsf_setup');

my $globusdir	= $ENV{GLOBUS_LOCATION};
my $libexecdir	= "$globusdir/libexec";

$metadata->finish();

sub usage
{
    print "Usage: $0 [options]\n".
          "Options:  [--path|-p path to PBS server log]\n".
	  "          [--help|-h]\n".
          " default path is /var/spool/lsf/server_logs\n";
    exit 1;
}
