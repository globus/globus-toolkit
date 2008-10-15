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

my $path                = $ENV{GLOBUS_LOCATION} . '/var/globus-fake.log';
my $help		= 0;

GetOptions('path|p=s' => \$path,
	   'help|h' => \$help);

&usage if $help;

if (-e $path) {
    if (-o $path) {
        chmod(0622, $path);
    } else {
        print STDERR "Log file $path exists but is not owned by this user\n";
        exit(1);
    }
} else {
    if (! open(LOG, ">$path")) {
        print STDERR "Unable to create log file at $path\n";
        exit (1);
    }
    chmod(0622, $path);
}

my $metadata =
    new Grid::GPT::Setup(package_name =>
            'globus_scheduler_event_generator_fake_setup');

my $globusdir	= $ENV{GLOBUS_LOCATION};
my $libexecdir	= "$globusdir/libexec";
local(*FP);

open(FP, ">$globusdir/etc/globus-fake.conf");
print FP "log_path=$path\n";
close(FP);

$metadata->finish();

sub usage
{
    print "Usage: $0 [options]\n".
          "Options:  [--path|-p path to Fake server log]\n".
	  "          [--help|-h]\n".
          " default path is $ENV{GLOBUS_LOCATION}/var/globus-fake.log\n";
    exit 1;
}
