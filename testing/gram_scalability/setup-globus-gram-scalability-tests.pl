#use Grid::GPT::Setup;
use Getopt::Long;
use strict;

my $help;

GetOptions('help|h' => \$help);

&usage if $help;

sub usage {
    print "Usage: $0 [-help]\n";
    exit 1;
}

sub get_condor_os_arch {
    my $condor_os;
    my $condor_arch;
    open(CONDOR_STATUS, "$ENV{GLOBUS_SH_CONDOR_STATUS} |")
        or die "ERROR: unable to execute $ENV{GLOBUS_SH_CONDOR_STATUS}";
    while (<CONDOR_STATUS>) {
        s/[^A-Z]+([A-Z]+)\/([A-Z]+).+/$1\/$2/;
        if (/\//) {
            (my $condor_os_upper, my $condor_arch_upper) = split '\/';

            my $condor_os_lower = $condor_os_upper;
            $condor_os_lower =~ tr/[A-Z]/[a-z]/;
            $condor_os
                = substr($condor_os_upper, 0, 1)
                . substr($condor_os_lower, 1, length($condor_os_lower)-1);

            my $condor_arch_lower = $condor_arch_upper;
            $condor_arch_lower =~ tr/[A-Z]/[a-z]/;
            chomp($condor_arch_lower);
            $condor_arch
                = substr($condor_arch_upper, 0, 1)
                . substr($condor_arch_lower, 1, length($condor_arch_upper)-1);
        };
    }
    close(CONDOR_STATUS);

    return ($condor_os, $condor_arch);
}

#my $metadata =
    #new Grid::GPT::Setup(package_name => "globus_gram_scalability_tests_setup");

my @condor_os_arch_list = get_condor_os_arch();
my $condor_os_arch = $condor_os_arch_list[0] . $condor_os_arch_list[1];

my %small_names=(
    "Condor$condor_os_arch" => "condor",
    "Fork"                  => "fork",
    "Lsf"                   => "lsf",
    "Pbs"                   => "pbs");
my %stat_pgms=(
    "Condor$condor_os_arch" => $ENV{GLOBUS_SH_CONDOR_STATUS},
    "Fork"                  => $ENV{GLOBUS_SH_PS},
    "Lsf"                   => $ENV{GLOBUS_SH_BJOBS},
    "Pbs"                   => $ENV{GLOBUS_SH_QSTAT});
my %templates=(
    "stress"        => "stress-SCHEDULER-mmjfs-test.in",
    "submit"        => "submit-SCHEDULER-mmjfs-test.in",
    "deactivation"  => "deactivation-SCHEDULER-mmjfs-test.in",
    "kill"          => "kill-SCHEDULER-mjfs-job.in",
    "monitor"       => "monitor-SCHEDULER-jobs.in");

my $directory = "$ENV{GLOBUS_LOCATION}/test/globus_gram_scalability_test";
my $keyword = "SCHEDULER";

foreach my $scheduler (keys(%small_names)) {
    my %filenames=(
        "stress"       => "stress-$small_names{$scheduler}-mmjfs-test.sh",
        "submit"       => "submit-$small_names{$scheduler}-mmjfs-test.sh",
        "deactivation" => "deactivation-$small_names{$scheduler}-mmjfs-test.sh",
        "kill"         => "kill-$small_names{$scheduler}-mjfs-job.sh");
        #"monitor"   => "monitor-$small_names{$scheduler}-jobs.sh");

    foreach my $script_type (keys(%filenames)) {
        my $script = "$directory/$filenames{$script_type}";
        print "generating $script\n";
        open(TEMPLATE, "$templates{$script_type}")
            or die "ERROR: unable to open $templates{$script_type} for reading";
        open(SCRIPT, ">$script")
            or die "ERROR: unable to open $script for writing";

            while (<TEMPLATE>) {
                s/$keyword/$scheduler/;
                print SCRIPT;
            }

            chmod(0755, $script);

        close(SCRIPT);
        close(TEMPLATE);
    }
}

#$metadata->finish();

END{};
1;
