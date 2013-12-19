#! /usr/bin/perl

require 5.8.0;

use strict;
use File::Basename;
use Getopt::Long;
use Test::Harness;
use lib dirname($0);

use vars qw(@tests);
sub test_exec
{
    my ($harness, $test_file) = @_;
    if ($test_file =~ /.pl$/) {
        if (-f dirname($0)."/".$test_file) {
            return dirname($0)."/".$test_file;
        } else {
            return undef;
        }
    } else {
        my @cmd;
        my $valgrind="";
        if (exists $ENV{VALGRIND})
        {
            push(@cmd, 'valgrind');
            push(@cmd, "--log-file=VALGRIND-$test_file.log");
            if (exists $ENV{VALGRIND_OPTIONS})
            {
                for my $opt (split(/\s+/, $ENV{VALGRIND_OPTIONS})) {
                    if ($opt ne '') {
                        push(@cmd, $opt);
                    }
                }
            }
        }
        push(@cmd, "./$test_file");
        return \@cmd;
    }
}
my $harness_class = "TAP::Harness";

if (!GetOptions("harness=s" => \$harness_class))
{
    print STDERR "Usage: $0 [-harness CLASSNAME]\n";
    exit(1);
}
            
eval "use $harness_class";

my $harness_args = {'exec' => \&test_exec, 'merge' => 1};
my $harness = $harness_class->new($harness_args);

my $test_result = 1;
$|=1;

@tests = qw(
   seg-api-test.pl seg-module-load-test  seg-timestamp-test
);
$harness->runtests(@tests)
