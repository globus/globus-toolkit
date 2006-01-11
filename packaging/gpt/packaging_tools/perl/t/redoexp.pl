#! /usr/bin/env perl
use Getopt::Long;

my $test;

GetOptions(t => \$test) 
  or usage();

if (!defined($ARGV[0])) {
  usage();
}

$regex = qr/$ARGV[0]/;

opendir(T, "t");

my @files = grep { m!$regex! } grep { m!\.rslt! } readdir T;

for my $f(@files) {
  my $exp = $f;
  $exp =~ s!\.rslt!\.exp!;
  print "cp t/$f t/$exp\n";
  system "cp t/$f t/$exp\n" if ! defined $test;
}

closedir T;
sub usage
  {
    print "USAGE: t/redoexp.pl [-test] perl_regex";
    exit;
  }
