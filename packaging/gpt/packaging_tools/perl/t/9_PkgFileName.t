use strict;
use Data::Dumper;

print "1..22\n";

my $t = 1;

##############################################################################
#                   S U P P O R T   R O U T I N E S
##############################################################################

##############################################################################
# Print out 'n ok' or 'n not ok' as expected by test harness.
# First arg is test number (n).  If only one following arg, it is interpreted
# as true/false value.  If two args, equality = true.
#

sub ok {
  my($n, $x, $y) = @_;
  die "Sequence error got $n expected $t" if($n != $t);
  $x = 0 if(@_ > 2  and  $x ne $y);
  print(($x ? '' : 'not '), 'ok ', $t++, "\n");
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

require Grid::GPT::PkgFileName;
require Grid::GPT::Locations;

my @tests = (
             ["globus_flue-gcc32-pgm", "globus_flue","gcc32","pgm"],
             ["globus_flue-*-pgm", "globus_flue","ANY","pgm"],
             ["globus_flue-gcc32-*", "globus_flue","gcc32","ANY"],
             ["globus_flue-*-*", "globus_flue","ANY","ANY"],
             ["*-*-pgm", "ANY","ANY","pgm"],
             ["*-gcc32-*", "ANY","gcc32","ANY"],
             ["*-*-*", "ANY","ANY","ANY"],
             ["globus-flue-gcc32", "globus-flue","gcc32","ANY"],
             ["globus-flue", "globus-flue","ANY","ANY"],
             ["globus-flue-gcc32-pgm", "globus-flue","gcc32","pgm"],
             ["globus-flue-*-pgm", "globus-flue","ANY","pgm"],
             ["globus-flue-gcc32-*", "globus-flue","gcc32","ANY"],
             ["globus-flue-*-*", "globus-flue","ANY","ANY"],
             ["globus-flue-gcc32", "globus-flue","gcc32","ANY"],
             ["globus-flue", "globus-flue","ANY","ANY"],
             ["globus_flue-gcc32_pgm", "globus_flue","gcc32","pgm"],
             ["globus_flue-*_pgm", "globus_flue","ANY","pgm"],
             ["globus_flue-gcc32_*", "globus_flue","gcc32","ANY"],
             ["globus-flue-gcc32_pgm", "globus-flue","gcc32","pgm"],
             ["globus-flue-*_pgm", "globus-flue","ANY","pgm"],
             ["globus-flue-gcc32_*", "globus-flue","gcc32","ANY"],
             ["globus-flue-gxx32-booboo", "globus-flue-gxx32-booboo","ANY","ANY"],
            );

my $locations = new Grid::GPT::Locations();
my $parser = new Grid::GPT::PkgFileName(locations => $locations);

for my $tst(@tests) {
  my $parsed = $parser->parse_name($tst->[0]);
  my $result = $parsed->{'pkgname'} eq $tst->[1] and 
    $parsed->{'flavor'} eq $tst->[2] and 
      $parsed->{'pkgtype'} eq $tst->[3];

  ok($t, $result);

  if (! $result) {
    print "$tst->[0] == |$parsed->{'pkgname'}|$parsed->{'flavor'}|$parsed->{'pkgtype'}| should be |$tst->[1]|$tst->[2]|$tst->[3]|\n";
  }

}

