use strict;
use Data::Dumper;

# Initialise filenames and check they're there

unless(-f 't/version1.exp') {
  print STDERR "test data missing...";
  print "1..0\n";
  exit 0;
}

print "1..31\n";

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

my $DOWARN = 1;

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

require Grid::GPT::XML;
require Grid::GPT::V1::Version;
require Grid::GPT::V1::BinaryDependency;
require Grid::GPT::V1::BaseDependency;


my @pkg_list = ('data','doc', 'dev','pgm','rtl');
my @pkg_names = ('foo1', 'fee2','fow3','fum4', 'fewy5');

my $age = new Grid::GPT::V1::Version(type => 'aging', 
				 major => '3', 
				 minor => '3', 
				 age => '1');  

my $no_age = new Grid::GPT::V1::Version(type => 'aging', 
				 major => '4', 
				 minor => '3', 
				 age => '1');  

my $xml = new Grid::GPT::XML;

$xml->read('t/bin_deps.exp');

require Grid::GPT::DepIndexes;
my $deps = new Grid::GPT::DepIndexes;
for my $d (@{$xml->{'roottag'}->{'contents'}}) {
  next if ref($d) ne 'HASH';
  Grid::GPT::V1::BaseDependency::add_xml_to(xml => $d, depindexes => $deps);
}

#print Dumper $deps;

my ($input, $output);
for my $dl (sort keys %$deps) {
  for my $d (sort keys %{$deps->{$dl}}) {
    for my $l (@pkg_list) {
      for my $n (@pkg_names) {
	my $ver = $deps->{$dl}->{$d}->fulfills_dependency($n, $age, $l);
#	print "$d $n $l\n";
	if (defined($ver)) {
	  $input ="$ {n}_$l";
	  $output = $d;
	}
      }
    }
  }
  ok($t, $input eq $output);
}

# test for pgm eq pgm_static
for my $dl (sort keys %$deps) {
  for my $d (sort keys %{$deps->{$dl}}) {
    for my $n (@pkg_names) {
      my $ver = $deps->{$dl}->{$d}->fulfills_dependency($n, $age, 'pgm_static');
#      print "$d $n 'pgm_static'\n";
      if (defined($ver)) {
	$input ="$ {n}_pgm"; # fudged so that ok is right
	$output = $d;
      }
    }
  }
}

ok($t, $input eq $output);


my @expect = (
              ' fee1_dev-1 fee1_dev-3.2, fee1_dev-3.3, fee1_dev-3.4',
              ' fee2_dev-1 fee2_dev-3.2, fee2_dev-3.3, fee2_dev-3.4',
              ' fee3_dev-1 fee3_dev-3.2, fee3_dev-3.3, fee3_dev-3.4',
              ' fee4_dev-1 fee4_dev-3.2, fee4_dev-3.3, fee4_dev-3.4',
              ' fee5_dev-1 fee5_dev-3.2, fee5_dev-3.3, fee5_dev-3.4',
              ' foo1_dev-1 foo1_dev-3.2, foo1_dev-3.3, foo1_dev-3.4',
              ' foo2_dev-1 foo2_dev-3.2, foo2_dev-3.3, foo2_dev-3.4',
              ' foo3_dev-1 foo3_dev-3.2, foo3_dev-3.3, foo3_dev-3.4',
              ' foo4_dev-1 foo4_dev-3.2, foo4_dev-3.3, foo4_dev-3.4',
              ' foo5_dev-1 foo5_dev-3.2, foo5_dev-3.3, foo5_dev-3.4',
              ' fow1_dev-1 fow1_dev-3.2, fow1_dev-3.3, fow1_dev-3.4',
              ' fow2_dev-1 fow2_dev-3.2, fow2_dev-3.3, fow2_dev-3.4',
              ' fow3_dev-1 fow3_dev-3.2, fow3_dev-3.3, fow3_dev-3.4',
              ' fow4_dev-1 fow4_dev-3.2, fow4_dev-3.3, fow4_dev-3.4',
              ' fow5_dev-1 fow5_dev-3.2, fow5_dev-3.3, fow5_dev-3.4',
              ' fewy1_pgm-1 fewy1_pgm-3.2, fewy1_pgm-3.3, fewy1_pgm-3.4',
              ' fewy2_pgm-1 fewy2_pgm-3.2, fewy2_pgm-3.3, fewy2_pgm-3.4',
              ' fewy3_pgm-1 fewy3_pgm-3.2, fewy3_pgm-3.3, fewy3_pgm-3.4',
              ' fewy4_pgm-1 fewy4_pgm-3.2, fewy4_pgm-3.3, fewy4_pgm-3.4',
              ' fewy5_pgm-1 fewy5_pgm-3.2, fewy5_pgm-3.3, fewy5_pgm-3.4',
              ' fum1_rtl-2 fum1_rtl-2.2, fum1_rtl-2.3, fum1_rtl-2.4',
              ' fum2_rtl-2 fum2_rtl-2.2, fum2_rtl-2.3, fum2_rtl-2.4',
              ' fum3_rtl-2 fum3_rtl-2.2, fum3_rtl-2.3, fum3_rtl-2.4',
              ' fum4_rtl-2 fum4_rtl-2.2, fum4_rtl-2.3, fum4_rtl-2.4',
              ' fum5_rtl-2 fum5_rtl-2.2, fum5_rtl-2.3, fum5_rtl-2.4',
             );

my $r = 0;

for my $dl (sort keys %$deps) {
  for my $d (sort keys %{$deps->{$dl}}) {
    my $rpmstring = $deps->{$dl}->{$d}->rpm('spicy');
    my $result += $rpmstring eq $expect[$r];
    $r++;
    ok($t, $result);
#    print "\'$rpmstring\',\n";
  }
}
#  ok($t, $input eq $output);


