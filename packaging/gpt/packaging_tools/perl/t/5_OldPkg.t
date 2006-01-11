use strict;
use Data::Dumper;

# Initialise filenames and check they're there

unless(-f 't/src_old.exp') {
  print STDERR "test data missing...";
  print "1..0\n";
  exit 0;
}

print "1..19\n";

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

require Grid::GPT::V1::Package;
require Grid::GPT::V1::Definitions;

my $pkg = new Grid::GPT::V1::Package;

$pkg->read_metadata_file('t/src_old.input');


$pkg->output_metadata_file('t/src_old.rslt');

my $result = ! system("diff -b -w t/src_old.rslt t/src_old.exp");

ok($t, $result);

for my $typ (@Grid::GPT::V1::Definitions::package_types) {
  next if $typ eq 'src';
  my $bin_pkg = new Grid::GPT::V1::Package;
#  print "reading t/$ {typ}_old.exp\n";	
  $bin_pkg->read_metadata_file("t/$ {typ}_old.exp");	
  $bin_pkg->output_metadata_file("t/$ {typ}_old.rslt");
  $result = ! system("diff -b -w t/$ {typ}_old.rslt t/$ {typ}_old.exp");
  ok($t, $result);
}

for my $typ (@Grid::GPT::V1::Definitions::package_types) {
  next if $typ eq 'src';
  my $flavor = "spicy";
  my $bin_pkg = $pkg->convert_metadata($typ, $flavor);
  $bin_pkg->output_metadata_file("t/$ {typ}_old.rslt");
  $result = ! system("diff -b -w t/$ {typ}_old.rslt t/$ {typ}_old.exp");
  ok($t, $result);
}

for my $typ (@Grid::GPT::V1::Definitions::package_types) {
  next if $typ eq 'src';
  my $flavor = "spicy";
  my $bin_pkg = $pkg->convert_metadata($typ, $flavor);
  my $rpm = $bin_pkg->rpm();
  open(OUT, ">t/$ {typ}_rpm.rslt");
  for (sort keys %$rpm) {
    print OUT "$_: $rpm->{$_}\n";
  }
  close OUT;
  $result = ! system("diff -b -w t/$ {typ}_rpm.rslt t/$ {typ}_rpm.exp");
  ok($t, $result);
}
exit;

$ENV{'GLOBUS_LOCATION'} = "t";

$pkg=new Grid::GPT::V1::Package(installed_pkg=>"foo", flavor=>"gcc32", type=>"pgm");
$result=($pkg->{installed_pkg} eq 'foo');
ok($t, $result);

$pkg=new Grid::GPT::V1::Package(installed_pkg=>"fee", flavor=>"gcc32", type=>"data");
$result=($pkg->{installed_pkg} eq 'fee');
ok($t, $result);

$pkg=new Grid::GPT::V1::Package(installed_pkg=>"fum", flavor=>"gcc32", type=>"pgm");
$result=($pkg->{installed_pkg} eq 'fum');
ok($t, $result)
