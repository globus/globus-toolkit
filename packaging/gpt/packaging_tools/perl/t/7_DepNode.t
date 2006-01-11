use strict;
use Data::Dumper;

# Initialise filenames and check they're there

unless(-f 't/src_old.exp') {
  print STDERR "test data missing...";
  print "1..0\n";
  exit 0;
}

print "1..16\n";

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
require Grid::GPT::DepIndexes;
require Grid::GPT::V1::Definitions;
require Class::ISA;

my $pkg = new Grid::GPT::V1::Package;
my $table = new Grid::GPT::DepIndexes;

$pkg->read_metadata_file('t/src_old.exp');

$table = $pkg->{'Source_Dependencies'};

open (OUT, ">t/depindexes_src.rslt");
print OUT Dumper($table->{'table'});
close OUT;
my $result = ! system("diff -b -w t/depindexes_src.rslt t/depindexes_src.exp");

ok($t, $result);

my $list = $table->query();

$list = $table->query(deptype => 'lib_link');

open (OUT, ">t/depindexes_src_query.rslt");
print OUT Dumper($list);
close OUT;
$result = ! system("diff -b -w t/depindexes_src_query.rslt t/depindexes_src_query.exp");

ok($t, $result);

$list = $table->query(deptype => 'Wonteverexist');

ok($t, @$list == 0);
