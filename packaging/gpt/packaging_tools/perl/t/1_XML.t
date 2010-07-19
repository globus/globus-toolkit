use strict;
use Data::Dumper;

# Initialise filenames and check they're there

unless(-f 't/xml_data.exp') {
  print STDERR "test data missing...";
  print "1..0\n";
  exit 0;
}

print "1..2\n";

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
BEGIN { $SIG{'__WARN__'} = sub { warn $_[0] if $DOWARN } };
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

my $xml = new Grid::GPT::XML;

$xml->read('t/xml_data.exp');

$xml->write('t/xml_data.rslt');

my $result = ! system("diff -b t/xml_data.rslt t/xml_data.exp");
ok($t, $result);

$xml = new Grid::GPT::XML;

$DOWARN = 0;
$xml->read('t/xml_bad.exp');
$DOWARN = 1;

open(OUT,">t/xml_errors.rslt");

for my $e (@{$xml->{'errors'}}) {
	print OUT "$e\n";	
}
close OUT;

$result = ! system("diff -b t/xml_errors.rslt t/xml_errors.exp");
ok($t, $result);


