use strict;
use Data::Dumper;

# Initialise filenames and check they're there

unless(-f 't/version1.exp') {
  print STDERR "test data missing...";
  print "1..0\n";
  exit 0;
}

print "1..13\n";

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
require Grid::GPT::V1::SourceDependency;
require Grid::GPT::V1::BaseDependency;


my @pkg_list = ('data','doc', 'dev','pgm','pgm_static','rtl');
my @pkg_names = ('foo1', 'pl_foo2','ll_foo3','dr_foo4', 'docr_foo5', 'pr_foo1', 'lr_foo1');

my $age = new Grid::GPT::V1::Version(type => 'aging', 
				 major => '3', 
				 minor => '3', 
				 age => '1');  

my $no_age = new Grid::GPT::V1::Version(type => 'aging', 
				 major => '4', 
				 minor => '3', 
				 age => '1');  

my $xml = new Grid::GPT::XML;

$xml->read('t/src_deps.exp');

my $deps = {};
for my $d (@{$xml->{'roottag'}->{'contents'}}) {
  next if ref($d) ne 'HASH';
  Grid::GPT::V1::BaseDependency::add_xml_to(xml => $d, depshash => $deps);
}

for my $dl (sort keys %$deps) {
my ($input, $output) = ("in","out");
  for my $d (sort keys %{$deps->{$dl}}) {
    for my $l (@pkg_list) {
      for my $n (@pkg_names) {
	my $ver = $deps->{$dl}->{$d}->fulfills_dependency($n, $age, $l);
#	print "$d $dl->{$d}->{'type'} $n $l\n";
	if (defined($ver)) {
	  $input ="$ {n}_$l";
	  my $gen_pkg_hdr = $deps->{$dl}->{$d}->src2bin_dep_extension($l);
	  my $pname = $d;
	  $pname =~ s!_(data|doc|dev|pgm|pgm_static|rtl)!!;
	  $pname =~ s!_$!!;	  
	  $output = "$ {pname}_$gen_pkg_hdr";
#	  print "$ {pname}_$gen_pkg_hdr ..........matched\n";
	}
      }
    }
  }
  ok($t, $input eq $output);
}


for my $p (@pkg_list) {
  $xml = new Grid::GPT::XML;
  $xml->startTag("Test_Dependencies");
  $xml->characters("\n");

  my $bindeps = Grid::GPT::V1::SourceDependency::get_bindeps_from($deps, $p);
  Grid::GPT::V1::BaseDependency::get_xml_from($bindeps, $xml, 'Binary_Dependencies') 
      if $bindeps;
  $xml->doctype("0.01", "no.dtd");
#  print Dumper $xml;
  my $rootfile = "src2$ {p}";
  $xml->write("t/$rootfile.rslt");
  my $result = ! system("diff -b t/$rootfile.rslt t/$rootfile.exp");
  ok($t, $result);

}
