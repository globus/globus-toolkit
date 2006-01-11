use strict;
use Data::Dumper;
use File::Find;

# Initialise filenames and check they're there

print "1..10\n";

my $t = 1;

##############################################################################
#                   S U P P O R T   R O U T I N E S
##############################################################################

##############################################################################
# Print out 'n ok' or 'n not ok' as expected by test harness.
# First arg is test number (n).  If only one following arg, it is interpreted
# as true/false value.  If two args, equality = true.
#

my @list;

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

require Grid::GPT::BuildFlavors;


sub print_ok {
  my($t, $result, $obj) = @_;
  ok($t, $result);
}

my $flavors = new Grid::GPT::BuildFlavors(core => 1);

open(OUT, ">t/permute.rslt");

for my $l (@{$flavors->{'flavors'}}) {
  my $config = $flavors->{$l}->build_core_configure_line();
  print OUT "$config->{'flavor'} $config->{'switches'} $config->{'env'} \n";
}

close OUT;

my $result = ! system("diff t/permute.exp t/permute.rslt");

print_ok($t, $result);

my $stdflavors = new Grid::GPT::BuildFlavors(core => 1, std => 1);

open(OUT, ">t/std_permute.rslt");

for my $l (@{$stdflavors->{'flavors'}}) {
  my $config = $stdflavors->{$l}->build_core_configure_line();
  print OUT "$config->{'flavor'} $config->{'switches'} $config->{'env'} \n";
}

close OUT;

$result = ! system("diff t/std_permute.exp t/std_permute.rslt");

print_ok($t, $result);


my $f = 0;
for my $bp("t/build-parameters",
           "t/build-parameters1",
           "t/build-parameters2",
           "t/build-parameters3") {
  my $myflavor =
    new Grid::GPT::FlavorDefinition(name => "dingbat$f", 
                          build_parameters => $bp);
  
  $myflavor->write_xml(filename => "t/dingbat$f.rslt");
  my $result = ! system("diff t/dingbat$f.exp t/dingbat$f.rslt");
  print_ok($t, $result);
  $f++;
}

$f = 0;

for my $bp("t/dingbat0.exp",
           "t/dingbat1.exp",
           "t/dingbat2.exp",
           "t/dingbat3.exp",
          ) {
  my $myflavor =
    new Grid::GPT::FlavorDefinition(xmlfile => $bp);  
  $myflavor->write_xml(filename => "t/second$f.rslt");
  my $result = ! system("diff t/dingbat$f.exp t/second$f.rslt");
  print_ok($t, $result);
  $f++;
}

my $weird_flavors = new Grid::GPT::BuildFlavors(core => 1, 
                                                cfg => 't/weird_flavors.exp');
open(OUT, ">t/translate.rslt");

for my $f (@{$flavors->{'flavors'}}) {
  my $config = $flavors->{$f}->translate_configure_line($weird_flavors->{'choices'});
  print OUT "SWITCHES: $config->{'switches'} ENV: $config->{'env'} \n";

}

close OUT;
