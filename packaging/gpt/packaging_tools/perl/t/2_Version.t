use strict;
use Data::Dumper;

# Initialise filenames and check they're there

unless(-f 't/version1.exp') {
  print STDERR "test data missing...";
  print "1..0\n";
  exit 0;
}

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

my $age = new Grid::GPT::V1::Version(type => 'aging', 
				 major => '3', 
				 minor => '3', 
				 age => '1');  

my $xml = new Grid::GPT::XML;

$xml->read('t/version1.exp');

my $list = Grid::GPT::V1::Version::create_version_list($xml->{'roottag'});

my @expect = ("0", "1","0","1","0","1", "0");
my $r = 0;
for my $v (@$list) {
	my $result = $v->is_compatible($age);
	$result = $result == $expect[$r];
	ok($t, $result);
	$result = $age->is_compatible($v);
	$result = $result == $expect[$r];
	ok($t, $result);
	$r++;
}

my @testversions = (
                    {
                     type => 'aging', 
                     major => '4', 
                     minor => '3', 
                     age => '1'
                    },
                    {
                     type => 'aging', 
                     major => '4', 
                     minor => '2', 
                     age => '1'
                    },
                    {
                     type => 'aging', 
                     major => '3', 
                     minor => '4', 
                     age => '1'
                    },
                    {
                     type => 'aging', 
                     major => '3', 
                     minor => '3', 
                     age => '1'
                    },
                    {
                     type => 'aging', 
                     major => '3', 
                     minor => '2', 
                     age => '1'
                    },
                    {
                     type => 'aging', 
                     major => '2', 
                     minor => '4', 
                     age => '1'
                    },
                    {
                     type => 'simple', 
                     major => '3', 
                     minor => '3', 
                    },
                    {
                     type => 'aging', 
                     major => '3', 
                     minor => '3', 
                     age => '2'
                    },

                   );
@expect = ("0", "0","0","1","0","0", "0","0");
my @expect1 = ("0", "0","0","0","1","1","0","0");

$r = 0;

for my $tv (@testversions) {
  my $v = new Grid::GPT::V1::Version(%$tv);

  print "Version: ",$v->label(),"\n";

  my $result = $age->is_equal($v);
  $result = $result == $expect[$r];
  ok($t, $result);
  $result = $age->is_newer($v);
  $result = $result == $expect1[$r];
  ok($t, $result);
  $r++;
}




@expect = ('foo-1',
           'foo-2',
           'foo-1, foo-2',
           'foo-1, foo-2, foo-3',
           'foo-3.1, foo-3.2',
           'foo-3.2, foo-3.3, foo-3.4',
           'foo-2.1, foo-2.2, foo-2.3, foo-2.4, foo-2.5, foo-2.6, foo-2.7, foo-2.8, foo-2.9, foo-3.0, foo-3.1, foo-3.2',
          );
$r = 0;

for my $v (@$list) {
	my $rpmstring = $v->rpm("foo");
	my $vstring = $v->label();
	my $result = $rpmstring eq $expect[$r];
	ok($t, $result);
#        print "\'$rpmstring\',\n"
	$r++;
}

my $rpmstring = $age->rpm("foo");
my $result = $rpmstring eq 'foo-2, foo-3';
ok($t, $result);

