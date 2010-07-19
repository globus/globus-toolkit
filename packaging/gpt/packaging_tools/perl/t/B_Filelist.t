use strict;

# Initialise filenames and check they're there

unless(-f 't/master.filelist') {
  print STDERR "test data missing...";
  print "1..0\n";
  exit 0;
}

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

sub ok {
  my($n, $x, $y) = @_;
  die "Sequence error got $n expected $t" if($n != $t);
  $x = 0 if(@_ > 2  and  $x ne $y);
  print(($x ? '' : 'not '), 'ok ', $t++, "\n");
}

sub dump_list {
  my ($name, $list) = @_;
  open(OUT, ">t/$ {name}.rslt");
  for (sort @{$list}) {
    print OUT "$_\n";
  }
  close OUT;
  my $result = ! system("diff t/$ {name}.exp t/$ {name}.rslt");
  ok($t,$result);
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

require Grid::GPT::Filelist;
require Grid::GPT::Definitions;

my $pkg = new Grid::GPT::Filelist;

open(MASTER, 't/master.filelist');
my @master = <MASTER>;
close MASTER;

my $obj = new Grid::GPT::Filelist(list => \@master, flavor => 'sweet');

$obj->flavored_files();
my $list = $obj->get_list();
dump_list("flavored_files",$list);
$obj->reset();

$obj->noflavor_files();
$list = $obj->get_list();
dump_list("noflavor_files",$list);
$obj->reset();

$obj->flavored_headers();
$list = $obj->get_list();
dump_list("flavored_headers",$list);
$obj->reset();

$obj->noflavor_headers();
$list = $obj->get_list();
dump_list("noflavor_headers",$list);
$obj->reset();

$obj->extract_programs();
$list = $obj->get_list();
dump_list("extract_programs",$list);
$obj->reset();

$obj->extract_static_libs();
$list = $obj->get_list();
dump_list("extract_static_libs",$list);
$obj->reset();

$obj->extract_dynamic_libs();
$list = $obj->get_list();
dump_list("extract_dynamic_libs",$list);
$obj->reset();

$obj->extract_libtool_libs();
$list = $obj->get_list();
dump_list("extract_libtool_libs",$list);
$obj->reset();

$obj->extract_docs();
$list = $obj->get_list();
dump_list("extract_docs",$list);
$obj->reset();

$obj->extract_data();
$list = $obj->get_list();
dump_list("extract_data",$list);
$obj->reset();



