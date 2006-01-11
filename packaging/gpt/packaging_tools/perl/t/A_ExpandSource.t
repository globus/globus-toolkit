use strict;
use Data::Dumper;
use File::Find;

# Initialise filenames and check they're there

unless(-f 't/expand_source_test3.tar.gz') {
  print STDERR "test data missing...";
  print "1..0\n";
  exit 0;
}
print "1..5\n";

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

require Grid::GPT::PkgMngmt::ExpandSource;


sub print_ok {
  my($t, $result, $obj) = @_;
  ok($t, $result);

  if (! $result) {
    print "srcdir = $obj->{'srcdir'}\n" if defined $obj->{'srcdir'};
    print "patchdir = $obj->{'patchdir'}\n" if defined $obj->{'patchdir'};
    print "srcfile = $obj->{'srcfile'}\n" if defined $obj->{'srcfile'};
  }
}

my $expsrc = new Grid::GPT::PkgMngmt::ExpandSource( srcdir => "t/expand_source_test2",
                                          srcfile => "t/expand_source_test2/pkg_data_src.gpt",
                                        );
$expsrc->setup_source();
my $result = $expsrc->{'srcdir'} =~ m!t/expand_source_test2! &&
  $expsrc->{'srcfile'} =~  m!t/expand_source_test2/pkg_data_src\.gpt!;

print_ok($t, $result, $expsrc);

$expsrc = new Grid::GPT::PkgMngmt::ExpandSource( srcdir => "t/expand_source_test1");
$expsrc->setup_source();

$result = $expsrc->{'srcdir'}  =~ m!t/expand_source_test1! &&
  $expsrc->{'srcfile'} =~ m!expand_source_test1/pkgdata/pkg_data_src\.gpt\.in$!;


print_ok($t, $result, $expsrc);

$expsrc = new Grid::GPT::PkgMngmt::ExpandSource( srcdir => "t/expand_source_test2");
$expsrc->setup_source();

$result = $expsrc->{'srcdir'}  =~ m!t/expand_source_test2/+foo\-1\.0! &&
  $expsrc->{'srcfile'} =~ m!expand_source_test2/+pkg_data_src\.gpt$!;

print_ok($t, $result, $expsrc);

$expsrc = new Grid::GPT::PkgMngmt::ExpandSource( tarfile => "t/expand_source_test3.tar.gz",
                                     builddir => "t");
$expsrc->setup_source();

$result = $expsrc->{'srcdir'}  =~ m!t/expand_source_test3! &&
  $expsrc->{'srcfile'} =~ m!expand_source_test3/+pkgdata/+pkg_data_src\.gpt\.in$!;

print_ok($t, $result, $expsrc);

$expsrc = new Grid::GPT::PkgMngmt::ExpandSource( tarfile => "t/expand_source_test4.tar.gz",
                                     builddir => "t");
$expsrc->setup_source();

$result = $expsrc->{'srcdir'}  =~ m!t/expand_source_test4! &&
  -f "t/expand_source_test4/foo-1.0/configure.in" &&
  $expsrc->{'srcfile'} =~ m!expand_source_test4/+pkg_data_src\.gpt$!;

print_ok($t, $result, $expsrc);

$result = `rm -r t/expand_source_test[34]`;
