use strict;
use Data::Dumper;

# Initialise filenames and check they're there

unless(-f 't/src_old.exp') {
  print STDERR "test data missing...";
  print "1..0\n";
  exit 0;
}

print "1..7\n";

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

require Grid::GPT::Installation;
require Grid::GPT::SetupInstallation;
require Grid::GPT::PackageFactory;
#require Class::ISA;


sub print_missing {
  my ($miss) = @_;
  print "Package ";
  $miss->{'pkg'}->printnode();
  print "Needs ";
  $miss->{'needs'}->printnode();

}


if (! -d "t/depdir") {
  system("perl t/gendeptrees");
}


my $installation = 
  new Grid::GPT::Installation(pkgdir => 't/depdir/etc/globus_packages');
#  new Grid::GPT::Installation();

open (OUT, ">t/runtime_order.rslt");
select OUT;
$installation->set_depenv('Runtime');
print "++++++++++++++++Table++++++++++++++++++\n";
$installation->printtable(full=>1);
$installation->sort_pkgs();

print "++++++++++++++++Sorted++++++++++++++++++\n";

for my $p (@{$installation->sorted()}) {
  $p->printnode();
}
print "++++++++++++++++Missing+++++++++++++++++\n";

for my $p (@{$installation->missing()}) {
  print_missing($p);
}
select STDOUT;
close OUT;

my $result = ! system("diff -b -w t/runtime_order.rslt t/runtime_order.exp");

ok($t, $result);

open (OUT, ">t/build_order.rslt");
select OUT;
$installation->set_depenv('Build');
print "++++++++++++++++Table++++++++++++++++++\n";
$installation->printtable(full=>1);
$installation->sort_pkgs();

print "++++++++++++++++Sorted++++++++++++++++++\n";

for my $p (@{$installation->sorted()}) {
  $p->printnode();
}
print "++++++++++++++++Missing+++++++++++++++++\n";

for my $p (@{$installation->missing()}) {
  print_missing($p);
}
select STDOUT;
close OUT;

$result = ! system("diff -b -w t/build_order.rslt t/build_order.exp");

ok($t, $result);

open (OUT, ">t/setup_needs.rslt");
select OUT;
my $setupinstallation = 
  new Grid::GPT::SetupInstallation(pkgdir => 't/depdir/etc/globus_packages');

my $list = $installation->setup_pkgs();
$list = $setupinstallation->check_for_setup_needs(pkgs=>$list);

for (@$list) {
  $_->printnode();
}
select STDOUT;
close OUT;

$result = ! system("diff -b -w t/setup_needs.rslt t/setup_needs.exp");

ok($t, $result);

open (OUT, ">t/setup_order.rslt");
select OUT;
$installation->set_depenv('Setup');
print "++++++++++++++++Table++++++++++++++++++\n";
$installation->printtable(full=>1);
$installation->sort_pkgs();

print "++++++++++++++++Sorted++++++++++++++++++\n";

for my $p (@{$installation->sorted()}) {
  $p->printnode();
}
print "++++++++++++++++Missing+++++++++++++++++\n";

for my $p (@{$installation->missing()}) {
  print_missing($p);
}
select STDOUT;
close OUT;
$result = ! system("diff -b -w t/setup_order.rslt t/setup_order.exp");

ok($t, $result);

my $installation = 
  new Grid::GPT::Installation(pkgdir => 't/depdir/etc/globus_packages');

opendir (SRCPKGS, "t/depdir");

my @srcpkgs = grep { ! m!^complexsrc! } grep { m!\.gpt$! } readdir SRCPKGS;

closedir SRCPKGS;

my $factory = new Grid::GPT::PackageFactory;

for my $s(@srcpkgs) {
  my $file = "t/depdir/$s";
  my $pkg = $factory->type_of_package($file);
  $pkg->read_metadata_file($file);
  $installation->add_package(pkg => $pkg);
}

open (OUT, ">t/installsrcbuild_order.rslt");
select OUT;
$installation->set_depenv('Build');
print "++++++++++++++++Table++++++++++++++++++\n";
$installation->printtable(full=>1);
$installation->sort_pkgs();

print "++++++++++++++++Sorted++++++++++++++++++\n";

for my $p (@{$installation->sorted()}) {
  $p->printnode();
}
print "++++++++++++++++Missing+++++++++++++++++\n";

for my $p (@{$installation->missing()}) {
  print_missing($p);
}
select STDOUT;
close OUT;

$result = ! system("diff -b -w t/installsrcbuild_order.rslt t/installsrcbuild_order.exp");

ok($t, $result);

open (OUT, ">t/lib_order.rslt");
select OUT;
my $extracted = $installation->query_pkgset(
                                            pkgnames => ['source_link_dev',
                                                         'source_complex_link_dev'],
                                            pkgtype => 'src',
                                            flavor => 'bitter'
                                           );
my $libs = $extracted->get_sorted_buildenvs();

print "++++++++++++++++Sorted++++++++++++++++++\n";

for my $p (@{$extracted->sorted()}) {
  $p->printnode();
}
print "++++++++++++++++Missing+++++++++++++++++\n";

for my $p (@{$extracted->missing()}) {
  print_missing($p);
}

print "++++++++++++++++Libraries+++++++++++++++++\n";
for my $l(@$libs) {
  print "/ext_libs=$l->{'ext_libs'}/pkglibs=$l->{'pkg_libs'}\n";
}

$installation = 
  new Grid::GPT::Installation(pkgdir => 't/depdir/etc/globus_packages');

my $srcpkg = $factory->type_of_package("t/srcdeps/source_complex2_src.gpt");
$srcpkg->read_metadata_file("t/srcdeps/source_complex2_src.gpt");

my $srcnode = $installation->add_package(pkg =>$srcpkg);
my $setpkg = $factory->type_of_package("t/srcdeps/source_complex2_setup_src.gpt");
$setpkg->read_metadata_file("t/srcdeps/source_complex2_setup_src.gpt");

my $setnode = $installation->add_package(pkg =>$setpkg);
$installation->set_depenv('BuildandSetup');
#$installation->printtable(full => 1);

$extracted = $installation->extract_deptree(
                                           srcpkg => $srcnode,
                                           srcdep => 'pgm_link',
                                           );

$libs = $extracted->get_sorted_buildenvs();
print "++++++++++++++++Sorted++++++++++++++++++\n";

for my $p (@{$extracted->sorted()}) {
  $p->printnode();
}
print "++++++++++++++++Missing+++++++++++++++++\n";

for my $p (@{$extracted->missing()}) {
  print_missing($p);
}

print "++++++++++++++++Libraries+++++++++++++++++\n";
for my $l(@$libs) {
  print "/ext_libs=$l->{'ext_libs'}/pkglibs=$l->{'pkg_libs'}\n";
}

$extracted = $installation->extract_deptree(
                                            srcpkg => $srcnode,
                                            srcdep => 'lib_link',
                                           );

$libs = $extracted->get_sorted_buildenvs();

print "++++++++++++++++Sorted++++++++++++++++++\n";

for my $p (@{$extracted->sorted()}) {
  $p->printnode();
}
print "++++++++++++++++Missing+++++++++++++++++\n";

for my $p (@{$extracted->missing()}) {
  print_missing($p);
}

print "++++++++++++++++Libraries+++++++++++++++++\n";
for my $l(@$libs) {
  print "/ext_libs=$l->{'ext_libs'}/pkglibs=$l->{'pkg_libs'}\n";
}


select STDOUT;
close OUT;

$result = ! system("diff -b -w t/lib_order.rslt t/lib_order.exp");

ok($t, $result);

#$extracted->printtable();

#for my $p (@{$extracted->sorted()}) {
#  $p->printnode();
#}




opendir (SRCPKGS, "t/depdir");

my $bundle = new Grid::GPT::PkgSet;

my @srcpkgs = grep { m!^complexsrc! } readdir SRCPKGS;

closedir SRCPKGS;


for my $s(@srcpkgs) {
  my $file = "t/depdir/$s";
  my $pkg = $factory->type_of_package($file);
  $pkg->read_metadata_file($file);
  $bundle->add_package(pkg => $pkg);
}

open (OUT, ">t/srcbuild_order.rslt");
select OUT;
$bundle->set_depenv('Build');
print "++++++++++++++++Table++++++++++++++++++\n";
$bundle->printtable(full=>1);
$bundle->sort_pkgs();

print "++++++++++++++++Sorted++++++++++++++++++\n";

for my $p (@{$bundle->sorted()}) {
  $p->printnode();
}
print "++++++++++++++++Missing+++++++++++++++++\n";

for my $p (@{$bundle->missing()}) {
  print_missing($p);
}
select STDOUT;
close OUT;

$result = ! system("diff -b -w t/srcbuild_order.rslt t/srcbuild_order.exp");

ok($t, $result);

