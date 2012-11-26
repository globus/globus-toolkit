#!/usr/bin/env perl

use File::Find;
use Data::Dumper;
use Cwd;

 my $gpt_dir;
    my $gpt_ver;
    my $target;
 my @packagelist;
$top_dir = cwd();

    # we maintain a patched copy of gpt - find out what we call it
    $gpt_ver = `cat $top_dir/gpt/gpt_version`;
    chomp($gpt_ver);
    $gpt_ver = "gpt-$gpt_ver";
    $gpt_dir = $top_dir . "/$gpt_ver";
    $ENV{'GPT_LOCATION'} = $gpt_dir;


@INC = ("$ENV{GPT_LOCATION}/lib/perl", @INC);
my $source_output = $top_dir . "/source-output";
mkdir $source_output;
$ENV{GLOBUS_LOCATION} = "$source_output/tmp_core";


my %packagemap;

#find(\&is_metadata, './source-trees');
require Grid::GPT::PkgDist;
my $dist = new Grid::GPT::PkgDist;
find(\&is_spec, './source-trees');
#$dist->load_dist_from_list(@packagelist);
#to get the PkgDist object to actually read in metadata and sort it, we need to
#put the packagelist into its structure.  This API sucks, but, well, it's legacy
$dist->{'pkgs_gpt'}=\@packagelist;
$dist->load_dist_from_list($dist);
    $dist->cleardepenv();
    $dist->set_depenv('Build');
	$dist->sort_pkgs();
  my @nocorepkgs = grep { $_->pkgname ne 'globus_core' }
      @{ ( $dist->sorted())};
  my @corepkgs = grep { $_->pkgname eq 'globus_core' }
      @{ ( $dist->sorted() )};
  my @sorted_package_names;
#  for my $p (@corepkgs){
#    push (@sorted_package_names, $p->pkgname);
#  }
  for my $p (@nocorepkgs){
    push (@sorted_package_names, $p->pkgname);
  }
#print "Sorted package names are:\n";
#print Dumper @sorted_package_names;
#bootstrap(@sorted_package_names);
build(@sorted_package_names);

#	print @{$dist->{'sorted'}};
#for my $p(@{$dist->{'sorted'}}) {
#for my $p(@nocorepkgs) {
#  print $p->pkgname();
#}

sub is_metadata{
if ($File::Find::dir =~ /pkgdata$/){
     print "$File::Find::dir is a pkgdata dir\n";
if (($File::Find::name =~/pkg_data_src\.gpt\.in/)){
      print "$File::Find::name\n";
        require Grid::GPT::V1::Package;
        my $pkg = new Grid::GPT::V1::Package;

        print "Reading in metadata for $pack.\n";
        $pkg->read_metadata_file($_);

	#$packagemap{$pkg->{'Name'}}=$File::Find::dir;
      }
      }

}
sub is_spec{
if (($File::Find::name =~/\.spec$/)){
        require Grid::GPT::V1::Package;
        my $pkg = new Grid::GPT::V1::Package;

        print "Reading in metadata for $File::Find::name.\n";
        $pkg->read_metadata_file("\./pkgdata/pkg_data_src.gpt.in");

	$packagemap{$pkg->{'Name'}}=$File::Find::dir;
	push(@packagelist, $File::Find::dir."\/pkgdata\/pkg_data_src.gpt.in");
	#$dist->look_for_metadata_files(cwd());
      }

}

sub print_packagelist{
 my @packages = keys %packagemap;
for my $package (@packages){
     my $srcdir = $packagemap{$package};
     $srcdir =~ s/\.\/source-trees\///;
     print "$package	$srcdir	gpt\n";
}
}

sub read_package_list{
  open(PKG, "etc/package-list-5.1.0");
  chdir "./source-trees";
  my $topsrcdir=cwd();
    while ( <PKG> )
    {
        my $log;
        my ($pkg, $subdir, $custom, $pnb, $pkgtag) = split(' ', $_);
        next if ($pkg =~ m/^#/ || $pkg =~ m/^$/);
        print cwd()."\n";
        print $subdir."\n";
        chdir "./$subdir";
        system("cvs update -r RIC-92_branch ");
        chdir "$topsrcdir";
    }


}

sub bootstrap{
   my @sorted_package_names = @_;
   print Dumper @sorted_package_names;
   my $topsrcdir=cwd();
   chdir($packagemap{'globus_core'});
	print "cwd is". cwd()."\n";
	print "pkg is". $pkg." $ENV{'GPT_LOCATION'} is GPT LOCATION\n";
	print `system("ls -al $ENV{'GPT_LOCATION'}/share/globus/globus_aclocal/gpt_autoconf_macros.m4")`;
	system("./bootstrap");
	system("./configure; make; make install");
	chdir($topsrcdir);
   for my $pkg (@sorted_package_names){

	chdir($packagemap{$pkg});
	print "cwd is". cwd()."\n";
	system("./bootstrap");
	chdir($topsrcdir);
   }
}

sub build{
   my @sorted_package_names = @_;
   print Dumper @sorted_package_names;
   my $topsrcdir=cwd();
   chdir($packagemap{'globus_core'});
	print "cwd is". cwd()."\n";
	print "pkg is". $pkg." $ENV{'GPT_LOCATION'} is GPT LOCATION\n";
	print "$ENV{'GLOBUS_LOCATION'} is GLOBUS LOCATION\n";
	system("./configure; make; make install");
	chdir($topsrcdir);
   for my $pkg (@sorted_package_names){

	chdir($packagemap{$pkg});
	print "cwd is". cwd()."\n";
	system("./configure; make; make install");
	chdir($topsrcdir);
   }
}
