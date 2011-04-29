#!/usr/bin/env perl

use File::Find;
use Data::Dumper;
use Cwd;

 my $gpt_dir;
    my $gpt_ver;
    my $target;
 my @packagelist;
$top_dir = cwd();
#print "$top_dir is top_dir\n";

    # we maintain a patched copy of gpt - find out what we call it
    $gpt_ver = `cat $top_dir/gpt/gpt_version`;
    chomp($gpt_ver);
#print "$gpt_ver is gpt_ver\n";
    $gpt_ver = "gpt-$gpt_ver";
#print "$gpt_ver is gpt_ver\n";
    $gpt_dir = $top_dir . "/$gpt_ver";
print "$gpt_dir is gpt_dir\n";
    $ENV{'GPT_LOCATION'} = $gpt_dir;


@INC = ("$ENV{GPT_LOCATION}/lib/perl", @INC);
my $source_output = $top_dir . "/source-output";
mkdir $source_output;
$ENV{GLOBUS_LOCATION} = "$source_output/tmp_core";


my %packagemap;

#find(\&is_metadata, './source-trees');
#print Dumper %packagemap;
#print_packagelist();
require Grid::GPT::PkgDist;
my $dist = new Grid::GPT::PkgDist;
#find(\&is_spec, './source-trees');
read_package_list();
#print Dumper @packagelist;
#$dist->load_dist_from_list(@packagelist);
#to get the PkgDist object to actually read in metadata and sort it, we need to
#put the packagelist into its structure.  This API sucks, but, well, it's legacy
$dist->{'pkgs_gpt'}=\@packagelist;
$dist->load_dist_from_list($dist);
#print Dumper $dist;
    $dist->cleardepenv();
    $dist->set_depenv('Build');
	$dist->sort_pkgs();
  my @nocorepkgs = grep { $_->pkgname ne 'globus_core' }
      @{ ( $dist->sorted())};
  my @corepkgs = grep { $_->pkgname eq 'globus_core' }
      @{ ( $dist->sorted() )};
  my @sorted_package_names;
  for my $p (@corepkgs){
    push (@sorted_package_names, $p->pkgname);
  }
  for my $p (@nocorepkgs){
    push (@sorted_package_names, $p->pkgname);
  }
#  for my $p (@{ ($dist->sorted() )}){
#    push (@sorted_package_names, $p->pkgname);
#  }
#print "Sorted package names are:\n";
#print Dumper @sorted_package_names;
$dist->cleardepenv();
$dist->set_depenv('Runtime');
$dist->sort_pkgs();
  my @nocorepkgs = grep { $_->pkgname ne 'globus_core' }
      @{ ( $dist->sorted())};
my @runtime_sorted_package_names;
  for my $p (@nocorepkgs){
    push (@runtime_sorted_package_names, $p->pkgname);
  }

bootstrap(@sorted_package_names);
#build(@sorted_package_names);
create_makefile_installer(@sorted_package_names);

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
  print "in read_package_list\n";
  open(PKG, "etc/package-list-5.1.0");
  my $topsrcdir=cwd();
    while ( <PKG> )
    {
        my $log;
        my ($pkg, $subdir, $custom, $pnb, $pkgtag) = split(' ', $_);
	print "package is ".$pkg." in ".$subdir."\n";
	$packagemap{$pkg}="./source-trees/".$subdir;
	if (-e "./source-trees/$subdir/pkgdata/pkg_data_src.gpt.in"){
	push(@packagelist, "./source-trees/".$subdir."\/pkgdata\/pkg_data_src.gpt.in");
	}else{
	#gsi-openssh is a non-standard package
	  if (-e "./source-trees/$subdir/pkg_data_src.gpt"){
	    push(@packagelist, "./source-trees/".$subdir."\/pkg_data_src.gpt");
	  }
	}
    }


}

sub bootstrap{
   my @sorted_package_names = @_;
   #print Dumper @sorted_package_names;
   my $topsrcdir=cwd();
   chdir($packagemap{'globus_core'});
	print "cwd is". cwd()."\n";
	print "pkg is". $pkg." $ENV{'GPT_LOCATION'} is GPT LOCATION\n";
	#print `system("ls -al $ENV{'GPT_LOCATION'}/share/globus/globus_aclocal/#gpt_autoconf_macros.m4")`;
	system("./bootstrap");
	system("./configure --with-flavor=gcc32; make; make install");
	#have to clean up after ourselves or core will never build in installer
	system("make distclean");
	chdir($topsrcdir);
   for my $pkg (@sorted_package_names){

	chdir($packagemap{$pkg});
	print "cwd is". cwd()."\n";
	if (-e "./make_gpt_dist"){
	#This is currently only for gsi_openssh
	  #system("./make_gpt_dist");
	  system("autoconf");
	  system("./configure");
	  system("make distprep");
	  system("make distclean");
	  #system("mv ${package}*.tar.gz $package_output");
	}else{
	  system("./bootstrap");
	}
	chdir($topsrcdir);
   }
}

sub build{
   my @sorted_package_names = @_;
   #print Dumper @sorted_package_names;
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


# --------------------------------------------------------------------
sub populate_bundle_list
# --------------------------------------------------------------------
{
    my $bundle;

    chdir "$top_dir/etc/";
    open(BUN, "bundles");

    while ( <BUN> )
    {
        my ($pkg, $bun) = split(' ', $_);
        next if ( $pkg eq "" or $pkg eq "#" );
    
        chomp $flags;

        if ( $pkg eq "BUNDLE" )
        {
            $bundle = $bun;

        } else {
            if ( $bundle eq undef )
            {
                print "Ignoring $pkg, no bundle set yet.\n";
            } else {
                push @{$bundle_list{$bundle}}, $pkg;
            }
        }
    }
}

sub create_makefile_installer
{
    my ($file) = $@;
my $installer="installer_makefile.frag";
    open(INS, ">$top_dir/$installer") or die "Can't open $installer: $!\n";
#    install_globus_core();

    # First list all depordered 
    # package lists.  Then list all the packages as targets in both
    # threaded and unthreaded versions.  Bootstrap the CVS directories
    # as we go so they can be built.
         
    foreach my $pack ( @sorted_package_names )
    {
         my $packname = $pack;
         my $extras="";
 # Extract the list of dependent packages so we
 #   # can load Installation with only packages we require.
      my @pkgdirs;
	my $pkg = $dist->get_package(pkgname => $packname, setupname => 'NONE', pkgtype => 'src');

#	$pkg->{'depindexes'}->{'pkgname-list'}
 
       for my $e ( keys %{$pkg->{'depindexes'}->{'pkgname-list'}} ) {
            next if ($e =~ /setup/);
                  push @pkgdirs, $e;
                    }

	#print "PackageName is $packname\n";
	#print Dumper @pkgdirs;
 

         # This package gets run in a sudo environment that doesn't
         # have LD_LIBRARY_PATH set, so we want it to always be static.
         if ( $pack=~/globus_gridmap_and_execute/ )
         {
              $extras = "-static ";
         }
	# if there are Build_Instructions, it's a patch-n-build, and we're going to punt and
	# use gpt-build
	if ((!defined $pkg->{'depnode'})||(defined $pkg->{'depnode'}->{'Build_Instructions'})){
         print INS "${packname}-only: gpt\n";
         print INS "\t\$\{GPT_LOCATION\}/sbin/gpt-build $extras \$\{BUILD_OPTS\} -srcdir=" . $packagemap{$pack} . " \${FLAVOR}\n";
	}else{
         print INS "${packname}-only: gpt ${packname}-configure ${packname}-make ${packname}-makeinstall\n";
	 print INS "${packname}-configure:";
	 print INS "\t $packagemap{$pack}/config.status\n";
	 print INS "$packagemap{$pack}/config.status:\n";
         print INS "\tcd $packagemap{$pack} \;";
         print INS "\t\./configure $extras \$\{BUILD_OPTS\} --with-flavor=\${FLAVOR}\n";
	 print INS "${packname}-make:\n";
         print INS "\tcd $packagemap{$pack} \;";
         print INS "\t\make\n";
	 print INS "${packname}-makeinstall:\n";
         print INS "\tcd $packagemap{$pack} \;";
	 print INS "\tmake install\n\n";
	}

         print INS "$packname: gpt ${packname}-runtime ${packname}-compile\n";
         print INS "${packname}-runtime: ";
         foreach my $deppack ( @sorted_package_names )
         {
              #if ( $package_runtime_hash{$pack}{$deppack} )
              if ( $pkg->{'depindexes'}->{'pkgname-list'}{$deppack} )
              {
                   print INS " $deppack" unless ( $pack eq $deppack );
              }
         }
         print INS "\n";

         print INS "${packname}-compile: ";
         foreach my $deppack ( @runtime_sorted_package_names )
         {
              #if ( $package_dep_hash{$pack}{$deppack} )
              if ( $pkg->{'depindexes'}->{'pkgname-list'}{$deppack} )
              {
                   print INS " ${deppack}-compile" unless ( $pack eq $deppack );
              }
         }

         #print INS "\n";

         #print INS "\t$packname"."-only\n";
         print INS "\t$packname"."-only\n";

    }

    close(INS) if $installer;
}
