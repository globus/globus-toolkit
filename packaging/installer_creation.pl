#! /usr/bin/perl

use File::Find;
use Data::Dumper;
use Cwd;
use Getopt::Long;

my $top_dir = $0;
print "$top_dir\n";
if ($top_dir =~ m|^/|) {
    $top_dir =~ s|/+[^/]*$||;
} else {
    $top_dir = cwd() . "/$top_dir";
    $top_dir =~ s|/+[^/]*$||;
}
my $flavor = "gcc32";
my $package_list_file = "etc/package-list-5.1.0";
my $gpt_dir;
my $gpt_ver;
my $target;
my $avoid_bootstrap=0;
my @packagelist;

GetOptions(
    "flavor|f=s" => \$flavor,
    "package-list|p=s" => \$package_list_file,
    "avoid-bootstrap|a" => \$avoid_bootstrap);

# we maintain a patched copy of gpt - find out what we call it
$gpt_ver = `cat $top_dir/gpt/gpt_version`;
chomp($gpt_ver);
$gpt_ver = "gpt-$gpt_ver";
$gpt_dir = $top_dir . "/$gpt_ver";
print "$gpt_dir is gpt_dir\n";
$ENV{'GPT_LOCATION'} = $gpt_dir;

@INC = ("$ENV{GPT_LOCATION}/lib/perl", @INC);
my $source_output = $top_dir . "/source-output";
mkdir $source_output;
$ENV{GLOBUS_LOCATION} = "$source_output/tmp_core";

my %packagemap;

require Grid::GPT::PkgDist;
my $dist = new Grid::GPT::PkgDist;

read_package_list();
# to get the PkgDist object to actually read in metadata and sort it, we need
# to put the packagelist into its structure.  This API sucks, but, well, it's
# legacy
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
for my $p (@corepkgs) {
    push (@sorted_package_names, $p->pkgname);
}
for my $p (@nocorepkgs) {
    push (@sorted_package_names, $p->pkgname);
}
$dist->cleardepenv();
$dist->set_depenv('Runtime');
$dist->sort_pkgs();
my @nocorepkgs = grep { $_->pkgname ne 'globus_core' }
      @{ ( $dist->sorted())};
my @runtime_sorted_package_names;
for my $p (@nocorepkgs) {
    push (@runtime_sorted_package_names, $p->pkgname);
}

bootstrap(@sorted_package_names) if (!$avoid_bootstrap);
create_makefile_installer(@sorted_package_names);

sub read_package_list {
    print "in read_package_list\n";
    open(PKG, "<", $package_list_file);
    my $topsrcdir=cwd();

    while ( <PKG> ) {
        my $log;
        my ($pkg, $subdir, $custom, $pnb, $pkgtag) = split(' ', $_);
        next if ($pkg =~ m/^#/ || $pkg =~ m/^$/);
	print "package is ".$pkg." in ".$subdir."\n";
	$packagemap{$pkg}="./source-trees/".$subdir;
	if (-e "./source-trees/$subdir/pkgdata/pkg_data_src.gpt.in") {
            push(@packagelist,
                "./source-trees/".$subdir."\/pkgdata\/pkg_data_src.gpt.in");
	} else {
            # gsi-openssh is a non-standard package
            if (-e "./source-trees/$subdir/pkg_data_src.gpt") {
                push(@packagelist, "./source-trees/".$subdir."\/pkg_data_src.gpt");
	    }
	}
    }

}

sub bootstrap {
    my @sorted_package_names = @_;
    my $topsrcdir=cwd();
    chdir($packagemap{'globus_core'});
    print "cwd is". cwd()."\n";
    print "pkg is globus_core--- $ENV{'GPT_LOCATION'} is GPT LOCATION\n";
    system("./bootstrap");
    system("./configure --with-flavor=$flavor; make; make install");
    # have to clean up after ourselves or core will never build in installer
    system("make distclean");
    chdir($topsrcdir);
    for my $pkg (@sorted_package_names) {
        chdir($packagemap{$pkg});
	print "cwd is". cwd()."\n";
	if (-e "./make_gpt_dist") {
	    # This is currently only for gsi_openssh
            system("autoconf");
            system("./configure");
            system("make distprep");
            system("make distclean");
	} else {
	    system("./bootstrap");
	}
	chdir($topsrcdir);
   }
}


sub create_makefile_installer {
    my ($file) = $@;
    my $installer="installer_makefile.frag";
    open(INS, ">$top_dir/$installer") or die "Can't open $installer: $!\n";

    # First list all depordered 
    # package lists.  Then list all the packages as targets in both
    # threaded and unthreaded versions.  Bootstrap the CVS directories
    # as we go so they can be built.
         
    my @subdirs="";
    my @dist_rules;
    foreach my $pack ( @sorted_package_names ) {
        my $packname = $pack;
        my $extras="";
        # Extract the list of dependent packages so we
        # can load Installation with only packages we require.
        my @pkgdirs;
	my $pkg = $dist->get_package(pkgname => $packname, setupname => 'NONE', pkgtype => 'src');

 
        for my $e ( keys %{$pkg->{'depindexes'}->{'pkgname-list'}} ) {
            next if ($e =~ /setup/);
            push @pkgdirs, $e;
        }

        # This package gets run in a sudo environment that doesn't
        # have LD_LIBRARY_PATH set, so we want it to always be static.
        if ( $pack=~/globus_gridmap_and_execute/ ) {
            $extras = "-static ";
        }
	if ((!defined $pkg->{'depnode'})||(defined $pkg->{'depnode'}->{'Build_Instructions'})||($pack=~/globus_core/)) {
            # if there are Build_Instructions, it's a patch-n-build, and we're
            # going to punt and use gpt-build
	    # If the package is globus_core, we have to use gpt-build for the
	    # moment, since core isn't figuring out the right flavor_label stuff
	    # by itself (yet)
            print INS <<EOF;
${packname}-only: gpt
	\$(LIBPATH_VARIABLE)=\${libdir} \$\{GPT_LOCATION\}/sbin/gpt-build $extras \$\{BUILD_OPTS\} -srcdir=$packagemap{$pack} \${FLAVOR}
${packname}-dist: ${packname} source-packages
	cd $packagemap{$pack}; make dist;
	. $packagemap{$pack}/gptdata.sh; \\
        cp $packagemap{$pack}/\$\$GPT_NAME-\$\${GPT_MAJOR_VERSION}.\$\${GPT_MINOR_VERSION}.tar.gz source-packages/
EOF
	} else {
            # "normal" gpt package
            print INS <<EOF;
${packname}-only: gpt ${packname}-configure ${packname}-make ${packname}-makeinstall
${packname}-configure: $packagemap{$pack}/config.status
$packagemap{$pack}/config.status:
	cd $packagemap{$pack}; \\
	./configure $extras \$\{BUILD_OPTS\} --with-flavor=\${FLAVOR}
${packname}-make:
	cd $packagemap{$pack} ; make
${packname}-makeinstall:
	cd $packagemap{$pack} ; make install
${packname}-dist: ${packname}-configure source-packages
	cd $packagemap{$pack}; make dist;
	. $packagemap{$pack}/gptdata.sh; \\
        cp $packagemap{$pack}/\$\$GPT_NAME-\$\${GPT_MAJOR_VERSION}.\$\${GPT_MINOR_VERSION}.tar.gz source-packages/
EOF
	}
        push(@dist_rules, "${packname}-dist");
        print INS "$packname: gpt ${packname}-runtime ${packname}-compile\n";
        print INS "${packname}-runtime: ";
        foreach my $deppack ( @sorted_package_names ) {
            if ( $pkg->{'depindexes'}->{'pkgname-list'}{$deppack} ) {
                print INS " $deppack" unless ( $pack eq $deppack );
            }
        }
        print INS "\n";

        print INS "${packname}-compile: ";
        foreach my $deppack ( @runtime_sorted_package_names ) {
            if ( $pkg->{'depindexes'}->{'pkgname-list'}{$deppack} ) {
                print INS " ${deppack}-compile" unless ( $pack eq $deppack );
            }
        }

        print INS "\t$packname"."-only\n";

	push(@subdirs,$packagemap{$pack});
    }
    print INS "SUBDIRS=", join(" \\\n\t\t", @subdirs), "\n";
    print INS "dist: ", join(" \\\n\t\t", @dist_rules), "\n";
    close(INS) if $installer;
}
