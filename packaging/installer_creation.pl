#! /usr/bin/perl

use File::Find;
use File::Spec;
use File::Basename;
use Data::Dumper;
use Cwd;
use Getopt::Long;

my $top_dir = dirname(File::Spec->rel2abs($0));
my $checkout_top_dir = dirname($top_dir);
my $flavor = "gcc32";
my $package_list_file = "$top_dir/etc/packages";
my $external_package_list_file = "$top_dir/etc/packages-external";
my $gpt_dir;
my $gpt_ver;
my $target;
my $avoid_bootstrap=0;
my @packagelist;
my @nongpt_packagelist;

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

read_package_list($package_list_file, $external_package_list_file);
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
copy_source_trees(@sorted_package_names, @nongpt_packagelist);
create_makefile_installer(\@sorted_package_names, \@nongpt_packagelist);

sub read_package_list {
    my ($plist, $xplist) = @_;
    print "in $plist\n";
    open(PKG, "<", $plist);

    while ( <PKG> ) {
        chomp;
        s/#.*//;
        next if $_ eq '';

        my ($pkg, $subdir) = split(/\s+/, $_);
	print "package is ".$pkg." in ".$subdir."\n";
	$packagemap{$pkg}=$subdir;
	if (-e "$checkout_top_dir/$subdir/pkgdata/pkg_data_src.gpt.in") {
            push(@packagelist,
                "$checkout_top_dir/$subdir/pkgdata/pkg_data_src.gpt.in");
	} else {
            # gsi-openssh is a non-standard package
            if (-e "$checkout_top_dir/$subdir/pkg_data_src.gpt") {
                push(@packagelist, "$checkout_top_dir/".$subdir."\/pkg_data_src.gpt");
            }
	}
    }

    open(PKG, "<$xplist");

    while ( <PKG> ) {
        chomp;
        s/#.*//;
        while (/\\$/) {
            chop;
            chomp(my $continuation = <PKG>);
            $continuation =~ s/#.*//;
            $_ .= " $continuation";
        }
        next if $_ eq '';

        # Column 1 is the package name
        # Column 2 is the path where the source of the package is unpacked
        # Column 3 is the package tarball name
        # Column 4 is the command to fetch the external package and untar it
        # into column 2

        
        my ($pkg, $subdir, $tarball, $fetch) = split(/\s+/, $_, 4);
	print "package is $pkg in $subdir\n";
        print "Fetching with cd $checkout_top_dir; $fetch\n";
        system("cd $checkout_top_dir; $fetch");
	$packagemap{$pkg}=$subdir;
	if (-e "$checkout_top_dir/$subdir/pkgdata/pkg_data_src.gpt.in") {
            push(@packagelist,
                "$checkout_top_dir/$subdir/pkgdata/pkg_data_src.gpt.in");
	} else {
            # gsi-openssh is a non-standard package
            if (-e "$checkout_top_dir/$subdir/pkg_data_src.gpt") {
                push(@packagelist, "$checkout_top_dir/$subdir/pkg_data_src.gpt");
	    } else {
                push(@nongpt_packagelist, $pkg);
	    }
	}
    }
}

sub bootstrap {
    my @sorted_package_names = @_;
    my $topsrcdir=cwd();
    chdir("$checkout_top_dir/$packagemap{'globus_core'}");
    print "cwd is ". cwd()."\n";
    print "pkg is globus_core--- $ENV{'GPT_LOCATION'} is GPT LOCATION\n";
    system("./bootstrap");
    system("./configure --with-flavor=$flavor; make; make install");
    # have to clean up after ourselves or core will never build in installer
    system("make distclean");
    chdir($topsrcdir);
    for my $pkg (@sorted_package_names) {
        chdir("$checkout_top_dir/$packagemap{$pkg}");
	print "[$pkg] " .cwd()."\n";
	if (-e "./make_gpt_dist") {
	    # This is currently only for gsi_openssh
            system("autoconf");
            system("./configure");
            system("make distprep");
            system("make distclean");
	} else {
	    system("./bootstrap");
	    system("make distclean") if (-f 'config.status');
	}
	chdir($topsrcdir);
   }
}

sub copy_source_trees {
    my @sorted_package_names = @_;
    my $topsrcdir=cwd();
    chdir($packagemap{'globus_core'});
    print "cwd is ". cwd()."\n";
    print "pkg is globus_core--- $ENV{'GPT_LOCATION'} is GPT LOCATION\n";
    chdir($topsrcdir);
    for my $pkg (@sorted_package_names) {
        system("mkdir -p $top_dir/source-trees/$packagemap{$pkg}");
        system("cp -RpL $checkout_top_dir/$packagemap{$pkg}/. $top_dir/source-trees/$packagemap{$pkg}");
   }
}


sub create_makefile_installer {
    my ($file) = $@;
    my @package_names = @{$_[0]};
    my @nongpt_packages = @{$_[1]};
    my $installer="installer_makefile.frag";
    open(INS, ">$top_dir/$installer") or die "Can't open $installer: $!\n";

    # First list all depordered 
    # package lists.  Then list all the packages as targets in both
    # threaded and unthreaded versions.  Bootstrap the CVS directories
    # as we go so they can be built.
         
    my @subdirs="";
    my @dist_rules;
    foreach my $pack ( @package_names ) {
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

	if ((!defined $pkg->{'depnode'})||(defined $pkg->{'depnode'}->{'Build_Instructions'})||($pack=~/globus_core/)) {
            # if there are Build_Instructions, it's a patch-n-build, and we're
            # going to punt and use gpt-build
	    # If the package is globus_core, we have to use gpt-build for the
	    # moment, since core isn't figuring out the right flavor_label stuff
	    # by itself (yet)
            print INS <<EOF;
${packname}-only: gpt
	\$(LIBPATH_VARIABLE)=\${libdir}:\${\$(LIBPATH_VARIABLE)} \$\{GPT_LOCATION\}/sbin/gpt-build $extras \$(CONFIGOPTS_GPTMACRO) -srcdir=./source-trees/$packagemap{$pack} \${FLAVOR}
${packname}-dist: ${packname} source-packages
	cd ./source-trees/$packagemap{$pack}; make dist;
	. ./source-trees/$packagemap{$pack}/gptdata.sh; \\
        cp ./source-trees/$packagemap{$pack}/\$\$GPT_NAME-\$\${GPT_MAJOR_VERSION}.\$\${GPT_MINOR_VERSION}.tar.gz source-packages/
EOF
	} else {
            # "normal" gpt package
            print INS <<EOF;
${packname}-only: gpt ${packname}-configure ${packname}-make ${packname}-makeinstall
${packname}-configure: ./source-trees/$packagemap{$pack}/config.status
./source-trees/$packagemap{$pack}/config.status:
	cd ./source-trees/$packagemap{$pack}; \\
	./configure $extras \$\{BUILD_OPTS\} --with-flavor=\${FLAVOR}
${packname}-make:
	cd ./source-trees/$packagemap{$pack} ; make
${packname}-makeinstall:
	cd ./source-trees/$packagemap{$pack} ; make install
${packname}-dist: ${packname}-configure source-packages
	cd ./source-trees/$packagemap{$pack}; make dist;
	. ./source-trees/$packagemap{$pack}/gptdata.sh; \\
        cp ./source-trees/$packagemap{$pack}/\$\$GPT_NAME-\$\${GPT_MAJOR_VERSION}.\$\${GPT_MINOR_VERSION}.tar.gz source-packages/
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

	push(@subdirs,"source-trees/$packagemap{$pack}");
    }
    foreach my $pack ( @nongpt_packages ) {
        if ($pack eq 'udt') {
            print INS <<EOF;
${pack}-only: gpt
	case "\$(host_os)" in linux*) export os=LINUX;; *) export os=\`echo \$(host_os) | tr -d .[0-9]\` ;; esac; \\
	case "\$(host_cpu)" in x86_64*) export arch=AMD64;; *) export C++="g++ -m32";; esac; \\
	make -C ./source-trees/$packagemap{$pack}; \\
	mkdir -p \${libdir} \${includedir}; \\
        cp ./source-trees/$packagemap{$pack}/src/libudt.so* \${libdir}; \\
        cp ./source-trees/$packagemap{$pack}/src/udt.h \${includedir};
EOF
            push(@subdirs, "source-trees/$packagemap{$pack}");
        } else {
            die "Unhandled package $pack\n";
        }
    }
    print INS "SUBDIRS=", join(" \\\n\t\t./", @subdirs), "\n";
    print INS "dist: ", join(" \\\n\t\t", @dist_rules), "\n";
    close(INS) if $installer;
}
