#!/usr/bin/env perl

# GT3.x build tool

# Basic strategy:
#  Iterate over etc/{cvstree}/package-list and /bundles
#  to get a list of packages and bundles defined by that tree.
#  Then, package up all the sources corresponding to the packages.
#  After that, make source bundles out of the packages.
#  Finally, install the resulting bundles.

use strict;
use Getopt::Long;
use Config;
use Cwd;
use Pod::Usage;

# Where do things go?
my $top_dir = cwd();
my $cvs_prefix = $top_dir . "/source-trees/";
my $log_dir = $top_dir . "/log-output";
my $pkglog = $log_dir . "/package-logs";
my $bundlelog = $log_dir . "/bundle-logs";
my $source_output = $top_dir . "/source-output";
my $package_output = $top_dir . "/package-output";
my $bundle_output = $top_dir . "/bundle-output";

# What do I need to clean up from old buids?
my @cleanup_dirs = ('log-output', '$bundle_ouput/BUILD');

# tree_name => [ cvs directory, module, checkout-dir tag ]
# TODO: Make prereq builds separate?
my %prereq_archives = (
     'autotools' => [ "/home/globdev/CVS/globus-packages", "side_tools", "autotools", "HEAD" ],
		       );

# tree_name => [ cvs directory, module, checkout-dir tag ]
# TODO: Add explicit CVSROOT
my %cvs_archives = (
     'gt2' => [ "/home/globdev/CVS/globus-packages", "all", "gt2-cvs", "HEAD" ],
     'gt3' => [ "/home/globdev/CVS/gridservices", "all", "ogsa-cvs", "HEAD" ],
     'cbindings' => [ "/home/globdev/CVS/gridservices", "ogsa-c", "cbindings", "HEAD" ],
     'autotools' => [ "/home/globdev/CVS/globus-packages", "side_tools", "autotools", "HEAD" ]
      );

# package_name => [ tree, subdir, custom_build, (patch-n-build file, if exists) ]
my %package_list;

# bundle_name => [ flavor, @package_array ]
my %bundle_list;

# Which of the bundles defined should I build?
my @bundle_build_list;

# Which of the CVS trees should I operate on?
my @cvs_build_list;
my %cvs_build_hash;

# What flavor shall things be built as?
my $flavor = "gcc32dbg";
my $thread = "pthr";

my ($install, $buildjava, $buildc, $anonymous, $noupdates, $force,
    $help, $man, $verbose, $skippackage, $skipbundle, $faster,
    $paranoia, $version, $uncool) =
   (0, 1, 1, 0, 0, 0,
    0, 0, 0, 0, 0, 0,
    0, "1.0", 0);

my @user_bundles;
my @user_packages;

GetOptions( 'i|install=s' => \$install,
	    'j|build-java!' => \$buildjava,
	    'c|build-c!' => \$buildc,
	    'a|anonymous!' => \$anonymous,
	    'n|no-updates!' => \$noupdates,
	    'f|force!' => \$force,
	    'faster!' => \$faster,
	    'flavor=s' => \$flavor,
	    't2|gt2-tag=s' => \$cvs_archives{gt2}[3],
	    't3|gt3-tag=s' => \$cvs_archives{gt3}[3],
	    'v|verbose!' => \$verbose,
	    'skippackage!' => \$skippackage,
	    'skipbundle!' => \$skipbundle,
	    'bundles=s' => \@user_bundles,
	    'p|packages=s' => \@user_packages,
	    'trees=s' => \@cvs_build_list,
	    'paranoia!' => \$paranoia,
	    'version=s' => \$version,
	    'uncool!' => \$uncool,
	    'help|?' => \$help,
	    'man' => \$man,
) or pod2usage(2);

if ( $help or $man ) {
    pod2usage(2) if $help;
    pod2usage(1) if $man;
}

# Allow comma separated packages or multiple instances.
@user_packages = split(/,/,join(',',@user_packages));
@user_bundles = split(/,/,join(',',@user_bundles));
@cvs_build_list = split(/,/,join(',',@cvs_build_list));



# main ()

cleanup();
setup_environment();

if ( not $noupdates )
{
    # Need autotools for gt2 or gt3
    if ($cvs_build_hash{'gt2'} eq 1 or $cvs_build_hash{'gt3'} eq 1)
    {
	$cvs_build_hash{'autotools'} = 1;
	push @cvs_build_list, 'autotools';
    }
    get_sources();
} else {
    print "Not checking out sources with -no-updates set.\n";
    print "INFO: This means CVS Tags are not being checked either.\n";
}

build_prerequisites();

if ( not $skippackage )
{
    package_sources();
} else {
    print "Not packaging sources with -skippackage set.\n";
}

if ( not $skipbundle )
{
    bundle_sources();
} else {
    print "Not bundling sources with -skipbundle set.\n";
}

if ( $install )
{
    install_bundles();
} else {
    print "Not installing bundle without -install= set.\n";
}

exit 0;


# --------------------------------------------------------------------
sub setup_environment()
# --------------------------------------------------------------------
{
    if ( not defined(@cvs_build_list) )
    {
	@cvs_build_list = ("autotools", "gt2", "gt3", "cbindings");
    }

    foreach my $tree (@cvs_build_list)
    {
	$cvs_build_hash{$tree} = 1;
    }

    print "Setting up environment and checking dependencies...\n";

    #TODO: figure out package list first, then set
    # cvs_build_hash appropriately.q
    if ( $cvs_build_hash{'gt3'} eq 1  )
    {
	check_java_env();
    }
    
    if ( $install )
    {
	$ENV{GLOBUS_LOCATION} = $install;
    } else {
	$ENV{GLOBUS_LOCATION} = "$source_output/tmp_core";
    }

    if ( $verbose )
    {
	$verbose = "-verbose";
    } else {
	$verbose = "";
    }

    mkdir $log_dir;
    report_environment();

    # Figure out what bundles and packages exist.
    for my $tree (@cvs_build_list)
    {
	populate_bundle_list($tree);
	populate_package_list($tree);
    }

    # Out of what exists, what shall we build?
    populate_bundle_build_list();
}

# --------------------------------------------------------------------
sub check_java_env()
# --------------------------------------------------------------------
{
    if ( $ENV{'JAVA_HOME'} eq "" ) 
    {
	if ( -e "/usr/java/j2sdk1.4.1_02/" ) 
	{
	    $ENV{'JAVA_HOME'} = "/usr/java/j2sdk1.4.1_02/";
	} elsif ( -e "/home/dsl/javapkgs/java-env-setup.sh" )
	{
	    system("source /home/dsl/javapkgs/java-env-setup.sh");
	} elsif ( -e "/usr/java/jdk1.3.1_07" )
	{
	    $ENV{'JAVA_HOME'} = "/usr/java/jdk1.3.1_07";
	} else {
	    print "Could not find JAVA_HOME for your system.\n";
	    print "Please set JAVA_HOME before running this script\n";
	    exit 1;
	}
    }
    system("ant -h > /dev/null");
    if ( $? != 0 )
    {
	print "ant -h returned an error.  Make sure ant is on your path.\n";
	exit 1;
    }
}

# --------------------------------------------------------------------
sub report_environment()
# --------------------------------------------------------------------
{
    if ( -e "$top_dir/CVS/Tag" )
    {
	open(TAG, "$top_dir/CVS/Tag");
	my $mptag = <TAG>;
	chomp $mptag;
	print "You are using $0 from: " . substr($mptag,1) . "\n";
    }

    print "Using JAVA_HOME = ", $ENV{'JAVA_HOME'}, "\n";
    system("type ant");

    if ( $install )
    {
	print "Installing to $install\n";
    }

    print "\n";
}
    
	    
# --------------------------------------------------------------------
sub cleanup()
# --------------------------------------------------------------------
{
    # Need to make this depend on which steps you're going to do
    # So that if you want to leave things in package-output, you can.

    if ( not $skippackage and not $faster )
    {
	push @cleanup_dirs, "package-output";
    }

    for my $f ( @cleanup_dirs )
    {
	if ( -d "$f" )
	{
	    print "Cleaning up old build by moving $f to ${f}.old\n";
	    if ( -d "${f}.old" )
	    {
		system("rm -fr ${f}.old");
	    }
	    system("mv ${f} ${f}.old");
	}
    }

    print "\n";
}


# --------------------------------------------------------------------
sub populate_package_list
# --------------------------------------------------------------------
{
    my ($tree) = @_;
    my $build_default;

    if (-d "$top_dir/etc/$tree")
    {
	chdir "$top_dir/etc/$tree";
    } else {
	print "INFO: No packages defined for tree $tree.\n";
	return;
    }

    open(DEFAULT, "build-default");
    $build_default = <DEFAULT>;
    chomp $build_default;

    open(PKG, "package-list");

    while ( <PKG> )
    {
	my ($pkg, $subdir, $custom, $pnb) = split(' ', $_);
	chomp $pnb;

	next if substr($pkg, 0, 1) eq "#";

	if ( $custom eq "" )
	{
	    $custom = $build_default;
	}

	$package_list{$pkg} = [ $tree, $subdir, $custom, $pnb ];

    }
}

# TODO: Use the GT2 bundle.def files for this instead.
# TODO: Add the NMI GT3 bundle.xml files for this also.
# --------------------------------------------------------------------
sub populate_bundle_list
# --------------------------------------------------------------------
{
    my ($tree) = @_;
    my $bundle;

    chdir "$top_dir/etc/$tree";
    open(BUN, "bundles");

    while ( <BUN> )
    {
	my ($pkg, $bun, $isthreaded) = split(' ', $_);
	
	next if ( $pkg eq "" or $pkg eq "#" );
	chomp $isthreaded;
    
	if ( $pkg eq "BUNDLE" )
	{
	    $bundle = $bun;
	    if ( $isthreaded eq "THREADED" )
	    {
		push @{$bundle_list{$bundle}}, $flavor . $thread;
	    } else {
		push @{$bundle_list{$bundle}}, $flavor;
	    }
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

# The goal is to let the user specify both bundles and packages.
# User defined packages will be collected into a bundle called
# "user_def".  If only packages are specified, then only those
# should be built.  If both packages and bundles are specified,
# then both sets of things should be built.  If only bundles are
# specified, only they should be built.
# If nothing is specified, build everything.
# --------------------------------------------------------------------
sub populate_bundle_build_list()
# --------------------------------------------------------------------
{
    if ( defined(@user_packages) ) 
    {
	my $bundle = "user_def";

	#TODO: How do I know what flavor for the user_def bundle?
	push @{$bundle_list{$bundle}}, $flavor;
	push @{$bundle_list{$bundle}}, @user_packages;
	push @bundle_build_list, $bundle;
    } 

    if ( defined(@user_bundles) or defined(@user_packages))
    {
	foreach my $user_bundle (@user_bundles)
	{
	    if (exists $bundle_list{$user_bundle} )
	    {
		print "Adding user requested bundle of $user_bundle\n";
		push @bundle_build_list, $user_bundle;
		print "\n";
	    }
	}
    } else {
	# build all bundles.
	for my $f ( keys %bundle_list )
	{
	    push @bundle_build_list, $f;
	}
    }
}


# --------------------------------------------------------------------
sub build_prerequisites()
# --------------------------------------------------------------------
{
    install_gpt2();

    if ( $cvs_build_hash{'autotools'} eq 1 or $cvs_build_hash{'gt2'} eq 1 )
    {
	install_gt2_autotools();
    }

    if ( $cvs_build_hash{'gt2'} eq 1 or $cvs_build_hash{'gt3'} eq 1 )
    {
	install_globus_core();
    }
}

# --------------------------------------------------------------------
sub paranoia
# --------------------------------------------------------------------
{
    my ($errno, $errmsg) = ($?, $!);
    my ($death_knell) = @_;

    if ($? ne 0 and $paranoia)
    {
	die "ERROR: $death_knell";
    }
}

#TODO: Make all system() calls logging() calls instead.
# --------------------------------------------------------------------
sub log_system
# --------------------------------------------------------------------
{
    my ($command, $log) = @_;

    my $output;
    my $res;

    if ( $verbose )
    {
	# This contruction is like piping through tee
	# except that I can get the return code too.
	open LOG, $log;
	open FOO, "$command 2>&1 |";

	while (<FOO>)
	{
	    print;
	    print LOG;
	}

	close FOO;
	$res = $?;
    }
    else
    {
	$output =  ">> $log 2>&1";
	system("$command $output");
	$res = $?
    }

    return $res;
}

# --------------------------------------------------------------------
sub install_gpt2()
# --------------------------------------------------------------------
{
    my $gpt_ver = "gpt-2.2.9";
    my $gpt_dir = $top_dir . "/$gpt_ver";

    $ENV{'GPT_LOCATION'}=$gpt_dir;
    
    if ( -e "${gpt_dir}/sbin/gpt-build" )
    {
	print "GPT is already built, skipping.\n";
	print "\tDelete $gpt_dir to force rebuild.\n";
    } else {
	print "Installing $gpt_ver\n";
	print "Logging to ${log_dir}/$gpt_ver.log\n";
	chdir $top_dir;
	system("tar xzf fait_accompli/${gpt_ver}-src.tar.gz");
	paranoia("Trouble untarring fait_accompli/${gpt_ver}-src.tar.gz");

	chdir $gpt_dir;
	system("./build_gpt > $log_dir/$gpt_ver.log 2>&1");
	paranoia("Trouble with ./build_gpt.  See $log_dir/$gpt_ver.log");
    }

    @INC = (@INC, "$gpt_dir/lib/perl", "$gpt_dir/lib/perl/$Config{'archname'}");
    print "\n";
}

#
# --------------------------------------------------------------------
sub gpt_get_version
# --------------------------------------------------------------------
{
    my ($metadatafile) = @_;

    require Grid::GPT::V1::Package;
    my $pkg = new Grid::GPT::V1::Package;
	
    $pkg->read_metadata_file("$metadatafile");
    my $version = $pkg->{'Version'}->label();
    return $version;
}

#TODO: Let them specify a path to autotools
# --------------------------------------------------------------------
sub install_gt2_autotools()
# --------------------------------------------------------------------
{
    my $res;
    chdir cvs_subdir('autotools');

    if ( -e 'autotools/bin/automake' )
    {
	print "Using existing GT2 autotools installation.\n";
    } else {
	print "Building GT2 autotools.\n";
	print "Logging to ${log_dir}/gt2-autotools.log\n";

	if ( -e "side_tools/build-autotools" )
	{	    
	    $res = log_system("./side_tools/build-autotools",
		    "${log_dir}/gt2-autotools.log");
	} else {
	    die "ERROR: side_tools/build-autotools doesn't exist.  Check cvs logs.";
	}

	if ( $? ne 0 )
	{
	    print "\tAutotools dies the first time through sometimes due to\n";
	    print "\temacs .texi issues.  I am trying again.\n";

	    log_system("./side_tools/build-autotools", 
		       "${log_dir}/gt2-autotools.log");
	    if ( $? ne 0 )
	    {
		die "ERROR: Error building autotools.  Check log.\n";
	    } else {
		print "\tWorked second time through.\n";
	    }
	}
    }

    $ENV{'PATH'} = cwd() . "/autotools/bin:$ENV{'PATH'}";

    print "\n";
}

# Some packages require globus core to be installed to build.
# TODO:  This should always go local, because packages install links
#  to the automake headers.  These links don't get cleaned by
#  make distclean.  So we need to have a stable install of globus_core
#  so that users can delete old install directories.
# --------------------------------------------------------------------
sub install_globus_core()
# --------------------------------------------------------------------
{
    system("$ENV{GPT_LOCATION}/sbin/gpt-build -nosrc $flavor");

    if ( $? ne 0 )
    {
	die "ERROR: Error building gpt_core from $ENV{GPT_LOCATION}/sbin/gpt-build -nosrc $flavor.\n";
    }
}


# Double-check that the existing checkout has the right tag for the user.
# Assumes you are somewhere where a CVS/Tag exists.
# --------------------------------------------------------------------
sub cvs_check_tag
# --------------------------------------------------------------------
{
    my ( $tree ) = @_;

    # TODO: Need to find a way to do this even if -noupdates is set.
    # TODO: Let --force enforce a new checkout with the right tag.
    if ( -e "CVS/Tag" )
    {
	open(TAG, "CVS/Tag");
	my $cvstag = <TAG>;
	chomp $cvstag;
	$cvstag = substr($cvstag, 1);
	if ( $cvstag ne cvs_tag($tree) )
	{
	    die "ERROR: Want to build tag " . cvs_tag($tree) . ", CVS checkout is from $cvstag.\n";
	}
    }
}

# --------------------------------------------------------------------
sub cvs_subdir
# --------------------------------------------------------------------
{
    my ( $tree ) = @_;

    return $cvs_prefix . $cvs_archives{$tree}[2];
}

# --------------------------------------------------------------------
sub cvs_tag
# --------------------------------------------------------------------
{
    my ( $tree ) = @_;

    return $cvs_archives{$tree}[3];
}

# --------------------------------------------------------------------
sub package_subdir
# --------------------------------------------------------------------
{
    my ( $package ) = @_;

    return cvs_subdir($package_list{$package}[0]) . $package_list{$package}[1];
}


# --------------------------------------------------------------------
sub get_sources()
# --------------------------------------------------------------------
{
    if (not -e $cvs_prefix)
    {
	mkdir $cvs_prefix;
    }

    foreach my $tree ( @cvs_build_list )
    {
	print "Checking out cvs tree $tree.\n";
	cvs_checkout_generic( $tree );
    }
}

# --------------------------------------------------------------------
sub cvs_checkout_generic ()
# --------------------------------------------------------------------
{
    my ( $tree ) = @_;
    my ($cvsroot, $module, $dir, $tag) = @{$cvs_archives{$tree}};
    my $cvs_logs = $log_dir . "/cvs-logs";
    my $cvsopts = "-r $tag";

    mkdir $cvs_logs if not -d $cvs_logs;

    chdir $cvs_prefix;

    if ( $anonymous )
    {
	$cvsroot = ":pserver:anonymous\@cvs.globus.org:" . $cvsroot;
    } 
    else {
	if ( not -d $cvsroot )
	{
	    $cvsroot = "cvs.globus.org:$cvsroot";
	    $ENV{CVS_RSH} = "ssh";
	}
	# else cvsroot is fine as-is.
    }

    if ( not -e $dir )
    {
	print "Making fresh CVS checkout of \n";
	print "$cvsroot, module $module, tag $tag\n";
	print "Logging to $cvs_logs/" . $dir . ".log\n";
	mkdir $dir;
	chdir $dir;

	#CVS doesn't think of HEAD as a branch tag, so
	#don't use -r if you're checking out HEAD.
	if ( $tag eq "HEAD" )
	{
	    $cvsopts = "";
	}

	log_system("cvs -d $cvsroot co $cvsopts $module",
		   "$cvs_logs/" . $dir . ".log");

	if ( $? ne 0 )
	{
	    chdir "..";
	    rmdir $dir;
	    die "ERROR: There was an error checking out $cvsroot with module $module, tag $tag.\n";
	}
    }
    else {
	if ( $noupdates )
	{
	    print "Skipping CVS update of $cvsroot\n";
	    print "INFO: This means that I'm not checking the CVS tag for you, either.\n";
	}
	else {
	    print "Updating CVS checkout of $cvsroot\n";
	    chdir $dir;

	    for my $f ( <*> ) 
	    {
		chdir $f;

		cvs_check_tag($tree);
		if ( -d "CVS" )
		{
		    print "Logging to ${cvs_logs}/" . $dir . "-${f}.log\n";
		    log_system("cvs -z3 -qq up -dP",
			       "${cvs_logs}/" . $dir . "-${f}.log");
		    paranoia "Trouble with cvs up on tree $tree.";
		}
		chdir "..";
	    }
	}
    }

    print "\n";
}

# --------------------------------------------------------------------
sub package_sources()
# --------------------------------------------------------------------
{
    my @package_build_list;
    my $build_default;

    mkdir $pkglog;
    mkdir $source_output;
    mkdir $package_output;

    # make the decision of whether to build all source packages or no.
    # bundle_build_list = array of bundle names.
    # $bundle_list{'bundle name'} = flavor, array of packages.
    # So, for each bundle to build, run through the array of packages
    # and add it to the list of packages to be built.
    if ( defined(@bundle_build_list) ) 
    {
	for my $iter (@bundle_build_list)
	{
	    my @array = $bundle_list{$iter};

	    foreach my $pkg_array (@array)
	    {
		foreach my $pkg (@{$pkg_array}) {
		    # TODO: There must be a better way to skip flavors.
		    next if $pkg eq $flavor or $pkg eq $flavor . $thread;
		    push @package_build_list, $pkg;
		}
	    }
	}
    } else {
	@package_build_list = keys %package_list;
    }

    # Eliminate duplicates in the package_build_list
    # A "Perl Idiom".
    my %unique_packages = map { $_ => 1 } @package_build_list;
    
    for my $package ( keys %unique_packages )
    {
	my ($tree, $subdir, $custom) = ($package_list{$package}[0],
					$package_list{$package}[1], 
					$package_list{$package}[2]);
	chdir cvs_subdir($tree);

	if ( $faster )
	{
	    if ( -e "$package_output/${package}-.*" )
	    {
		print "-faster set.  ${package} exists, skipping.\n";
		next;
	    }
	}

	if ( $custom eq "gpt" ){
	    package_source_gpt($package, $subdir, $tree);
	} elsif ( $custom eq "pnb" ){
	    package_source_pnb($package, $subdir, $tree);
	} elsif ( $custom eq "tar" ) { 
	    package_source_tar($package, $subdir);
	} else {
	    print "ERROR: Unkown custom packaging type '$custom' for $package.\n";
	}
    }
    
    print "\n";
}

# --------------------------------------------------------------------
sub package_source_gpt()
# --------------------------------------------------------------------
{
    my ($package, $subdir, $tree) = @_;
    
    if ( ! -d $subdir )
    {
	print "$subdir does not exist, skipping\n";
    } else {
	$ENV{'GPT_IGNORE_DEPS'}="and how";
	chdir $subdir;

	print "Following GPT packaging for $package.\n";

	if ( $package eq "globus_openssl" or
	     $package eq "globus_gsoap_soapcpp2")
	{
	    print "\tUsing openssl_tools version of autotools.\n";
	    my $OPATH = $ENV{PATH};
	    $ENV{PATH} = cvs_subdir('autotools') . "/autotools/openssl_tools/bin" . ":$OPATH";
	    log_system("./bootstrap", "$pkglog/$package");
	    paranoia("$package bootstrap failed.");
	    $ENV{PATH} = $OPATH;
	} else {
	    log_system("./bootstrap", "$pkglog/$package");
	    paranoia("$package bootstrap failed.");
	}

	#TODO: make function out of "NB" part of PNB, call it here.
	if ( $package eq "globus_gridftp_server" or $package eq "gsincftp") 
	{
	    print "\tSpecial love for gridftp_server and gsincftp\n";
	    my $version = gpt_get_version("pkg_data_src.gpt");

	    my $tarfile = "$package-$version";

	    #Strip leading dirs off of $subdir
	    my ($otherdirs, $tardir) = $subdir =~ m!(.+/)([^/]+)$!;

	    if ( -e Makefile )
	    {
		log_system("make distcean", "$pkglog/$package");
		paranoia "make distclean failed for $package";
	    }

	    chdir "..";
	    
	    # The dir we are tarring is probably called "source" in CVS.
	    # mv it to package name.
	    log_system("mv $tardir $package-$version",
		       "$pkglog/$package");
	    paranoia "system() call failed.  See $pkglog/$package.";
	    log_system("tar cf $package_output/$tarfile.tar $package-$version",
		       "$pkglog/$package");
	    paranoia "system() call failed.  See $pkglog/$package.";
	    log_system("gzip -f $package_output/$tarfile.tar",
		       "$pkglog/$package");
	    paranoia "system() call failed.  See $pkglog/$package.";

	    # Move it back so future builds find it.
	    log_system("mv $package-$version $tardir",
		       "$pkglog/$package");
	    paranoia "system() call failed.  See $pkglog/$package.";
	} else {	
	    log_system("./configure --with-flavor=$flavor",
		       "$pkglog/$package");
	    paranoia "configure failed.  See $pkglog/$package.";
	    log_system("make dist", "$pkglog/$package");
	    paranoia "make dist failed.  See $pkglog/$package.";
	    log_system("cp *.tar.gz $package_output", "$pkglog/$package");
	    paranoia "cp failed.  See $pkglog/$package.";
	    $ENV{'GPT_IGNORE_DEPS'}="";
	}
    }
}

# --------------------------------------------------------------------
sub package_source_pnb()
# --------------------------------------------------------------------
{
    my ($package, $subdir, $tree) = @_;
    my $tarname = $package_list{$package}[3];
    my $tarfile = cvs_subdir($tree) . "/tarfiles/" . $tarname;
    my $tarbase = $tarname;
    $tarbase =~ s!\.tar\.gz!!;
    my $patchfile = "${tarbase}-patch";

    print "Following PNB packaging for $package.\n";
    print "\tUsing tarfile: $tarfile.\n";

    chdir $subdir;

    my $version = gpt_get_version("pkg_data_src.gpt");
    log_system("gzip -dc $tarfile | tar xf -",
	       "$pkglog/$package");
    paranoia "Untarring $package failed.  See $pkglog/$package.";
    chdir $tarbase;
    log_system("patch -N -s -p1 -i ../patches/$patchfile",
	       "$pkglog/$package");
    paranoia "patch failed.  See $pkglog/$package.";

    # Strip off leading directory component
    my ($otherdirs, $tardir) = $subdir =~ m!(.+/)([^/]+)$!;

    chdir "../..";

    # The dir we are tarring is probably called "source" in CVS.
    # mv it to package name so tarball looks correct.
    log_system("mv $tardir $package-$version",
	       "$pkglog/$package");
    paranoia "a system() failed.  See $pkglog/$package.";
    log_system("tar cf $package_output/${package}-${version}.tar $package-$version",
	       "$pkglog/$package");
    paranoia "a system() failed.  See $pkglog/$package.";
    log_system("gzip -f $package_output/${package}-${version}.tar",
	       "$pkglog/$package");
    paranoia "a system() failed.  See $pkglog/$package.";

    # Move it back so future builds find it.
    log_system("mv $package-$version $tardir",
	       "$pkglog/$package");
    paranoia "a system() failed.  See $pkglog/$package.";
}

# --------------------------------------------------------------------
sub package_source_tar()
# --------------------------------------------------------------------
{
    my ($package, $subdir) = @_;

    my $package_name="${package}-src";
    my $destdir = "$source_output/$package_name";
    
    if ( ! -d $subdir )
    {
	print "CWD is " . cwd() . "\n";
	print "$subdir does not exist, skipping\n";
    } else {
	print "Creating source directory for $package\n";
	log_system("rm -fr $destdir", "$pkglog/$package");

	mkdir $destdir;
	log_system("cp -Rp $subdir/* $destdir", "$pkglog/$package");
	paranoia "Failed to copy $subdir to $destdir for $package.";
	log_system("touch $destdir/INSTALL", "$pkglog/$package");
	paranoia "touch $destdir/INSTALL failed";

	if ( -e "$destdir/pkgdata/pkg_data_src.gpt" and not $uncool)
	{
	    log_system("cp $destdir/pkgdata/pkg_data_src.gpt $destdir/pkgdata/pkg_data_src.gpt.in",
		       "$pkglog/$package");
	    paranoia "Metadata copy failed for $package.";
	} else {
	    log_system("mkdir $destdir/pkgdata/", "$pkglog/$package");
	    paranoia "mkdir failed during $package.";
	    log_system("cp $top_dir/package-list/$package/pkg_data_src.gpt  $destdir/pkgdata/pkg_data_src.gpt.in",
		   "$pkglog/$package");
	    paranoia "Metadata copy failed for $package.";
	    print "\tUsed pkgdata from package-list, not cool.\n";
	}
    
	#Introspect metadata to find version number.
	my $version = gpt_get_version("$destdir/pkgdata/pkg_data_src.gpt.in");

	my $tarfile = "$package-$version";
	
	chdir $source_output;
	log_system("tar czf $package_output/$tarfile.tar.gz $package_name",
		   "$pkglog/$package");
	paranoia "tar failed for $package.";
    }
}

#TODO: Add bundle logging.
#TODO: Add release version.  (--bundle-version and -bv)
# --------------------------------------------------------------------
sub bundle_sources()
# --------------------------------------------------------------------
{
    my $bundlename;

    mkdir $bundle_output;
    mkdir $bundlelog;
    chdir $bundle_output;

    for my $bundle ( @bundle_build_list )
    {
	next if $bundle eq "";
	next if $bundle eq "user_def";

	print "Trying to make bundle $bundle\n";
	mkdir $bundle;

	open(PKG, ">$bundle/packaging_list") or die "Can't open packaging_list: $!\n";

	for my $package ( @{$bundle_list{$bundle}} )
	{
	    next if $package eq $flavor or $package eq $flavor . $thread;
	    system("cp $package_output/*${package}-* $bundle");
	    paranoia("cp of $package_output/*${package}-* failed.");
	    print PKG "$package\n";
	}
	#TODO: Let user choose deps/nodeps
	#TODO: backticks make me nervous about using log_system
	system("($ENV{'GPT_LOCATION'}/sbin/gpt-bundle -nodeps -bn=$bundle -bv=$version -srcdir=$bundle `cat $bundle/packaging_list`) > $bundlelog/$bundle 2>&1");
	paranoia("Bundling of $bundle failed.  See $bundlelog/$bundle.");
    }
}


# --------------------------------------------------------------------
sub install_bundles
# --------------------------------------------------------------------
{
    chdir $bundle_output;

    for my $bundle ( @bundle_build_list )
    {
	next if $bundle eq "" or $bundle eq "user_def";
	
	my ($flava, @packages) = @{$bundle_list{$bundle}};
	
	print "Installing $bundle to $install using flavor $flava.\n";
	system("$ENV{'GPT_LOCATION'}/sbin/gpt-build $verbose ${bundle}-*.tar.gz $flava");
	paranoia("Building of $bundle failed.\n");
    }

}


END{}
1;

=head1 NAME

make-packages.pl - GT3 packaging tool

=head1 SYNOPSIS

make-packages.pl [options] [file ...]

Options:

    --skippackage          Don't create source packages
    --skipbundle           Don't create source bundles
    --install=<dir>        Install into <dir>
    --anonymous            Use anonymous cvs checkouts
    --no-updates           Don't update CVS checkouts
    --force                Force
    --faster               Don't repackage if packages exist already
    --flavor               Set flavor base.  Default gcc32dbg
    --gt2-tag              Set GT2 tag.  Default HEAD
    --gt3-tag              Set GT3 tag.  Default HEAD
    --verbose              Be verbose.  Also sends logs to screen.
    --bundles="b1,b2,..."  Create bundles b1,b2,...
    --packages="p1,p2,..." Create packages p1,p2,...
    --trees="t1,t2,..."    Work on trees t1,t2,... Default "gt2,gt3,cbindings"
    --paranoia             Exit at first error.
    --help                 Print usage message
    --man                  Print verbose usage page

=head1 OPTIONS

=over 8

=item B<--skippackage>

Don't create source packages.  In this case, you should have source
    packages already created in source-packages/

=item B<--skipbundle>

Don't create source bundles

=back

=head1 DESCRIPTION

B<This program> will read the given input file(s) and do something
useful with the contents thereof.

=cut
