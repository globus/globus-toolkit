#!/usr/bin/env perl
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

@INC = ("$ENV{GPT_LOCATION}/lib/perl", @INC);

# Where do things go?
chomp(my $top_dir = `dirname $0`);
$top_dir = cwd() . "/$top_dir";
my $cvs_prefix = $top_dir . "/source-trees/";
my $log_dir = $top_dir . "/log-output";
my $pkglog = $log_dir . "/package-logs";
my $bundlelog = $log_dir . "/bundle-logs";
my $source_output = $top_dir . "/source-output";
my $package_output = $top_dir . "/package-output";
my $bin_output = $top_dir . "/bin-pkg-output";
my $bundle_output = $top_dir . "/bundle-output";
my $bin_bundle_output = $top_dir . "/bin-bundle-output";

# What do I need to clean up from old buids?
my @cleanup_dirs = ('log-output', '$bundle_ouput/BUILD');

# tree_name => [ cvs directory, module, checkout-dir tag ]
my %cvs_archives = (
     'gt' => [ "/home/globdev/CVS/globus-packages", "all", $cvs_prefix, "HEAD" ],
      );

my %virtual_packages = ("trusted_ca_setup" => 1,
                        "globus_gram_job_manager_service_setup" => 1,
                        "mmjfs_service_setup" => 1,
                        "mjs_service_setup" => 1,
                        "simple_ca_setup" => 1,
                        "netlogger_c" => 1 );

# package_name => [ tree, subdir, build_type, 
#                   (patch-n-build file, if exists), (per-package tag) ]
my %package_list;

# bundle_name => [ flavor, flags, @package_array ]
my %bundle_list;

# Which of the bundles defined should I build?
my @bundle_build_list;
my %package_build_hash;
my @package_build_list;

# For each package, keep track of that package's dependencies.
# $package_dep_hash{$pkg1}{$pkg2} == 1 if pkg1 depends on pkg2
# $package_runtime_hash{$pkg1}{$pkg2} == 1 if pkg1 runtime depends on pkg2
my %package_dep_hash;
my %package_runtime_hash;

# Track package versions.  $package_version_hash{$pkg} = version(pkg1)
my %package_version_hash;

# Track version requirements.  $package_require_hash{$pkg1}{$pkgs2} = X
# implies that pkgs2 depends on pkg1 having major version X
my %package_require_hash;

# Which of the CVS trees should I operate on?
my @cvs_build_list;
my %cvs_build_hash;

# What flavor shall things be built as?
my $flavor = "default";
my $thread = "pthr";

my ($install, $installer, $anonymous, $force,
    $noupdates, $help, $man, $verbose, $skippackage,
    $skipbundle, $faster, $paranoia, $version, $uncool, $avoid_bootstrap,
    $binary, $deporder, $inplace, $restart_package, $doxygen,
    $deps, $graph, $listpack, $listbun, $cvsuser,
    $autotools, $gpt, $core, $enable_64bit ) =
   (0, 0, 0, 0,
    0, 0, 0, 0, 0, 
    0, 0, 1, "1.0", 0, 0,
    0, 0, "no", 0, 0,
    0, 0, 0, 0, "",
    1, 1, 1, "");

my @user_bundles;
my @user_packages;

GetOptions( 'i|install=s' => \$install,
            'installer=s' => \$installer,
            'a|anonymous!' => \$anonymous,
            'force' => \$force,
            'n|no-updates!' => \$noupdates,
            'faster!' => \$faster,
            'ab|avoid-bootstrap!' => \$avoid_bootstrap,
            'flavor=s' => \$flavor,
            'dir|gt2-dir|gt4-dir|gt-dir=s' => \$cvs_archives{gt}[2],
            't|gt2-tag|gt4-tag|gt-tag=s' => \$cvs_archives{gt}[3],
            'v|verbose!' => \$verbose,
            'skippackage!' => \$skippackage,
            'skipbundle!' => \$skipbundle,
            'binary!' => \$binary,
            'bundles=s' => \@user_bundles,
            'p|packages=s' => \@user_packages,
            'trees=s' => \@cvs_build_list,
            'paranoia!' => \$paranoia,
            'version=s' => \$version,
            'uncool!' => \$uncool,
            'inplace:s' => \$inplace,
            'deporder!' => \$deporder,
            'restart=s' => \$restart_package,
            'doxygen!' => \$doxygen,
            'autotools!' => \$autotools,
            'gpt!' => \$gpt,
            'core!' => \$core,
            'd|deps!' => \$deps,
            'graph!' => \$graph,
            'lp|list-packages!' => \$listpack,
            'lb|list-bundles!' => \$listbun,
            'cvs-user=s' => \$cvsuser,
            'help|?' => \$help,
            'man' => \$man,
) or pod2usage(2);

if ( $help or $man ) {
    pod2usage(2) if $help;
    pod2usage(1) if $man;
}

if ($flavor eq 'default')
{
    my $archname = $Config{'archname'};

    if ($archname =~ m/^ia64-/)
    {
        $flavor = 'gcc64dbg';
    }
    else
    {
        $flavor = 'gcc32dbg';
    }
}

# Allow comma separated packages or multiple instances.
@user_packages = split(/,/,join(',',@user_packages));
@user_bundles = split(/,/,join(',',@user_bundles));
@cvs_build_list = split(/,/,join(',',@cvs_build_list));

if($inplace eq "no")
{
    $inplace = 0;
}
else
{
    if($inplace)
    {
        if(substr($inplace, 0, 1) ne '/')
        {
            $inplace = cwd() . "/$inplace";
        }

        $cvs_archives{gt}[2] = $inplace;
    }
    
    $inplace = 1;
}

if($inplace && !$install)
{
    $install = cwd() . "/INSTALL";
}

if ( $flavor =~ /64/ ) {
    $enable_64bit = "--enable-64bit";
}


# main ()

cleanup();
mkdir $log_dir;
setup_environment();
generate_build_list();

exit if ( $listpack or $listbun );

if ( not $noupdates )
{
    if ( $deps  )
    {
        cvs_checkout_subdir("gt", "autotools");
    } else {
        get_sources();
    }
} else {
    print "Not checking out sources with -no-updates set.\n";
}

build_prerequisites();

if ( not $skippackage )
{
    package_sources();
} else {
    print "Not packaging sources with -skippackage set.\n";
}

if ( $inplace )
{
    print "Exiting after installation for inplace builds.\n";
    exit;
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
    install_packages();
} else {
    print "Not installing bundle because -install= not set.\n";
}

if ( $binary )
{
    generate_bin_packages();
} else {
    print "Not generating binary packages because -binary not set.\n";
}

exit 0;

# --------------------------------------------------------------------
sub generate_build_list()
# --------------------------------------------------------------------
{
    print "Generating package build list ...\n";

    if ( not defined(@cvs_build_list) )
    {
        @cvs_build_list = ("gt");
    }

    foreach my $tree (@cvs_build_list)
    {
        $cvs_build_hash{$tree} = 1;
    }

    # Figure out what bundles and packages exist.
    populate_bundle_list();
    populate_package_list();

    # Out of what exists, what shall we build?
    populate_bundle_build_list();
    populate_package_build_hash();

    # Do we need to pull in more packages?
    if ( $deps )
    {
        install_gpt();
        if ( $graph )
        {
            open(GRAPH, ">$top_dir/dotty.out");
            print GRAPH "digraph G {\n";
        }
        import_package_dependencies(%package_build_hash);
        if ( $graph )
        {
            print GRAPH "}";
            close GRAPH;
        }
        
        # To interact well with installs, need to make
        # a new bundle that contains everything that was
        # pulled in via --deps, so that GPT may sort them
        # for us.  Otherwise we install in the wrong order.
        push @{$bundle_list{"custom-deps"}}, $flavor;
        push @{$bundle_list{"custom-deps"}}, "";  # No flags
        for my $pk (keys %package_build_hash)
        {
           push @{$bundle_list{"custom-deps"}}, $pk;
        }

        @bundle_build_list = ( "custom-deps" );
    }

    if($deporder || $inplace)
    {
        my @plist = keys %package_build_hash;
        @package_build_list = dep_sort_packages(\@plist);
    } else {
        @package_build_list = keys %package_build_hash;
    }

    if($restart_package)
    {
        my $ind = 0;
        for my $p (@package_build_list)
        {
            if($restart_package eq $p)
            {
                last;
            }
            $ind++;
        }

        @package_build_list = splice(@package_build_list, $ind);
        
        if(scalar(@package_build_list) == 0)
        {
            print "ERROR: -restart option specified $restart_package, which is not in the package list\n\n";
            exit 1;
        }
    }

    if ( $listpack )
    {
       if ( $installer )
       {
           create_makefile_installer("$top_dir/$installer");
       } else
       {
           my @errors;
           print "Final package build list:\n";
           foreach my $dpk ( @package_build_list )
           {
                my $high = $package_version_hash{$dpk}{'major'};
                my $age = $package_version_hash{$dpk}{'age'};
                my $low = $high - $age;
                print "$dpk at version $package_version_hash{$dpk}{'major'}\n";
                foreach my $depender ( keys %{$package_require_hash{$dpk}} )
                {
                   my $req = $package_require_hash{$dpk}{$depender};
                   next if ( ($low le $req) && ( $req le $high ) );
                   push @errors, "$depender wants $dpk at $req, but it is $high with age $age\n";
                }
           }
           if ( @errors )
           {
              print "ERROR: Bad dependencies found: \n";
              foreach my $badguy ( @errors )
              {
                 print $badguy;
              }

              exit 1;
           }
       }
    }
}

sub create_makefile_installer
{
    my ($file) = $@;

    system("mkdir $top_dir/pacman_cache");
    open(INS, ">$top_dir/$installer") or die "Can't open $installer: $!\n";
    install_gt2_autotools();
    install_globus_core();

    # First list all the bundles as targets, followed by their depordered
    # package lists.  Then list all the packages as targets in both
    # threaded and unthreaded versions.  Bootstrap the CVS directories
    # as we go so they can be built.
    foreach my $bun ( @user_bundles )
    {
         open(PAC, ">$top_dir/pacman_cache/$bun.pacman");

         my ($flavor, $flag, @packs) = @{$bundle_list{$bun}};
         my $suffix = "";
         my @sdkbundle;

         print INS "$bun: ";
         print PAC "packageName('$bun')\n";
         print PAC "url('Globus', 'http://www.globus.org/toolkit')\n";

         if ( $flavor =~ /thr/ )
         {
              $suffix = "-thr";
         }

         # We have the dependency sorted list of packages in our build list.
         # We will go through it in order, printing out those packages which
         # appear in the current bundle.  This gives us a dep-sorted bundle
         foreach my $pack ( @package_build_list )
         {
              if ( grep /^$pack$/, @packs )
              {
                  print INS "$pack$suffix ";
                  print PAC "package('$pack$suffix');\n";
                  push @sdkbundle, "$pack" . "-thr";
              }
         }
         print INS "\n";
         close PAC;

         # Also list a threaded version for unthreaded bundles
         # May not always make sense to build, but good to have
         # the target available when it does.
         if ( not ( $flavor =~ /thr/ ) )
         {
             open(PAC, ">$top_dir/pacman_cache/${bun}-thr.pacman");
             print INS "$bun" . "-thr: ";
             print PAC "packageName('${bun}-thr')\n";
             foreach my $pack ( @sdkbundle )
             {
                 print INS "$pack ";
                 print PAC "package('$pack');\n";
             }
        }
        print INS "\n";
        close PAC;
    }
         
    foreach my $pack ( @package_build_list )
    {
         my $packname = $pack;
         # In 4.2, we now use system openssl if available, but we
         # still provide a backup copy of our 4.0.x openssl package.
         # There's a redirector in the configure/makefile of the installer
         # that will point globus_openssl at either the system wrapper or
         # the backup, so we change the packagename here.
         if ( $pack eq "globus_openssl" )
         {
              $packname = "globus_system_openssl";
         }

         open(PAC, ">$top_dir/pacman_cache/$pack.pacman");
         print PAC "packageName($pack)\n";
         print PAC "version($package_version_hash{$pack});\n";

         my $extras="";

         # This package gets run in a sudo environment that doesn't
         # have LD_LIBRARY_PATH set, so we want it to always be static.
         if ( $pack=~/globus_gridmap_and_execute/ )
         {
              $extras = "-static ";
         }

         print INS "${packname}-only: gpt\n";
         print INS "\t\$\{GPT_LOCATION\}/sbin/gpt-build $extras \$\{BUILD_OPTS\} -srcdir=source-trees/" . $package_list{$pack}[1] . " \${FLAVOR}\n";

         print INS "$packname: gpt ${packname}-runtime ${packname}-compile\n";
         print INS "${packname}-runtime: ";
         foreach my $deppack ( @package_build_list )
         {
              if ( $package_runtime_hash{$pack}{$deppack} )
              {
                   print INS " $deppack" unless ( $pack eq $deppack );
                   print PAC "package('$deppack');\n" unless ( $pack eq $deppack );
              }
         }
         print INS "\n";

         print INS "${packname}-compile: ";
         foreach my $deppack ( @package_build_list )
         {
              if ( $package_dep_hash{$pack}{$deppack} )
              {
                   print INS " ${deppack}-compile" unless ( $pack eq $deppack );
                   print PAC "package('$deppack');\n" unless ( $pack eq $deppack );
              }
         }

         # Barf.  netlogger_c is provided as an external package, so it's in virtual_packages
         # But globus_xio_netlogger_driver expresses a real GPT dep on it, so we need to
         # re-add it here so make -j2 builds won't try to build the driver before netlogger_c
         if ( $pack=~/globus_xio_netlogger_driver/ )
         {
              print INS " netlogger_c";
              print PAC "package('netlogger_c');\n";
         }

         print INS "\n";
         print PAC "cd ('\$GLOBUS_LOCATION')\n";
         print PAC "downloadUntarzip('GLOBUS/${pack}-$package_version_hash{$pack}.tar.gz')\n";
         print PAC "cd ()\n";
         close PAC;

         print INS "\t\$\{GPT_LOCATION\}/sbin/gpt-build $extras \$\{BUILD_OPTS\} -srcdir=source-trees/" . $package_list{$pack}[1] . " \${FLAVOR}\n";

         print INS "${packname}-only-thr: gpt\n";
         print INS "\t\$\{GPT_LOCATION\}/sbin/gpt-build $extras \$\{BUILD_OPTS\} -srcdir=source-trees-thr/" . $package_list{$pack}[1] . " \${FLAVOR}\${THR}\n";
         print INS "${packname}-thr: gpt ${packname}-thr-compile ${packname}-thr-runtime\n";
         print INS "${packname}-thr-runtime: ";
         foreach my $deppack ( @package_build_list )
         {
              if ( $package_runtime_hash{$pack}{$deppack} )
              {
                   print INS " $deppack" unless ( $pack eq $deppack );
                   # globus_replication_client_test has a runtime dep on
                   # globus_rls_server, which must be built threaded only
                   if ( $deppack eq "globus_rls_server" ) { print "-thr"; }
              }    
         }    
         print INS "\n";

         print INS "${packname}-thr-compile: ";
         foreach my $deppack ( @package_build_list )
         {
              if ( $package_dep_hash{$pack}{$deppack} )
              {
                   print INS " ${deppack}-thr-compile" unless ( $pack eq $deppack );
              }
         }
         print INS "\n";

         print INS "\t\$\{GPT_LOCATION\}/sbin/gpt-build $extras \$\{BUILD_OPTS\} -srcdir=source-trees-thr/" . $package_list{$pack}[1] . " \${FLAVOR}\${THR}\n";
         my ($tree, $subdir, $custom) = ($package_list{$pack}[0],
                                         $package_list{$pack}[1],
                                         $package_list{$pack}[2]);

         package_source_bootstrap($pack, $subdir, $tree);
    }

    close(INS) if $installer;
}

# --------------------------------------------------------------------
sub import_package_dependencies
# --------------------------------------------------------------------
{
    my (%package_hash) = @_;
    my %new_hash;

    for my $pack ( keys %package_hash )
    {
        cvs_checkout_package($pack) unless $noupdates;

        # For a patch-n-build, also need to get patch tarball
        if ( $package_list{$pack}[2] eq "pnb" )
        {
            print "PNB detected for $pack.\n";
            my $cvs_dir = $package_list{$pack}[0];
            my $tarfile = $package_list{$pack}[3];
            my $pkgtag = $package_list{$pack}[4];

            if ( ! -e "$cvs_dir/tarfiles/$tarfile" )
            {
                print "checking out $cvs_dir/tarfiles/$tarfile\n";
                cvs_checkout_subdir( $cvs_dir, "tarfiles/$tarfile",
                                     $pkgtag ) unless $noupdates;
            }
        }

        my $metadatafile = package_subdir($pack) . "/pkgdata/pkg_data_src.gpt.in";
        if ( ! -e $metadatafile )
        {
            $metadatafile = package_subdir($pack) . "/pkg_data_src.gpt";
        }
        if ( ! -e $metadatafile )
        {
            $metadatafile = package_subdir($pack) . "/pkgdata/pkg_data_src.gpt";
        }

        require Grid::GPT::V1::Package;
        my $pkg = new Grid::GPT::V1::Package;
        
        print "Reading in metadata for $pack.\n";
        $pkg->read_metadata_file("$metadatafile");

        $package_version_hash{$pack}{'major'} = $pkg->{'Version'}->{'major'};
        $package_version_hash{$pack}{'age'} = $pkg->{'Version'}->{'age'};

        for my $dep (keys %{$pkg->{'Source_Dependencies'}->{'pkgname-list'}})
        {
             print GRAPH "$pack -> $dep;\n" if $graph;
            next if $graph and ($dep =~ /setup/ or $dep =~ /rips/);

            # if we don't have $dep in our hash, add it and iterate
            if ( ($package_build_hash{$dep} ne 1) and 
                 ( ! exists $virtual_packages{$dep} ) )
            {
                $package_build_hash{$dep} = 1;
                $new_hash{$dep} = 1;
                print "Pulling in dependency $dep\n";
            }
        }
    }

    # This checks whether new_hash is empty
    if ( %new_hash )
    {
        import_package_dependencies(%new_hash);
    }
}

# --------------------------------------------------------------------
sub setup_environment()
# --------------------------------------------------------------------
{
    # Make STDOUT and STDERR flush after every write.
    my $oldfh = select(STDOUT);
    $| = 1;
    select(STDERR);
    $| = 1;
    select($oldfh);

    print "Setting up build environment.\n";

    if ( $install )
    {
        $ENV{GLOBUS_LOCATION} = $install;
    } else {
        $ENV{GLOBUS_LOCATION} = "$source_output/tmp_core";
    }

    if ( $doxygen )
    {
        $doxygen = "CONFIGOPTS_GPTMACRO=--enable-doxygen";
    } else {
        $doxygen = "";
    }

    if ( $verbose )
    {
        $verbose = "-verbose";
    } else {
        $verbose = "";
    }

    if ( $force )
    {
        $force = "-force";
    } else {
        $force = "";
    }


    report_environment();
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
    } else {
        print "You are using $0 from HEAD.\n";
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
    my $build_default;

    chdir "$top_dir/etc/";

    $build_default = "gpt";

    open(PKG, "package-list");

    while ( <PKG> )
    {
        my ($pkg, $subdir, $custom, $pnb, $pkgtag) = split(' ', $_);
        chomp $pkgtag;

        next if substr($pkg, 0, 1) eq "#";

        if ( $custom eq "" )
        {
            $custom = $build_default;
        }

        $package_list{$pkg} = [ "gt", $subdir, $custom, $pnb, $pkgtag ];
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
        my ($pkg, $bun, $threaded, $flags) = split(' ', $_);
        next if ( $pkg eq "" or $pkg eq "#" );
    
        chomp $flags;

        if ( $pkg eq "BUNDLE" )
        {
            $bundle = $bun;

            # Process threading and gpt-build flags (like -static)
            if ( $threaded eq "THREADED" )
            {
                push @{$bundle_list{$bundle}}, $flavor . $thread;
            } else {
                push @{$bundle_list{$bundle}}, $flavor;
            }

            if ( defined $flags )
            {
                push @{$bundle_list{$bundle}}, $flags;
            } else {
                push @{$bundle_list{$bundle}}, "";
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

        push @{$bundle_list{$bundle}}, $flavor;
        push @{$bundle_list{$bundle}}, "";
        push @{$bundle_list{$bundle}}, @user_packages;
        push @bundle_build_list, $bundle;
    } 

    if ( defined(@user_bundles) or defined(@user_packages))
    {
        foreach my $user_bundle (@user_bundles)
        {
            if (exists $bundle_list{$user_bundle} )
            {
                print "Bundle $user_bundle\n";
                push @bundle_build_list, $user_bundle;
                print "\n";
            } else {
                die "Unknown bundle requested: $user_bundle\n";
            }
        }
    } else {
        # build all bundles.
        for my $f ( keys %bundle_list )
        {
            push @bundle_build_list, $f;
            print "Bundle $f\n" if $listbun;
        }
    }
}

# --------------------------------------------------------------------
sub populate_package_build_hash()
# --------------------------------------------------------------------
{
    my @temp_build_list;

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
                # TODO: There must be a better way to skip flavors.
                # I don't like the magic number "2" below.  It comes
                # from having "flavor, flags" in the array ahead of
                # @package_list.  However, if I change it, this is
                # kludgy.
                my @tmp_array = @{$pkg_array};
                foreach my $pkg (@tmp_array[2..$#tmp_array]) {
                    push @temp_build_list, $pkg;
                }
            }
        }
    } else {
        @temp_build_list = keys %package_list;
    }

    # Eliminate duplicates in the temporary build list
    # A "Perl Idiom".
    %package_build_hash = map { $_ => 1 } @temp_build_list;
}

# --------------------------------------------------------------------
sub build_prerequisites()
# --------------------------------------------------------------------
{
    install_gpt() if $gpt;

    if ( $autotools )
    {
        install_gt2_autotools();
    }

    if ( $core && $gpt )
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
        open LOG, ">>$log";
        open FOO, "$command 2>&1 |";

        my $oldfh = select(STDOUT);
        select(LOG);
        $| = 1;
        select(FOO);
        $| = 1;
        select($oldfh);


        while (<FOO>)
        {
            my $line = $_;
            print $line;
            print LOG "$line";

        }

        close FOO;
        close LOG;
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
sub install_gpt()
# --------------------------------------------------------------------
{
    my $gpt_dir;
    my $gpt_ver;
    my $target;

    # we maintain a patched copy of gpt - find out what we call it
    $gpt_ver = `cat $top_dir/gpt/gpt_version`;
    chomp($gpt_ver);
    $gpt_ver = "gpt-$gpt_ver";
    $gpt_dir = $top_dir . "/$gpt_ver";

    # create a copy of 'gpt' with the version number and a tar.gz
    # to be used by other projects
    chdir($top_dir);
    if ( ! -d "$gpt_ver" ) 
    {
        system("cp -Rp gpt $gpt_ver");
        paranoia("Trouble making a copy of gpt to $gpt_ver");
    }
    if ( ! -f "$gpt_ver.tar.gz" )
    {
        system("tar czf $gpt_ver.tar.gz gpt");
        paranoia("Trouble taring up $gpt_ver");
    }

    if ( $install )
    {
        $target=$install;
    } else {
        $target=$gpt_dir;
    }
    
    $ENV{'GPT_LOCATION'} = $target;
    @INC = ("$ENV{GPT_LOCATION}/lib/perl", @INC);

    if ( -f "$target/sbin/gpt-build" )
    {
        print "GPT is already built, skipping.\n";
        print "Delete $target to force rebuild.\n";
    } else {
        print "Installing $gpt_ver to $target\n";
        print "Logging to ${log_dir}/$gpt_ver.log\n";

        chdir $gpt_dir;

        # gpt 3.0.1 has trouble if LANG is set, as on RH9
        # Newer GPTs will unset LANG automatically in build_gpt.
        my $OLANG = $ENV{'LANG'};
        $ENV{'LANG'} = "";
        system("./build_gpt $verbose > $log_dir/$gpt_ver.log 2>&1");
        $ENV{'LANG'} = $OLANG;

        paranoia("Trouble with ./build_gpt.  See $log_dir/$gpt_ver.log");
    }

    @INC = (@INC, "$target/lib/perl", "$target/lib/perl/$Config{'archname'}");
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

# --------------------------------------------------------------------
sub install_gt2_autotools()
# --------------------------------------------------------------------
{
    my $res;
    chdir cvs_subdir('gt'). "/autotools";

    if ( -e 'bin/automake' )
    {
        print "Using existing GT2 autotools installation.\n";
    } else {
        print "Building GT2 autotools.\n";
        print "Logging to ${log_dir}/gt2-autotools.log\n";

        if ( -e "install-autotools" )
        {            
            $res = log_system("./install-autotools `pwd`",
                    "${log_dir}/gt2-autotools.log");
        } else {
            die "ERROR: autotools/install-autotools doesn't exist.  Check cvs logs.";
        }

        if ( $? ne 0 )
        {
            print "\tAutotools dies the first time through sometimes due to\n";
            print "\temacs .texi issues.  I am trying again.\n";

            log_system("./install-autotools `pwd`", 
                    "${log_dir}/gt2-autotools.log");
            if ( $? ne 0 )
            {
                die "ERROR: Error building autotools.  Check log.\n";
            } else {
                print "\tWorked second time through.\n";
            }
        }
    }

    $ENV{'PATH'} = cwd() . "/bin:$ENV{'PATH'}";

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
    system("mkdir -p $pkglog");
    my $dir = $cvs_archives{gt}[2];
    my $coresrcdir = $dir . "/core/source";

    if ( $inplace ) {
        my $_cwd = cwd();
        if ( -d "$coresrcdir" ) {
  	    chdir $dir . "/core/source";
            if ( !$avoid_bootstrap || ! -e 'configure') {
               log_system("./bootstrap", "$pkglog/globus_core");
               paranoia("Bootstrap of globus_core in CVS failed.");
            }
            log_system("$ENV{GPT_LOCATION}/sbin/gpt-build -force $verbose $flavor", "$pkglog/globus_core");
            paranoia("gpt-build of globus_core from CVS failed.");
        } else {
            print "Your checkout doesn't have core/source in it, so I will not\n";
            print "try to build globus_core for you.\n"
        }
        chdir $_cwd;
    } else {
        print "$ENV{PWD}";
        log_system("$ENV{GPT_LOCATION}/sbin/gpt-build -nosrc $verbose $flavor", "$pkglog/globus_core");
        paranoia("gpt-build of globus_core from GPT failed.");
    }
}

# --------------------------------------------------------------------
sub cvs_subdir
# --------------------------------------------------------------------
{
    my ( $tree ) = @_;

    return $cvs_archives{$tree}[2];
}

# --------------------------------------------------------------------
sub cvs_tag
# --------------------------------------------------------------------
{
    my ( $tree ) = @_;

    return $cvs_archives{$tree}[3];
}

# --------------------------------------------------------------------
sub package_tree
# --------------------------------------------------------------------
{
    my ( $package ) = @_;

    return $package_list{$package}[0];
}

# --------------------------------------------------------------------
sub package_subdir
# --------------------------------------------------------------------
{
    my ( $package ) = @_;
    my ( $package_subdir ) = cvs_subdir( package_tree($package) ) . "/" . $package_list{$package}[1];

    if ( $package_subdir eq '/')
    {
        die "ERROR: No known source directory for package \"$package\".\n";
    }
    return $package_subdir;
}


# --------------------------------------------------------------------
sub get_sources()
# --------------------------------------------------------------------
{
    foreach my $tree ( @cvs_build_list )
    {
        print "Checking out cvs tree $tree.\n";
        if ( $tree eq "autotools" )
        {
            cvs_checkout_subdir("gt", "autotools");
        } else
        {
            cvs_checkout_generic( $tree );
        }
    }
}

# --------------------------------------------------------------------
sub set_cvsroot
# --------------------------------------------------------------------
{
    my ($cvsroot) = @_;

    if ( $anonymous )
    {
        $cvsroot = ":pserver:anonymous\@cvs.globus.org:" . $cvsroot;
    } elsif ( defined $ENV{'CVSROOT'} )
    {
        $cvsroot = $ENV{'CVSROOT'};
    } else {
        if ( not -d "$cvsroot" )
        {
            $cvsroot = "cvs.globus.org:$cvsroot";
            $cvsroot = $cvsuser . "@" . $cvsroot if ( $cvsuser );
            $ENV{CVS_RSH} = "ssh" unless defined $ENV{'CVS_RSH'};
        }
        # else cvsroot is fine as-is.
    }

    return $cvsroot
}

# --------------------------------------------------------------------
sub cvs_checkout_subdir
# --------------------------------------------------------------------
{
    my ( $tree, $dir, $pkgtag ) = @_;
    my $cvs_logs = $log_dir . "/cvs-logs";
    my ($cvsroot, $module, $cvs_dir, $tag) = @{$cvs_archives{$tree}};
    my $cvsopts = "-r $tag";
    my $locallog;

    mkdir $cvs_logs if not -d $cvs_logs;
    mkdir $cvs_prefix if not -d $cvs_prefix;
    mkdir $cvs_dir if not -d $cvs_dir;
    chdir $cvs_dir;

    $cvsroot = set_cvsroot($cvsroot);

    if ( $tag eq "HEAD" )
    {
        $cvsopts = "";
    }
    elsif ( $tag =~ m/\d{4}-\d{2}-\d{2}/)
    {
        $cvsopts = "-D $tag";
    }

    if ( $pkgtag )
    {
        $cvsopts = "-r $pkgtag";
    }

    $locallog = $dir;
    $locallog =~ tr|/|_|;

    if ( ! -d "$dir" ) 
    { 
        log_system("cvs -d $cvsroot co $cvsopts -P $dir",
                   "$cvs_logs/" . $locallog . ".log");
    } else { 
        log_system("cvs -d $cvsroot update -dP $dir", 
                   "$cvs_logs/" . $locallog . ".log");
    }
}

# --------------------------------------------------------------------
sub cvs_checkout_package
# --------------------------------------------------------------------
{
    my ( $package ) = @_;
    my $tree = package_tree($package);
    my $subdir = $package_list{$package}[1];
    my $pkgtag = $package_list{$package}[4];

    if (! defined($tree)) {
        print "ERROR: There was a dependency on package $package which I know nothing about.\n";
        die "Try a cvs update of packaging.\n";
    }

    print "Checking out $subdir from $tree.\n";
    cvs_checkout_subdir($tree, $subdir, $pkgtag);
}

# --------------------------------------------------------------------
sub cvs_checkout_generic ()
# --------------------------------------------------------------------
{
    my ( $tree ) = @_;
    my ($cvsroot, $module, $dir, $tag) = @{$cvs_archives{$tree}};
    my $cvs_logs = $log_dir . "/cvs-logs";
    my $cvsopts = "-r $tag";

    system("mkdir -p $cvs_logs") unless -d $cvs_logs;

    chdir $cvs_prefix;
    $cvsroot = set_cvsroot($cvsroot);


    if ( -d "$dir" ) {
        if ( $noupdates )
        {
            print "Skipping CVS update of $cvsroot\n";
            print "INFO: This means that I'm not checking the CVS tag for you, either.\n";
        } else
        {
            my @update_list;
            print "Updating CVS checkout of $cvsroot\n";
            chdir $dir;

            for my $f ( <*> )
            {
                chdir $f;
                if ( -d "CVS" )
                {
                    print "Queueing $f on update command.\n";
                    push @update_list, $f;
                }
                chdir '..';
            }
            print "Logging to ${cvs_logs}/" . $tree . ".log\n";

            log_system("cvs -d $cvsroot -z3 up -dP @update_list", "${cvs_logs}/" . $tree . ".log");
            paranoia "Trouble with cvs up on tree $tree."; 
        }
    } else 
    {
        print "Making fresh CVS checkout of \n";
        print "$cvsroot, module $module, tag $tag\n";
        print "Logging to $cvs_logs/" . $tree . ".log\n";
        system("mkdir -p $dir");
        paranoia("Can't make $dir: $!.\n");
        chdir $dir || die "Can't cd to $dir: $!\n";

        #CVS doesn't think of HEAD as a branch tag, so
        #don't use -r if you're checking out HEAD.
        if ( $tag eq "HEAD" )
        {
            $cvsopts = "";
        }
        elsif ( $tag =~ m/\d{4}-\d{2}-\d{2}/)
        {
            $cvsopts = "-D $tag";
        }
    
        log_system("cvs -d $cvsroot co -P $cvsopts $module",
                   "$cvs_logs/" . $tree . ".log");
    
        if ( $? ne 0 )
        {
            chdir "..";
            rmdir $dir;
            die "ERROR: There was an error checking out $cvsroot with module $module, tag $tag.\n";
        }
    
        print "\n";
    }
}

sub topol_sort
{
    my $node = shift;
    my $sorted_nodes_ref = shift;
    my $sorted_nodes_hashref = shift;
    my $in_call_stack = shift;

    if(exists $sorted_nodes_hashref->{$node})
    {
        return;
    }
    
    if(exists $in_call_stack->{$node})
    {
#        print "FAILED: A circular dependency was found with package: $node\n\n";
        return;
    }

    my $metadatafile = package_subdir($node) . "/pkgdata/pkg_data_src.gpt.in";
    if ( ! -e $metadatafile )
    {
        $metadatafile = package_subdir($node) . "/pkg_data_src.gpt";
    }
    if ( ! -e $metadatafile )
    {
        $metadatafile = package_subdir($node) . "/pkgdata/pkg_data_src.gpt";
    }

    require Grid::GPT::V1::Package;
    my $pkg = new Grid::GPT::V1::Package;

    $pkg->read_metadata_file("$metadatafile");

    my @deptypes = (keys %{$pkg->{'Source_Dependencies'}->{'deptype-list'}});
    for my $deptype (@deptypes)
    {
        if ( ( $deptype eq "pgm_runtime" ) or ($deptype eq "Setup") )
        {
            for my $dep (keys %{$pkg->{'Source_Dependencies'}->{'table'}->{$deptype}})
            {
               $package_runtime_hash{$node}{$dep} = 1;
            }
        }

        next unless ( ($deptype eq "compile") or ($deptype eq "pgm_link")
                       or ($deptype eq "lib_link") );
        for my $dep (keys %{$pkg->{'Source_Dependencies'}->{'table'}->{$deptype}})
        {
            $package_dep_hash{$node}{$dep} = 1;
            # This loop goes through the list of required packages and
            # stores the major version required by $node of $dep
            for my $pkgtype (keys %{$pkg->{'Source_Dependencies'}->{'table'}->{$deptype}->{$dep}->{'ANY'}})
            {
                my $numdeps = scalar @{$pkg->{'Source_Dependencies'}->{'table'}->{$deptype}->{$dep}->{'ANY'}->{$pkgtype}->{'versions'}};
                my %ref = %{$pkg->{'Source_Dependencies'}->{'table'}->{$deptype}->{$dep}->{'ANY'}->{$pkgtype}->{'versions'}[$numdeps - 1]};
		$package_require_hash{$dep}{$node} = $ref{'major'};
            }

            if(exists $package_build_hash{$dep})
            {
                $in_call_stack->{$node} = $node;
                topol_sort($dep, $sorted_nodes_ref, $sorted_nodes_hashref, $in_call_stack);
                delete $in_call_stack->{$node};
            }
        }
    }

    push @{$sorted_nodes_ref}, $node;   
    $sorted_nodes_hashref->{$node} = $node;
}

sub dep_sort_packages
{
    my $packages = shift;
    my @dep_ordered = ();
    my %tmp_hash = ();
    my %call_stack = ();
    
    # need gpt for dep checking
    install_gpt();

    for my $p (@{$packages})
    {
        topol_sort($p, \@dep_ordered, \%tmp_hash, \%call_stack);
    }

    return @dep_ordered;
}

# --------------------------------------------------------------------
sub package_sources()
# --------------------------------------------------------------------
{
    my $build_default;

    mkdir $pkglog;
    mkdir $source_output;
    mkdir $package_output;

    for my $package ( @package_build_list )
    {
        my ($tree, $subdir, $custom) = ($package_list{$package}[0],
                                        $package_list{$package}[1], 
                                        $package_list{$package}[2]);
        chdir cvs_subdir($tree);

        if ( $faster )
        {
            my ($glob) = glob("$package_output/${package}-*");
            if ( -f $glob )
            {
                my $file = `basename $glob`;
                print "On $package, --faster set.  Using existing $file";
                next;
            }
        }

        if ( $inplace )
        {
            if( $package eq "globus_core" )
            {
                # skip core in inplace build for now
                print "Installing globus_core\n";
                install_globus_core();
                next;
            }

            if( $custom eq "gpt" ){
                inplace_build($package, $subdir, $tree);
            } elsif ( $custom eq "pnb" ){
                my $packagefile = package_source_pnb($package, $subdir, $tree);
                
                die "ERROR: Failed to build and install tarball for $package\n" if(!defined($packagefile));

                print "Installing user requested package $package to $install using flavor $flavor.\n";
                system("$ENV{'GPT_LOCATION'}/sbin/gpt-build $force $verbose $packagefile $flavor");
                paranoia("Building of $package failed.\n");
            } elsif ( $custom eq "tar" ){
                my $packagefile = package_source_tar($package, $subdir);

                die "ERROR: Failed to build and install tarball for $package\n" if(!defined($packagefile));

                print "Installing user requested package $package to $install using flavor $flavor.\n";
                system("$ENV{'GPT_LOCATION'}/sbin/gpt-build $force $verbose $packagefile $flavor");
                paranoia("Building of $package failed.\n");
            }

            next;
        }

        if ( $custom eq "gpt" ){
            package_source_gpt($package, $subdir, $tree);
        } elsif ( $custom eq "pnb" ){
            package_source_pnb($package, $subdir, $tree);
        } elsif ( $custom eq "tar" ) { 
            package_source_tar($package, $subdir);
        } elsif ( $custom eq "make_gpt_dist" ) {
            package_source_make_gpt_dist($package, $subdir);
        } else {
            print "You probably listed --trees, and need a package not from your list:\n";
            die "ERROR: Unknown custom packaging type '$custom' for $package.\n";
        }
    }
    
    print "\n";
}

# --------------------------------------------------------------------
sub inplace_build()
# --------------------------------------------------------------------
{
    my ($package, $subdir, $tree) = @_;

    print "Inplace build: $package.\n";

    chdir $subdir;
    if ( !$avoid_bootstrap || ! -e 'configure')
    {
        log_system("./bootstrap", "$pkglog/$package");
        paranoia("Inplace bootstrap of $package in $subdir failed!");
    }
    my $build_args = "";
    $build_args .= " CONFIGOPTS_GPTMACRO=--enable-doxygen " if $doxygen;
    $build_args .= " -verbose " if $verbose;
    $build_args .= " -force " if $force;

    if($force)
    {
	log_system("make distclean", "$pkglog/$package");
    }

    log_system("$ENV{GPT_LOCATION}/sbin/gpt-build $build_args $flavor", "$pkglog/$package");
    paranoia("Inplace build of $package in $subdir failed!");

}

# --------------------------------------------------------------------
sub patch_package
# --------------------------------------------------------------------
{
    my ($package) = @_;

    my $tree = $package_list{$package}[0];
    my $subdir = $package_list{$package}[1];
    my $tarname = $package_list{$package}[3];

    chdir $subdir;

    my $tarfile = cvs_subdir($tree) . "/tarfiles/" . $tarname;
    my $tarbase = $tarname;
    $tarbase =~ s!\.tar\.gz!!;
    my $patchfile = "${tarbase}-patch";
    my $version = gpt_get_version("pkg_data_src.gpt");
    # Some patches will fail to apply a second time
    # So clean up the old patched tar directory if
    # it exists from a previous build.
    if ( -d "$tarbase" )
    {
        log_system("rm -fr $tarbase", "$pkglog/$package");
        paranoia("$tarbase exists, but could not be deleted.\n");
    }
   
    log_system("gzip -dc $tarfile | tar xf -",
               "$pkglog/$package");
    paranoia "Untarring $package failed.  See $pkglog/$package.";
    chdir $tarbase;
    if ( -f "../patches/$patchfile" )
    {
       log_system("patch -N -s -p1 -i ../patches/$patchfile",
                  "$pkglog/$package");
       paranoia "patch failed.  See $pkglog/$package.";
    } else {
       print "Not patching PNB $package.\n";
    }       
}

# --------------------------------------------------------------------
sub package_source_bootstrap()
# --------------------------------------------------------------------
{
    my ($package, $subdir, $tree) = @_;
    my $custom = $package_list{$package}[2];

    chdir cvs_subdir($tree);
    chdir $subdir;

    print "Bootstrapping $package.\n";
    system("mkdir -p $pkglog");

    if ( $custom eq "gpt" ){
       if ( !$avoid_bootstrap || ! -e 'configure') {
           log_system("./bootstrap", "$pkglog/$package");
           paranoia("bootstrap failed for package $package");
       }
    } elsif ( $custom eq "pnb" ){
       patch_package($package);
    } elsif ( $custom eq "tar" ) {
       log_system("ln -s pkg_data_src.gpt pkgdata/pkg_data_src.gpt.in", "$pkglog/$package");
       log_system("ln -s pkgdata/filelist filelist", "$pkglog/$package");
    } elsif ( $custom eq "make_gpt_dist" ) {
       log_system("make -f Makefile.in distprep", "$pkglog/$package");
    }
}

# --------------------------------------------------------------------
sub package_source_gpt()
# --------------------------------------------------------------------
{
    my ($package, $subdir, $tree) = @_;
    
    if ( ! -d $subdir )
    {
        die "$subdir does not exist, for package $package in tree $tree\n";
    } else {
        #This causes GPT not to worry about whether dependencies
        #have been installed while doing configure/make dist.
        #Any non-zero value will do.  I chose "and how" for fun.
        $ENV{'GPT_IGNORE_DEPS'}="and how";

        chdir $subdir;

        print "Following GPT packaging for $package.\n";

        if ( !$avoid_bootstrap || ! -e 'configure') {
            log_system("./bootstrap", "$pkglog/$package");
            paranoia("$package bootstrap failed.");
        }

        if ( -e 'Makefile' )
        {
           log_system("make distclean", "$pkglog/$package");
           paranoia("make distclean failed for $package");
        }

        #TODO: make function out of "NB" part of PNB, call it here.
        if ( $package eq "globus_wuftpd_gridftp_server" or $package eq "gsincftp") 
        {
            print "\tSpecial love for wuftpd_gridftp_server and gsincftp\n";
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
            log_system("tar chf $package_output/$tarfile.tar $package-$version",
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
            log_system("./configure --with-flavor=$flavor $enable_64bit",
                       "$pkglog/$package");
            paranoia "configure failed.  See $pkglog/$package.";
            log_system("make dist", "$pkglog/$package");
            paranoia "make dist failed.  See $pkglog/$package.";
            my $version = gpt_get_version("pkgdata/pkg_data_src.gpt");
            log_system("cp ${package}-${version}.tar.gz $package_output", "$pkglog/$package");
            paranoia "cp of ${package}-*.tar.gz failed: $!  See $pkglog/$package.";
            $ENV{'GPT_IGNORE_DEPS'}="";
        }
    }
}

# --------------------------------------------------------------------
sub package_source_pnb()
# --------------------------------------------------------------------
{
    my ($package, $subdir, $tree) = @_;
    #my $tarname = $package_list{$package}[3];
    #my $tarfile = cvs_subdir($tree) . "/tarfiles/" . $tarname;
    #my $tarbase = $tarname;
    #$tarbase =~ s!\.tar\.gz!!;
    #my $patchfile = "${tarbase}-patch";

    print "Following PNB packaging for $package.\n";
    #print "\tUsing tarfile: $tarfile.\n";

    chdir $subdir;
    my $version = gpt_get_version("pkg_data_src.gpt");
    patch_package($package);

    # Some patches will fail to apply a second time
    # So clean up the old patched tar directory if
    # it exists from a previous build.
    #if ( -d "$tarbase" )
    #{
        #log_system("rm -fr $tarbase", "$pkglog/$package");
        #paranoia("$tarbase exists, but could not be deleted.\n");
    #}

    #log_system("gzip -dc $tarfile | tar xf -",
               #"$pkglog/$package");
    #paranoia "Untarring $package failed.  See $pkglog/$package.";
    #chdir $tarbase;
    #log_system("patch -N -s -p1 -i ../patches/$patchfile",
               #"$pkglog/$package");
    #paranoia "patch failed.  See $pkglog/$package.";

    # Strip off leading directory component
    my ($otherdirs, $tardir) = $subdir =~ m!(.+/)([^/]+)$!;

    chdir "../..";

    # The dir we are tarring is probably called "source" in CVS.
    # mv it to package name so tarball looks correct.
    log_system("mv $tardir $package-$version",
               "$pkglog/$package");
    paranoia "a system() failed.  See $pkglog/$package.";
    log_system("tar chf $package_output/${package}-${version}.tar $package-$version",
               "$pkglog/$package");
    paranoia "a system() failed.  See $pkglog/$package.";
    log_system("gzip -f $package_output/${package}-${version}.tar",
               "$pkglog/$package");
    paranoia "a system() failed.  See $pkglog/$package.";

    # Move it back so future builds find it.
    log_system("mv $package-$version $tardir",
               "$pkglog/$package");
    paranoia "a system() failed.  See $pkglog/$package.";
    return "$package_output/${package}-${version}.tar.gz";
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
        print "$subdir does not exist for package $package.\n";
        return undef;
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
            if (!( -e "$destdir/filelist" ))
            {
              if ( -e "$destdir/pkgdata/filelist" )
              {
                    log_system("cp $destdir/pkgdata/filelist $destdir", "$pkglog/$package");
                  paranoia "Filelist copy failed for $package.";
              } else {
                  print "\tNo filelist found for $package.\n";
              }
            }
        } else {
            log_system("mkdir -p $destdir/pkgdata/", "$pkglog/$package");
            paranoia "mkdir failed during $package.";
            log_system("cp $top_dir/package-list/$package/pkg_data_src.gpt  $destdir/pkgdata/pkg_data_src.gpt.in",
                   "$pkglog/$package");
            paranoia "Metadata copy failed for $package.";
            log_system("cp $top_dir/package-list/$package/filelist  $destdir/",
                   "$pkglog/$package");
            paranoia "Filelist copy failed for $package.";
            print "\tUsed pkgdata from package-list, not cool.\n";
        }
    
        #Introspect metadata to find version number.
        my $version = gpt_get_version("$destdir/pkgdata/pkg_data_src.gpt.in");

        my $tarfile = "$package-$version";
        
        chdir $source_output;
        log_system("tar cvhzf $package_output/$tarfile.tar.gz $package_name",
                   "$pkglog/$package");
        paranoia "tar failed for $package.";
        return "$package_output/$tarfile.tar.gz";
    }
}

# --------------------------------------------------------------------
sub package_source_make_gpt_dist()
# --------------------------------------------------------------------
{
    my ($package, $subdir) = @_;

    chdir "$subdir";
    log_system("./make_gpt_dist", "$pkglog/$package");
    log_system("mv ${package}*.tar.gz $package_output", "$pkglog/$package");
}

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

        my @tmp_array = @{$bundle_list{$bundle}};
        for my $package ( @tmp_array[2..$#tmp_array])
        {
#            next if $package eq $flavor or $package eq $flavor . $thread;
            system("cp $package_output/${package}-* $bundle");
            paranoia("cp of $package_output/${package}-* failed.");
            print PKG "$package\n";
        }
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
        
        my ($flava, $flags, @packages) = @{$bundle_list{$bundle}};
        
        print "Installing $bundle to $install using flavor $flava, flags $flags.\n";
        system("$ENV{'GPT_LOCATION'}/sbin/gpt-build $doxygen $force $verbose $flags ${bundle}-*.tar.gz $flava");
        paranoia("Building of $bundle failed.\n");
    }

}

# --------------------------------------------------------------------
sub install_packages
# --------------------------------------------------------------------
{
   chdir $package_output;

   for my $pkg ( @user_packages )
   {
       print "Installing user requested package $pkg to $install using flavor $flavor.\n";
       system("$ENV{'GPT_LOCATION'}/sbin/gpt-build $force $verbose ${pkg}-*.tar.gz $flavor");
       paranoia("Building of $pkg failed.\n");
   }
}

# --------------------------------------------------------------------
sub generate_bin_packages
# --------------------------------------------------------------------
{
    mkdir $bin_bundle_output;
    mkdir $bundlelog;
    chdir $bin_bundle_output;
    my $arch=`uname -m`;
    chomp $arch;

    log_system("$ENV{'GPT_LOCATION'}/sbin/gpt-pkg -all -pkgdir=$bin_output $verbose", "$log_dir/binary_packaging");

    paranoia("Failure to package binaries.  See $log_dir/binary_packaging");

    for my $bundle ( @bundle_build_list )
    {
        next if $bundle eq "" or $bundle eq "user_def";
        print "$ENV{'GPT_LOCATION'}/sbin/gpt-bundle -bn='${bundle}-${arch}' -bv=$version -nodeps -bindir=$bin_output `cat $bundle_output/$bundle/packaging_list`\n";
        log_system("$ENV{'GPT_LOCATION'}/sbin/gpt-bundle -bn='${bundle}-${arch}' -bv=$version -nodeps -bindir=$bin_output `cat $bundle_output/$bundle/packaging_list`", "$bundlelog/binary_$bundle");

        paranoia("Failed to create binary bundle for $bundle.");
    }
}

END{}
1;

=head1 NAME

make-packages.pl - GT3 packaging tool

=head1 SYNOPSIS

make-packages.pl [options] [file ...]

Options:

    --skippackage           Don't create source packages
    --skipbundle            Don't create source bundles
    --install=<dir>         Install into <dir>
    --anonymous             Use anonymous cvs checkouts
    --cvsuser=<user>        Use "user" as account on CVS server
    --no-updates            Don't update CVS checkouts
    --noautotools           Don't build autotools
    --nogpt                 Don't build gpt
    --nocore                Don't build core
    --force                 Force
    --faster                Don't repackage if packages exist already
    --flavor=<flv>          Set flavor base.  Default gcc32dbg
    --gt-tag (-t)           Set GT and autotools tags.  Default HEAD
    --gt-dir (-d)           Set GT CVS directory.
    --autotools-dir         Set autotools CVS directory.
    --verbose               Be verbose.  Also sends logs to screen.
    --bundles="b1,b2,..."   Create bundles b1,b2,...
    --packages="p1,p2,..."  Create packages p1,p2,...
    --deps                    Automatically include dependencies
    --trees="t1,t2,..."     Work on trees t1,t2,... Default "gt"
    --noparanoia            Don't exit at first error.
    --inplace[=<dir>]       Build inplace. <dir> overrides the cvs directory
                            for all trees. (ie, a dir you did a 'cvs co all' in)
    --list-packages (-lp)   Print a list of packages suitable for a Makefile.
                            Also bootstraps those package dirs in CVS
    --avoid-bootstrap (-ab) Avoid bootstrapping packages
    --deps                  Read in GPT metadata and add packages that
                            the listed bundles/packages require
    --deporder              Build the packages in dependency order.
                            Implied by --inplace.
    --help                  Print usage message
    --man                   Print verbose usage page

=head1 OPTIONS

=over 8

=item B<--skippackage>

Don't create source packages.  In this case, you should have source
    packages already created in source-packages/

=item B<--skipbundle>

Don't create source bundles.

=item B<--install=dir>

Attempt to install packages and bundles into dir.  Short
version is "-i=".

=item B<--anonymous>

Use anonymous cvs checkouts.  Otherwise it defaults to using
CVS_RSH=ssh.  Short version is "-a"

=item B<--cvsuser=user>

Use "user@" as the prefix in the remote CVSROOT.  Useful if
your local account name is different than the CVS account name.

=item B<--no-updates>

Don't update CVS checkouts.  This is useful if you have local
modifications.  Note, however, that make-packages won't
check that your CVS tags match the requested CVS tags.
Short version is "-n"
 
=item B<--noautotools>

Don't build the GT2 autotools.  You must have the autotools
already on your PATH for this to work.

=item B<--nogpt>

Don't build GPT.  You must have the correct version of GPT
on your PATH already for this to work.

=item B<--nocore>

Don't build GT2 core.  You must have core installed from an existing
installation for this to work.

=item B<--faster>

Faster doesn't work correctly.  It is supposed to not try 
re-creating a package that has already been packaged.

=item B<--flavor=>

Set flavor base.  Default gcc32dbg.  You might want to
switch it to vendorcc.  Threading type is currently always
"pthr" if necessary.

=item B<--gt-tag=TAG>

Set GT tag.  Default HEAD.  Short version is "-t=".

=item B<--verbose>

Echoes all log output to screen.  Otherwise logs are just
stored under log-output.  Good for getting headaches.

=item B<--bundles="b1,b2,...">

Create bundles b1,b2,....  Bundles are defined under
etc/*/bundles

=item B<--packages="p1,p2,...">

Create packages p1,p2,....  Packages are defined under
etc/*/package-list

=item B<--inplace=dir>

Build inside of a CVS checkout.  Will not create
any GPT packages or bundles as output.

=item B<--deps>

Automatically pull in dependencies.  Useful if you
want to build one package or bundle, and only want to
build the packages that it requires.

=item B<--deporder>

Read in the GPT meatadata of packages, then perform
a topological sort before building them.  Implied
by --inplace builds, not necessary for builds of
dependency complete bundles.

=item B<--list-packages>

Print out a list of Makefile targets, and bootstrap
the CVS subdirectories so they are ready to build.
Used by the fait_accompli/installer.sh script
to create the Makefile-based installer.

=item B<--noparanoia>

Don't exit at first error.  Strongly discouraged.

=back

=head1 DESCRIPTION

B<make-packages.pl> goes from checking out CVS to
creating GPT packges, then bundles, then installing.

You can affect the flow of control by not updating
CVS with "-n"

=cut
