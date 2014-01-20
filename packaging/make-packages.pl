#!/usr/bin/env perl
# Basic strategy:
#  Iterate over etc/{cvstree}/package-list and /bundles
#  to get a list of packages and bundles defined by that tree.
#  Then, package up all the sources corresponding to the packages.
#  After that, make source bundles out of the packages.
#  Finally, install the resulting bundles.

use strict;
use warnings;
use Getopt::Long;
use Config;
use Cwd;
use Pod::Usage;

@INC = ("$ENV{GPT_LOCATION}/lib/perl", @INC);

# Where do things go?
(my $top_dir = $0) =~ s|/[^/]*$||;
if ($top_dir eq '.') {
    $top_dir = cwd();
} elsif ($top_dir !~ m|^/|) {
    $top_dir = cwd() . "/$top_dir";
}
my $cvs_prefix = "$top_dir/../";
my $log_dir = $top_dir . "/log-output";
my $pkglog = $log_dir . "/package-logs";
my $bundlelog = $log_dir . "/bundle-logs";
my $source_output = $top_dir . "/source-output";
my $package_output = $top_dir . "/package-output";
my $bin_output = $top_dir . "/bin-pkg-output";
my $bundle_output = $top_dir . "/bundle-output";
my $bin_bundle_output = $top_dir . "/bin-bundle-output";
$ENV{CONFIG_SITE} = "$top_dir/fait_accompli/config.site" if not exists $ENV{CONFIG_SITE};

# What do I need to clean up from old buids?
my @cleanup_dirs = ('log-output', '$bundle_ouput/BUILD');

my %virtual_packages = ("trusted_ca_setup" => 1,
                        "globus_gram_job_manager_service_setup" => 1,
                        "mmjfs_service_setup" => 1,
                        "mjs_service_setup" => 1,
                        "simple_ca_setup" => 1,
                        "netlogger_c" => 1);

# package_name => subdir
my %package_list;
my %external_package_list;

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
my %cvs_build_hash;

# What flavor shall things be built as?
my $flavor = "default";
my $thread = "pthr";

my $install=undef;
my $installer=0;
my $force=0;
my $help=0;
my $man=0;
my $verbose=0;
my $skippackage=0;
my $skipbundle=0;
my $faster=1;
my $version="1.0";
my $avoid_bootstrap=0;
my $binary=0;
my $restart_package=0;
my $doxygen=0;
my $deps=0;
my $graph=0;
my $listpack=0;
my $listbun=0;
my $gpt=1;
my $core=1;
my $enable_64bit="";
my $order_include_runtime_deps=0;

my @user_bundles;
my @user_packages;

GetOptions( 'i|install=s' => \$install,
            'installer=s' => \$installer,
            'force' => \$force,
            'faster!' => \$faster,
            'ab|avoid-bootstrap!' => \$avoid_bootstrap,
            'flavor=s' => \$flavor,
            'v|verbose!' => \$verbose,
            'skippackage!' => \$skippackage,
            'skipbundle!' => \$skipbundle,
            'binary!' => \$binary,
            'bundles=s' => \@user_bundles,
            'p|packages=s' => \@user_packages,
            'version=s' => \$version,
            'restart=s' => \$restart_package,
            'doxygen!' => \$doxygen,
            'gpt!' => \$gpt,
            'core!' => \$core,
            'd|deps!' => \$deps,
            'graph!' => \$graph,
            'lp|list-packages!' => \$listpack,
            'lb|list-bundles!' => \$listbun,
            'help|?' => \$help,
            'man' => \$man,
            'order-include-runtime-deps' => \$order_include_runtime_deps,
) or pod2usage(2);

if ( $help or $man ) {
    pod2usage(2) if $help;
    pod2usage(1) if $man;
}

if ($install && $install !~ m|^/|) {
    $install = getcwd() . "/$install";
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
@user_packages = map {split /,/} @user_packages;
@user_bundles = map {split /,/} @user_bundles;

if(!$install)
{
    $install = cwd() . "/INSTALL";
}

if ( $flavor =~ /64/ ) {
    $enable_64bit = "--enable-64bit";
}

# globus_common wants GLOBUS_VERSION set to create the
# globus-version script
if ( $install )
{
    my $gt_ver = `cat $top_dir/fait_accompli/version`;
    chomp($gt_ver);
    $ENV{'GLOBUS_VERSION'} = $gt_ver;
}


# main ()
cleanup();
mkdir $log_dir;
setup_environment();
generate_build_list();

exit if ( $listpack or $listbun );

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
sub generate_build_list
# --------------------------------------------------------------------
{
    print "Generating package build list ...\n";

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
        for my $pk (keys %package_build_hash)
        {
           push @{$bundle_list{"custom-deps"}}, $pk;
        }

        @bundle_build_list = ( "custom-deps" );
    }

    my @plist = keys %package_build_hash;
    @package_build_list = dep_sort_packages(\@plist);

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
                print "$dpk at version $package_version_hash{$dpk}{'major'}.$package_version_hash{$dpk}{'minor'}\n";
                foreach my $depender ( keys %{$package_require_hash{$dpk}} )
                {
                   my $req = $package_require_hash{$dpk}{$depender};
                   next if ( ($low <= $req) && ( $req <= $high ) );
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
    install_globus_core();

    # First list all the bundles as targets, followed by their depordered
    # package lists.  Then list all the packages as targets in both
    # threaded and unthreaded versions.  Bootstrap the CVS directories
    # as we go so they can be built.
    foreach my $bun ( @user_bundles )
    {
         my ($flavor, $flag, @packs) = @{$bundle_list{$bun}};
         my $suffix = "";
         my @sdkbundle;

         print INS "$bun: ";
         # We have the dependency sorted list of packages in our build list.
         # We will go through it in order, printing out those packages which
         # appear in the current bundle.  This gives us a dep-sorted bundle
         foreach my $pack ( @package_build_list )
         {
              if ( grep /^$pack$/, @packs )
              {
                  print INS "$pack$suffix ";
              }
         }
         print INS "\n";
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

         my $extras="";

         # This package gets run in a sudo environment that doesn't
         # have LD_LIBRARY_PATH set, so we want it to always be static.
         if ( $pack=~/globus_gridmap_and_execute/ )
         {
              $extras = "-static ";
         }

         print INS "${packname}-only: gpt\n";
         print INS "\t\$\{GPT_LOCATION\}/sbin/gpt-build $extras \$\{BUILD_OPTS\} -srcdir=source-trees/" . $package_list{$pack} . " \${FLAVOR}\n";

         print INS "$packname: gpt ${packname}-runtime ${packname}-compile\n";
         print INS "${packname}-runtime: ";
         foreach my $deppack ( @package_build_list )
         {
              if ( $package_runtime_hash{$pack}{$deppack} )
              {
                   print INS " $deppack" unless ( $pack eq $deppack );
              }
         }
         print INS "\n";

         print INS "${packname}-compile: ";
         foreach my $deppack ( @package_build_list )
         {
              if ( $package_dep_hash{$pack}{$deppack} )
              {
                   print INS " ${deppack}-compile" unless ( $pack eq $deppack );
              }
         }

         # Barf.  netlogger_c is provided as an external package, so it's in
         # virtual_packages. But globus_xio_netlogger_driver expresses a real
         # GPT dep on it, so we need to re-add it here so make -j2 builds won't
         # try to build the driver before netlogger_c
         if ( $pack=~/globus_xio_netlogger_driver/ )
         {
              print INS " netlogger_c";
         }

         print INS "\n";

         print INS "\t\$\{GPT_LOCATION\}/sbin/gpt-build $extras \$\{BUILD_OPTS\} -srcdir=source-trees/" . $package_list{$pack} . " \${FLAVOR}\n";

         package_source_bootstrap($pack, $package_list{$pack});
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
        my $subdir = $package_list{$pack};
        my $metadatafile = (grep {-e "$_"} (
            "$subdir/pkgdata/pkg_data_src.gpt.in",
            "$subdir/pkg_data_src.gpt",
            "$subdir/pkgdata/pkg_data_src.gpt"))[0];

        next if (exists $external_package_list{$pack} && !$metadatafile);
        die "Unable to find metadata for $pack" unless $metadatafile;

        require Grid::GPT::V1::Package;
        my $pkg = new Grid::GPT::V1::Package;
        
        print "Reading in metadata for $pack.\n";
        $pkg->read_metadata_file("$metadatafile");

        $package_version_hash{$pack}{'major'} = $pkg->{'Version'}->{'major'};
        $package_version_hash{$pack}{'minor'} = $pkg->{'Version'}->{'minor'};
        $package_version_hash{$pack}{'age'} = $pkg->{'Version'}->{'age'};
        $package_version_hash{$pack}{'version'} = $pkg->{'Version'}->{'major'} 
                    . "." . $pkg->{'Version'}->{'minor'};

        for my $dep (keys %{$pkg->{'Source_Dependencies'}->{'pkgname-list'}})
        {
            print GRAPH "$pack -> $dep;\n" if $graph;
            next if $graph and ($dep =~ /setup/ or $dep =~ /rips/);

            # if we don't have $dep in our hash, add it and iterate
            if ((!$package_build_hash{$dep}) and 
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
sub setup_environment
# --------------------------------------------------------------------
{
    # Make STDOUT and STDERR flush after every write.
    my $oldfh = select(STDOUT);
    $| = 1;
    select(STDERR);
    $| = 1;
    select($oldfh);

    print "Setting up build environment.\n";

    if ( $install ) {
        $ENV{GLOBUS_LOCATION} = $install;
    } else {
        $ENV{GLOBUS_LOCATION} = "$source_output/tmp_core";
    }

    if ( $doxygen ) {
        $doxygen = "CONFIGOPTS_GPTMACRO=--enable-doxygen";
    } else {
        $doxygen = "";
    }

    if ( $verbose ) {
        $verbose = "-verbose";
    } else {
        $verbose = "";
    }

    if ( $force ) {
        $force = "-force";
    } else {
        $force = "";
    }

    report_environment();
}

# --------------------------------------------------------------------
sub report_environment
# --------------------------------------------------------------------
{
    if ( $install )
    {
        print "Installing to $install\n";
    }

    print "\n";
}
    
            
# --------------------------------------------------------------------
sub cleanup
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
    open(my $pkg_fh, "$top_dir/etc/packages");

    while ( <$pkg_fh> )
    {
        s/#.*//;
        s/\s*$//;
        next if $_ eq '';

        my ($pkg, $subdir) = split;

        $package_list{$pkg} = "$cvs_prefix/$subdir";
    }
    close ($pkg_fh);

    open (my $pkg_external_fh, "$top_dir/etc/packages-external");
    while ( <$pkg_external_fh> )
    {
        chomp;
        s/#.*//;
        while (/\\$/) {
            chop;
            chomp(my $continuation = <$pkg_external_fh>);
            $continuation =~ s/#.*//;
            $_ .= " $continuation";
        }
        next if $_ eq '';

        my ($pkg, $subdir, $tarball, $commands) = split(' ', $_, 4);

        $package_list{$pkg} = "$cvs_prefix/$subdir";
        %{$external_package_list{$pkg}} = (
                tarball => $tarball,
                commands => $commands );
        system($commands);
    }
    close ($pkg_external_fh);
}

# --------------------------------------------------------------------
sub populate_bundle_list
# --------------------------------------------------------------------
{
    my $bundle;
    open(my $bunfh, "$top_dir/etc/bundles");

    while ( <$bunfh> )
    {
        s/#.*//;
        s/\s*$//;
        next if $_ eq '';

        my ($pkg, $bun) = split;
    
        if ( $pkg eq "BUNDLE" ) {
            $bundle = $bun;
            @{$bundle_list{$bundle}} = ();
        } else {
            if ( ! $bundle) {
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
    if ( @user_packages ) 
    {
        my $bundle = "user_def";

        push @{$bundle_list{$bundle}}, @user_packages;
        push @bundle_build_list, $bundle;
    } 

    if ( @user_bundles or @user_packages)
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
sub populate_package_build_hash
# --------------------------------------------------------------------
{
    # make the decision of whether to build all source packages or no.
    # bundle_build_list = array of bundle names.
    # $bundle_list{'bundle name'} = array of packages.
    # So, for each bundle to build, run through the array of packages
    # and add it to the list of packages to be built.
    if ( @bundle_build_list ) 
    {
        my @bundle_pkgs = map {@{$bundle_list{$_}}} @bundle_build_list;
        %package_build_hash = map { $_ => 1} @bundle_pkgs;
    } else {
        %package_build_hash = map { $_ => 1 } keys %package_list;
    }
}

# --------------------------------------------------------------------
sub build_prerequisites
# --------------------------------------------------------------------
{
    install_gpt() if $gpt;

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

    if ($? ne 0)
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

        chdir "$gpt_dir/packaging_tools";
        system("./bootstrap > $log_dir/$gpt_ver.log 2>&1");
        chdir $gpt_dir;

        # gpt 3.0.1 has trouble if LANG is set, as on RH9
        # Newer GPTs will unset LANG automatically in build_gpt.
        my $OLANG = $ENV{'LANG'};
        $ENV{'LANG'} = "";
        system("./check-gpt-prereqs $verbose");
        paranoia("Missing prerequisites");

        system("./build_gpt $verbose >> $log_dir/$gpt_ver.log 2>&1");
        $ENV{'LANG'} = $OLANG;

        paranoia("Trouble with ./build_gpt.  See $log_dir/$gpt_ver.log");
        system("./make_gpt_dist >> $log_dir/$gpt_ver.log 2>&1");
	mkdir $package_output;
        system("mv ${gpt_ver}*.tar.gz $package_output");
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
    my $coresrcdir = "$cvs_prefix/core/source";

    my $_cwd = cwd();
    if ( -d "$coresrcdir" ) {
        chdir "$coresrcdir";
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
    my ( $package_subdir ) = $package_list{$package};

    if ( $package_subdir eq '/')
    {
        die "ERROR: No known source directory for package \"$package\".\n";
    }
    return $package_subdir;
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
    if ( ! -e $metadatafile )
    {
        push @{$sorted_nodes_ref}, $node;   
        return;
    }

    require Grid::GPT::V1::Package;
    my $pkg = new Grid::GPT::V1::Package;

    $pkg->read_metadata_file("$metadatafile");

    my @deptypes = (keys %{$pkg->{'Source_Dependencies'}->{'deptype-list'}});
    for my $deptype (@deptypes)
    {
        if (!$order_include_runtime_deps) {
            if ( ( $deptype eq "pgm_runtime" ) or ($deptype eq "Setup") )
            {
                for my $dep (keys %{$pkg->{'Source_Dependencies'}->{'table'}->{$deptype}})
                {
                   $package_runtime_hash{$node}{$dep} = 1;
                }
            }

            next unless ( ($deptype eq "compile") or ($deptype eq "pgm_link")
                           or ($deptype eq "lib_link"));
        } else {
            next unless ( ($deptype eq "compile") or ($deptype eq "pgm_link")
                           or ($deptype eq "lib_link")
                           or ($deptype eq 'pgm_runtime')
                           or ($deptype eq 'Setup'));
        }
        for my $dep (keys %{$pkg->{'Source_Dependencies'}->{'table'}->{$deptype}})
        {
            $package_dep_hash{$node}{$dep} = 1;
            # This loop goes through the list of required packages and
            # stores the major version required by $node of $dep
            for my $pkgtype (keys %{$pkg->{'Source_Dependencies'}->{'table'}->{$deptype}->{$dep}->{'ANY'}})
            {
                my $numdeps = scalar @{$pkg->{'Source_Dependencies'}->{'table'}->{$deptype}->{$dep}->{'ANY'}->{$pkgtype}->{'versions'}};
                my %ref = %{$pkg->{'Source_Dependencies'}->{'table'}->{$deptype}->{$dep}->{'ANY'}->{$pkgtype}->{'versions'}[$numdeps - 1]};
                if (defined($ref{major})) {
                    $package_require_hash{$dep}{$node} = $ref{'major'};
                } elsif (defined($ref{lower_major})) {
                    $package_require_hash{$dep}{$node} = $ref{'lower_major'};
                }
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
sub package_sources
# --------------------------------------------------------------------
{
    my $build_default;

    mkdir $pkglog;
    mkdir $source_output;
    mkdir $package_output;

    log_system("cp ${top_dir}/epstopdf-2.9.5gw $package_output", "make-packages.log");

    for my $package ( @package_build_list )
    {
        my ($subdir) = $package_list{$package};
        chdir $subdir;

        if ( $faster )
        {
            my ($glob) = glob("$package_output/${package}-*");
            if ( $glob && -f $glob )
            {
                my $file = `basename $glob`;
                print "On $package, --faster set.  Using existing $file";
                next;
            }
        }

        if( $package eq "globus_core" )
        {
            # skip core in inplace build for now
            print "Installing globus_core\n";
            install_globus_core();
            next;
        }

        inplace_build($package, $subdir);
        package_source_gpt($package, $subdir) unless $skippackage;
        next;
    }
    
    print "\n";
}

# --------------------------------------------------------------------
sub inplace_build()
# --------------------------------------------------------------------
{
    my ($package, $subdir) = @_;

    print "Inplace build: $package.\n";

    chdir $subdir;
    if ( !$avoid_bootstrap || ! -e 'configure')
    {
        if (-f 'bootstrap') {
            log_system("./bootstrap", "$pkglog/$package");
            paranoia("Inplace bootstrap of $package in $subdir failed!");
        }
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
sub package_source_bootstrap
# --------------------------------------------------------------------
{
    my ($package, $subdir) = @_;
    my $oldcwd = getcwd();

    chdir "$cvs_prefix/$subdir";
    print "Bootstrapping $package.\n";
    system("mkdir -p $pkglog");

    if ( !$avoid_bootstrap || ! -e 'configure') {
       if (-f 'bootstrap') {
           log_system("./bootstrap", "$pkglog/$package");
           paranoia("bootstrap failed for package $package");
       }
    }
    chdir $oldcwd;
}

# --------------------------------------------------------------------
sub package_source_gpt
# --------------------------------------------------------------------
{
    my ($package, $subdir) = @_;
    
    if ( ! -d $subdir )
    {
        die "$subdir does not exist, for package $package\n";
    } else {
        #This causes GPT not to worry about whether dependencies
        #have been installed while doing configure/make dist.
        #Any non-zero value will do.  I chose "and how" for fun.
        $ENV{'GPT_IGNORE_DEPS'}="and how";

        chdir $subdir;

        print "Following GPT packaging for $package.\n";

        if ( !$avoid_bootstrap || ! -e 'configure') {
            if (-f 'bootstrap') {
                log_system("./bootstrap", "$pkglog/$package");
                paranoia("$package bootstrap failed.");
            }
        }

        if ( -e 'Makefile' )
        {
           log_system("make distclean", "$pkglog/$package");
           paranoia("make distclean failed for $package");
        }

        if ( -e 'configure') {
            log_system("./configure --with-flavor=$flavor $enable_64bit",
                       "$pkglog/$package");
            paranoia "configure failed.  See $pkglog/$package.";
            log_system("make dist", "$pkglog/$package");
            paranoia "make dist failed.  See $pkglog/$package.";
            my $version = gpt_get_version("pkgdata/pkg_data_src.gpt");
            log_system("cp ${package}-${version}.tar.gz $package_output", "$pkglog/$package");
            paranoia "cp of ${package}-*.tar.gz failed: $!  See $pkglog/$package.";
        } elsif ( -e 'setup.py') {
            log_system("rm -rf dist");
            paranoia("clean failed");
            log_system("python setup.py sdist");
            paranoia("sdist failed");
            log_system("cp dist/*.tar.gz $package_output");
            paranoia("cp failed");
        }
        delete $ENV{'GPT_IGNORE_DEPS'};
    }
}

# --------------------------------------------------------------------
sub bundle_sources
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

    return if ($skipbundle);
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
    --nogpt                 Don't build gpt
    --nocore                Don't build core
    --force                 Force
    --faster                Don't repackage if packages exist already
    --flavor=<flv>          Set flavor base.  Default gcc32dbg
    --gt-dir (-d)           Set GT CVS directory.
    --verbose               Be verbose.  Also sends logs to screen.
    --bundles="b1,b2,..."   Create bundles b1,b2,...
    --packages="p1,p2,..."  Create packages p1,p2,...
    --deps                    Automatically include dependencies
    --trees="t1,t2,..."     Work on trees t1,t2,... Default "gt"
    --list-packages (-lp)   Print a list of packages suitable for a Makefile.
                            Also bootstraps those package dirs in CVS
    --avoid-bootstrap (-ab) Avoid bootstrapping packages
    --deps                  Read in GPT metadata and add packages that
                            the listed bundles/packages require
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

=item B<--verbose>

Echoes all log output to screen.  Otherwise logs are just
stored under log-output.  Good for getting headaches.

=item B<--bundles="b1,b2,...">

Create bundles b1,b2,....  Bundles are defined under
etc/*/bundles

=item B<--packages="p1,p2,...">

Create packages p1,p2,....  Packages are defined under
etc/*/package-list

=item B<--deps>

Automatically pull in dependencies.  Useful if you
want to build one package or bundle, and only want to
build the packages that it requires.

=item B<--list-packages>

Print out a list of Makefile targets, and bootstrap
the CVS subdirectories so they are ready to build.
Used by the fait_accompli/installer.sh script
to create the Makefile-based installer.

=back

=head1 DESCRIPTION

B<make-packages.pl> goes from checking out CVS to
creating GPT packges, then bundles, then installing.

You can affect the flow of control by not updating
CVS with "-n"

=cut
