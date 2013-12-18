#!/usr/bin/perl    
use File::Basename;
use File::Spec;

my $gpt_dir;
    my $gpt_ver;
    my $target;
    my $top_dir = dirname(File::Spec->rel2abs($0));

    my $log_dir = $top_dir."/buildlog";
    mkdir $log_dir;


    # we maintain a patched copy of gpt - find out what we call it
    print $top_dir."\n";
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
        #paranoia("Trouble making a copy of gpt to $gpt_ver");
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
        #paranoia("Missing prerequisites");

        system("./build_gpt $verbose >> $log_dir/$gpt_ver.log 2>&1");
        $ENV{'LANG'} = $OLANG;

        #paranoia("Trouble with ./build_gpt.  See $log_dir/$gpt_ver.log");
        system("./make_gpt_dist >> $log_dir/$gpt_ver.log 2>&1");
	#mkdir $top_dir."/package_output";
        #system("mv ${gpt_ver}*.tar.gz $package_output");
        system("mv ${gpt_ver}*.tar.gz $top_dir");
    }

    @INC = (@INC, "$target/lib/perl", "$target/lib/perl/$Config{'archname'}");
    print "\n";

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
