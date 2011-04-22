#!/usr/bin/env perl

use File::Find;
use Data::Dumper;
use Cwd;

 my $gpt_dir;
    my $gpt_ver;
    my $target;
$top_dir = cwd();

    # we maintain a patched copy of gpt - find out what we call it
    $gpt_ver = `cat $top_dir/gpt/gpt_version`;
    chomp($gpt_ver);
    $gpt_ver = "gpt-$gpt_ver";
    $gpt_dir = $top_dir . "/$gpt_ver";
    $ENV{'GPT_LOCATION'} = $gpt_dir;

@INC = ("$ENV{GPT_LOCATION}/lib/perl", @INC);

my %packagemap;

#find(\&is_metadata, './source-trees');
find(\&is_spec, './source-trees');
print_packagelist();

sub is_metadata{
if ($File::Find::dir =~ /pkgdata$/){
     print "$File::Find::dir is a pkgdata dir\n";
if (($File::Find::name =~/pkg_data_src\.gpt\.in/)){
      print "$File::Find::name\n";
        require Grid::GPT::V1::Package;
        my $pkg = new Grid::GPT::V1::Package;

        print "Reading in metadata for $pack.\n";
        $pkg->read_metadata_file($_);

	$packagemap{$pkg->{'Name'}}=$File::Find::dir;
      }
      }

}
sub is_spec{
if (($File::Find::name =~/\.spec$/)){
        require Grid::GPT::V1::Package;
        my $pkg = new Grid::GPT::V1::Package;

        #print "Reading in metadata for $File::Find::name.\n";
        $pkg->read_metadata_file("\./pkgdata/pkg_data_src.gpt.in");

	$packagemap{$pkg->{'Name'}}=$File::Find::dir;
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

