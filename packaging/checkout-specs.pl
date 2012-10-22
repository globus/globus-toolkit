#!/usr/bin/perl

use Cwd;
use Getopt::Long;

my $cvsuser = ':pserver:anonymous';
my $cvsroot = 'cvs.globus.org:/home/globdev/CVS/globus-packages';
my $sourcelistfile, $tag;

GetOptions( 'f|file=s' => \$sourcelistfile,
            'u|user=s' => \$cvsuser,
            'C|cvsroot=s' => \$cvsroot,
            't|tag=s' => \$tag);

$cvsroot = "$cvsuser\@$cvsroot"
        
if ($sourcelistfile ne '') {
    open(PKG, "$sourcelistfile");
} else {
    open(PKG, "etc/package-list-5.1.0");
}

mkdir "./source-trees";
chdir "./source-trees";
my $topsrcdir=cwd();
my %tagmap = ();

while ( <PKG> )
{
    my $log;
    my ($pkg, $subdir, $pnb, $pkgtag) = split(' ', $_);
    next if ($pkg =~ m/^#/ || $pkg =~ m/^$/);
    print cwd()."\n";
    print $subdir."\n";
    if ($tag ne '' && $pkgtag eq '') {
        $pkgtag = $tag;
    } elsif ($pkgtag eq '') {
        # no overriding tag is given, default to HEAD unless there's a
        # tag in the sourcelistfile
        $pkgtag = 'HEAD';
    }

    if (! exists($tagmap{$pkgtag})) {
        $tagmap{$pkgtag} = [];
    }
    push(@{$tagmap{$pkgtag}}, "$subdir");
}

foreach $t (keys %tagmap) {
    if ($t eq 'HEAD') {
        system("cvs", '-d', $cvsroot, 'co', @{$tagmap{$t}});
    } else {
        system("cvs", '-d', $cvsroot, 'co', '-r', $t, @{$tagmap{$t}});
    }
}
