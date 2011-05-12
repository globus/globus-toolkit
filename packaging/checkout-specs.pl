#!/bin/env perl
use Cwd;
use Getopt::Long;
my $sourcelistfile, $tag;

GetOptions( 'f|file=s' => \$sourcelistfile,
	    'u|user=s' => \$cvsuser,
	    't|tag=s' => \$tag);
  if ($cvsuser){
            $cvsroot = $cvsuser . "\@cvs.globus.org";
 }else{
        $cvsroot = ":pserver:anonymous\@cvs.globus.org"
 }
	
  if ($sourcelistfile ne ''){
    open(PKG, "$sourcelistfile");
  }else{
  open(PKG, "etc/package-list-spec");
  }
  mkdir "./source-trees";
  chdir "./source-trees";
  my $topsrcdir=cwd();
    while ( <PKG> )
    {
	my $log;
        my ($pkg, $subdir, $custom, $pnb, $pkgtag) = split(' ', $_);
	print cwd()."\n";
	print $subdir."\n";
	if ($tag ne ''){
	  system("cvs -d blau\@cvs.globus.org:/home/globdev/CVS/globus-packages co -r $tag $subdir");
	}else { #no overriding tag is given, default to HEAD unless there's a
		#tag in the sourcelistfile
	  if ($pkgtag eq ''){
	    system("cvs -d $cvsroot:/home/globdev/CVS/globus-packages co $subdir ");}
	  else {
	    system("cvs -d $cvsroot:/home/globdev/CVS/globus-packages co -r $pkgtag $subdir");
	  }
	}
	
    }



