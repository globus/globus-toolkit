#!/usr/bin/env perl

# What directory am I watching for commits?
$cvsmodule = "documentation/web";
# What is my CVSROOT?
$cvsroot = "/home/globdev/CVS/globus-packages";
# Where am I putting the commited files?
$webroot = "/mcs/www-unix.globus.org/toolkit/";
# What group ownership do they want?
$cvsgrp = "globdev";
# Shall I be chatty?
$verbose = 1;

if ( $verbose )
{
   print "Entirety of arguments:\n";
   print "@ARGV\n";
}

if ( ! -d $webroot )
{
   print "$webroot does not exist on the machine you're using as CVSROOT\n";
   print "These document changes will not be automatically propagated\n";
   exit;
}

($subdir, @files) = split(/ /,$ARGV[0]);

print "subdir is \"$subdir\"\n" if $verbose;
# Make sure loginfo is setup correctly
if ( $subdir =~ m#^($cvsmodule)(.*)# )
{
   $subdir = $2;
} else {
   print "I am not configured for cvs module $subdir.  Exiting.\n";
   exit;
}
$fulldir = "$webroot/$subdir";

# CVS dirs want to be group-writeable
umask 002;

# If the directory does not exist on the filesystem, this is probably
# a cvs add.  Check out the directory.
# If the directory does exist, this is probably a commit/add of files
# within that subdir.  Check them out/update them.
# In all cases, change group ownership, in case the user doesn't
# have the CVS group as a default
if ( ! -d $fulldir )
{
   chdir $webroot;
   print "Adding new subdirectory $subdir\n" if $verbose;
   # Take /path/to/new/dir, and run cvs up -dP on 
   # /path/to/new to add the lower-level dir.
   if ( $subdir =~ m#(.*/)([^/]+)# )
   {
       $checkoutdir = $1;
   }

   system("echo cvs up -dP ./$checkoutdir") if $verbose;
   system("cvs up -dP ./$checkoutdir");
   system("echo chgrp -R $cvsgrp $scheckoutdir") if $verbose;
   system("chgrp -R $cvsgrp $checkoutdir");
} else {
   chdir $fulldir;
   foreach my $f (@files) {
      print "Updating file $f in $fulldir\n" if $verbose;
      system("echo cvs up -dP $f") if $verbose;
      system("cvs up -dP $f");
      system("echo chgrp $cvsgrp $f") if $verbose;
      system("chgrp $cvsgrp $f");
   }
   if ( -f "Makefile" ) {
      system("echo Running make in the target directory");
      system("make");
   }
}

exit;
