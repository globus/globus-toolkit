use strict;

# Initialise filenames and check they're there

unless(-d 't/D_PackageFilelist/') {
  print STDERR "test data missing...";
  print "1..0\n";
  exit 0;
}

system("./t/D_PackageFilelist/run-test");
