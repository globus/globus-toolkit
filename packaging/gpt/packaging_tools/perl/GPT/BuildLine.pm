package Grid::GPT::BuildLine;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

use strict;

### convert_static_libs( $libslist, $flavor )
#
# change occurrences of -l<libname> to $GL/lib/lib<libname>.a
#
# [ used by ]
# globus_core:globus-makefile-header
#

sub convert_static_libs
{
    my ($libslist, $flavor) = @_;

    $libslist =~ s:\s+: :g;

    my @libs = split(/ /, $libslist);
    $libslist="";
    foreach my $libname (@libs)
    {
        if ( length($libslist) > 0 )
        {
            $libslist .= " ";
        }

        if ($libname =~ m!$flavor! || $libname =~ m!GLOBUS_FLAVOR_NAME!)
        {
            $libname =~ s/\-l/$ENV{GLOBUS_LOCATION}\/lib\/lib/;
            $libname = $libname.".a";
        }
        $libslist .= $libname;
    }
    return $libslist;
}

sub create_buildlines {
  my ($buildenvs) = @_;

  my $buildlines = { 
                    libs => "",
                    includes => "",
                    cflags => "",
                   };


  for my $be (reverse @$buildenvs) {
    $buildlines->{'extlibs'} .= "$be->{'ext_libs'} ";
    $buildlines->{'pkglibs'} .= "$be->{'pkg_libs'} ";
    $buildlines->{'includes'} .= "$be->{'includes'} ";
    $buildlines->{'cflags'} .= "$be->{'cflags'} ";
  }

  return $buildlines;

}


sub DESTROY {}
END { }       # module clean-up code here (global destructor)

1;
