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

    chomp($libslist);

    # For globus libraries, replace -lglobus_.* with ${libdir}/libglobus.*.a
    return join(' ',
        map { if (m!-lglobus!) { s!-l!\${libdir}/lib!; s!$!.a! } $_; }
        split(/ +/, $libslist));
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
