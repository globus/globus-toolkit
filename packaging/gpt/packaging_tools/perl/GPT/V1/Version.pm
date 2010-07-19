package Grid::GPT::V1::Version;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
use Data::Dumper;
use Grid::GPT::V1::XML;
use Grid::GPT::V1::Definitions;

# set the version for version checking
$VERSION     = 0.01;

@ISA         = qw(Exporter);
@EXPORT      = qw(&open_metadata_file &func2 &func4);
%EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],

sub create_version_list {
  my ($obj) = @_;
  die "ERROR: Grid::GPT::V1::XML object does not contain Version Tags\n"
    if $obj->{'name'} ne 'Version';

  my @versionlist;
  for my $v (@{$obj->{'contents'}}) {
    next if ref($v) ne 'HASH';
    my $version = new Grid::GPT::V1::Version(obj => $v);
    push @versionlist, $version;
  }
 
  return \@versionlist;
}


sub convert_version_list2xml {
  my ($versionlist, $xml) = @_;

  $xml->startTag('Version');
  $xml->characters("\n");
  for my $v (@$versionlist) {
    $v->write_tag($xml);
  }
  $xml->endTag('Version');
  $xml->characters("\n");
}

sub new {
    my ($that, %args)  = @_;
    my $class = ref($that) || $that;
    my $self  = {
		 type => $args{'type'},
		 major => $args{'major'},
		 minor => $args{'minor'},
		 age => $args{'age'},
		 upper_major => $args{'upper_major'},
		 upper_minor => $args{'upper_minor'},
		 lower_major => $args{'lower_major'},
		 lower_minor => $args{'lower_minor'},
		};
    bless $self, $class;
    if (defined($args{'obj'})) {
      my $obj = $args{'obj'};
      if( $obj->{'name'} eq 'Aging_Version' ||
          $obj->{'name'} eq 'BundleVersion' ) {
	$self->{'type'} = 'aging';
	$self->{'major'} = $obj->{'attributes'}->{'Major'};
	$self->{'minor'} = $obj->{'attributes'}->{'Minor'};
	$self->{'age'} = $obj->{'attributes'}->{'Age'};
      } elsif ($obj->{'name'} eq 'Simple_Version') {
	$self->{'type'} = 'simple';
	$self->{'major'} = $obj->{'attributes'}->{'Major'};
      } elsif ($obj->{'name'} eq 'Version_Range') {
	$self->{'type'} = 'range';
	$self->{'upper_major'} = $obj->{'attributes'}->{'Upper_Major'};
	$self->{'upper_minor'} = $obj->{'attributes'}->{'Upper_Minor'};
	$self->{'lower_major'} = $obj->{'attributes'}->{'Lower_Major'};
	$self->{'lower_minor'} = $obj->{'attributes'}->{'Lower_Minor'};
      }
      $self->validate(); 
    }

    if (defined $args{'label'}) {
      $self->{'type'} = 'aging';
      ($self->{'major'},$self->{'minor'},$self->{'age'}) = 
        $args{'label'} =~ m!(\d+)\.(\d+)(?:\.(\d+))?!;
      die "ERROR: $args{'label'} is not a valid version label\n"
        if ! defined $self->{'major'} or ! defined $self->{'minor'};
      $self->{'age'} = 0 if ! defined $self->{'age'};
    }

    return $self;
}

sub is_equal {
  my ($self, $other) = @_;
  return 0 if $self->{'type'} ne $other->{'type'};
  return 0 if $self->{'major'} != $other->{'major'};
  return 0 if $self->{'minor'} != $other->{'minor'};
  return 1;
}
	
sub is_newer {
  my ($self, $other) = @_;
  return 0 if $self->{'type'} ne $other->{'type'};
  return 1 if $self->{'major'} > $other->{'major'};
  return 0 if $self->{'major'} != $other->{'major'};
  return 1 if $self->{'minor'} > $other->{'minor'};
  return 0;
}
	
sub is_compatible {
  my ($self, $other) = @_;
  my ($aging_obj, $other_obj);
#  die "ERROR: Invalid version comparison $self->{'type'} $other->{'type'}\n" 
#    if $self->{'type'} ne 'aging' and $other->{'type'} ne 'aging';

  if ($self->{'type'} eq 'aging') {
    $aging_obj = $self;
    $other_obj = $other;
  } else {
    $aging_obj = $other;
    $other_obj = $self;    
  }


    if ($other_obj->{'type'} eq 'simple') {
      my $lower = $aging_obj->{'major'} - $aging_obj->{'age'};
      if ($other_obj->{'major'} >= $lower and 
	  $other_obj->{'major'} <= $aging_obj->{'major'}) {
	return 1;
      } else {
	return 0;
      }
    }
    
    if ($other_obj->{'type'} eq 'range' ) {
      return 0 if $aging_obj->{'major'} > $other_obj->{'upper_major'};
      return 0 if $aging_obj->{'major'} < $other_obj->{'lower_major'};
      return 1 if ! defined  $other_obj->{'upper_minor'} 
      or ! defined $other_obj->{'lower_minor'};
      return 0 if $aging_obj->{'minor'} > $other_obj->{'upper_minor'};
      return 0 if $aging_obj->{'minor'} < $other_obj->{'lower_minor'};
      return 1;
    }

}

sub validate {
  my ($self) = @_;

  if ($self->{'type'} eq 'aging') {

    die "ERROR: Major version not defined\n" if ! defined $self->{'major'};
    die "ERROR: Minor version not defined\n" if ! defined $self->{'minor'};
    die "ERROR: Age not defined\n" if ! defined $self->{'age'};

    die "ERROR: Range not used for this version type\n" 
      if defined $self->{'upper_major'} or defined $self->{'upper_minor'}
    or defined $self->{'lower_major'} or defined $self->{'lower_minor'};

  } elsif ($self->{'type'} eq 'simple') {

    die "ERROR: Major version not defined\n" if ! defined $self->{'major'};

    die "ERROR: Minor version not used for this version type\n" 
      if defined $self->{'minor'};
    die "ERROR: Age not used for this version type\n" if defined $self->{'age'};
    die "ERROR: Range not used for this version type\n" 
      if defined $self->{'upper_major'} or defined $self->{'upper_minor'}
    or defined $self->{'lower_major'} or defined $self->{'lower_minor'};

  } elsif ($self->{'type'} eq 'range') {

     die "ERROR: Upper range of major version not defined\n" 
       if ! defined $self->{'upper_major'};
     die "ERROR: Lower range of major version not defined\n" 
       if ! defined $self->{'lower_major'};

     die "ERROR: Invalid major version range\n" 
       if $self->{'upper_major'} < $self->{'lower_major'}; 
     die "ERROR: Invalid minor version range\n" 
       if $self->{'upper_major'} == $self->{'lower_major'} 
     and $self->{'upper_minor'} < $self->{'lower_minor'}; 
     
   
   } else {
     die "ERROR: Version type $self->{'type'} not recognized\n";
   }
}

sub clone {
    my $self = shift;
    my $clone = new Grid::GPT::V1::Version;
    replicate($self, $clone);
    return $clone;
}

sub replicate {
  my ($rold, $newclass) = @_;
  if (ref(\$rold) eq 'SCALAR') {
    return $rold;
  } elsif (ref($rold) eq 'ARRAY') {
    my @list = @$rold;
    return \@list;
  } elsif (ref($rold) eq 'HASH') {
    my $rnew = {};
    for my $e (sort keys %$rold) {
      $rnew->{$e} = replicate($rold->{$e});
    }
    return $rnew;

  } elsif (ref($rold) eq 'Grid::GPT::V1::Version' ) {
    for my $e (sort keys %$rold) {
      $newclass->{$e} = replicate($rold->{$e});
    }
    return;
  }
}

sub write_tag {
  my ($self, $xml) = @_;

  if ($self->{'type'} eq 'aging'){
    $xml->emptyTag('Aging_Version', 
		   Major => $self->{'major'}, 
		   Minor => $self->{'minor'}, 
		   Age => $self->{'age'});
    $xml->characters("\n");
    return;
  }
  
  if ($self->{'type'} eq 'simple'){
    $xml->emptyTag('Simple_Version', Major => $self->{'major'}); 
    $xml->characters("\n");
  }
  
  if ($self->{'type'} eq 'range'){
    if (defined($self->{'upper_minor'})) {
      $xml->emptyTag('Version_Range', 
		     Upper_Major => $self->{'upper_major'}, 
		     Lower_Major => $self->{'lower_major'}, 
		     Upper_Minor => $self->{'upper_minor'}, 
		     Lower_Minor => $self->{'lower_minor'});
      $xml->characters("\n");
      return;
    }
    
    $xml->emptyTag('Version_Range', 
		   Upper_Major => $self->{'upper_major'}, 
		   Lower_Major => $self->{'lower_major'});
    $xml->characters("\n");
    return;
  }

}

sub label {
  my ($self) = @_;
  my ($major, 
      $minor, 
      $upper_major, 
      $lower_major, 
      $upper_minor, 
      $lower_minor) = (
                       $self->{'major'}, 
                       $self->{'minor'},
                       $self->{'upper_major'}, 
                       $self->{'lower_major'},
                       $self->{'upper_minor'}, 
                       $self->{'lower_minor'},
                      );
  return "$major.$minor" if  $self->{'type'} eq 'aging';
  return "Simple: $major" . (defined $minor ? ".$minor" : "") if  $self->{'type'} eq 'simple';
  return "Range: $lower_major.$lower_minor - $upper_major.$upper_minor";
}
sub comp_id {
  my ($self) = @_;
  return "" if $self->{'type'} ne 'aging';
  my ($major, $minor, $age) = ($self->{'major'}, $self->{'minor'}, 
                               $self->{'age'});
  return "$major.$minor.$age";
}

sub rpm {
  my ($self, $name) = @_;
  my $rpm_string;

  if ($self->{'type'} eq 'aging') {
    # ignoring the minor version number
    for my $va (($self->{major} - $self->{age}) .. ($self->{major})) {
      if (defined $rpm_string) {
        $rpm_string .= ", $name-$va";
      } else {
        $rpm_string = "$name-$va";
      }
    }
    $rpm_string .= ", $name-$self->{'major'}.$self->{'minor'}, $name";
    return $rpm_string;
  }

  if ($self->{'type'} eq 'simple') {
    return "$name-$self->{'major'}";
  }

  if ($self->{'type'} eq 'range') {
    # RPM does not handle version operators correctly
#    return $name;

    $rpm_string = "$name <= $self->{'upper_major'}.$self->{'upper_minor'}";
    $rpm_string .= " $name >= $self->{'lower_major'}.$self->{'lower_minor'}";
    return $rpm_string;
  }
}

sub AUTOLOAD {
  use vars qw($AUTOLOAD);
  my $self = shift;
  my $type = ref($self) || croak "$self is not an object";
  my $name = $AUTOLOAD;
  $name =~ s/.*://;   # strip fully-qualified portion
  unless (exists $self->{$name} ) {
    croak "Can't access `$name' field in object of class $type";
  } 
  if (@_) {
    return $self->{$name} = shift;
  } else {
    return $self->{$name};
  } 
}

sub DESTROY {}
END { }       # module clean-up code here (global destructor)

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Grid::GPT::V1::Version - Perl extension for managing package version metadata

=head1 SYNOPSIS

  use Grid::GPT::V1::Version;
  my $a_ver = new Grid::GPT::V1::Version(type =>'aging', major => '4', minor =>'6', age =>'2');
  my $s_ver = new Grid::GPT::V1::Version(type =>'simple', major => '3');
  my $r_ver = new Grid::GPT::V1::Version(type =>'range', upper_major => '3', lower_major => '2');

  my $result = $a_ver->is_compatible($s_ver);

=head1 DESCRIPTION

I<Grid::GPT::V1::Version> is used to manage package version metadata. The
version metadata is to used to describe the version of a package as
well as dependencies to packages.

=head1 Version Metadata Types

There are several ways to express information about the compatibility
of the different versions.  This package supports the following
schemes which are called version metadata types.

=over 4

=item aging

This metadata is used to describe the version of a package. It consists of the following fields:

=over 4

=item major 

This is the main version number of the package.

=item minor

This is a number used to version bug fixes that maintain binary compatibility.

=item age

This number denotes the backward compatability of the package.  For
example a package with a major number of 5 and an age of 2 is
compatible back to version 3.

=back

=item simple

This metadata is used to describe the version requirements of a package dependency.
It consists of only a major version number.  The dependency indicates
with this metadata that it will accept a version if the major number
falls with in the age range of the package fulfilling the dependency.

=item range

This metadata is also used to describe the version requirements of a
package dependency.  The range is compared to the specific version
number of the package fulfilling the dependency.  Not that the age
criteria is not used here.  The metadata consists of the following:

=over 4

=item upper_major

The newest major version number accepted. 

=item lower_major

The oldest major version number accepted. 

=item upper_minor

The newest minor version number accepted. 

=item lower_minor

The oldest minor version number accepted. 

=back

=back

=head1 Methods

=over 4

=item new

Create a new I<Grid::GPT::V1::Version> object.  The following named arguments are accepted

=over 4

=item type

The type of version metadata this object will contain.

=item major

The major version number (used for aging and simple types).

=item minor

The minor version number (used only for the aging type).

=item age

The age of the major version (used only for the aging type).

=item upper_major

The newest major number allowed (used only for the range type).

=item upper_minor

The newest minor number allowed (used only for the range type).

=item lower_major

The oldest major number allowed (used only for the range type).

=item lower_minor

The oldest minor number allowed (used only for the range type).


=item obj

This passes in a L<Grid::GPT::V1::XML|Grid::GPT::V1::XML> version object.  The
version metadata is extracted from the object.

=back

=item is_compatible

Determines if the aging version metadata fulfills the requirements of
another version metadata which can be either simple version metadata
or range version metadata.  Returns 1 if the requirement is fulfilled.
Returns 0 otherwise.

=item validate

Determines if the version metadata is complete.

=item write_tag(xml_obj)

Adds version contents into an L<Grid::GPT::V1::XML|Grid::GPT::V1::XML> object. 

=item create_version_list(xml_obj)

Class function which creates a list of Version objects from a
L<Grid::GPT::V1::XML|Grid::GPT::V1::XML> object.  The function returns a
reference to the list.


=item convert_version_list2xml(version_list_reference, xml_obj)

Class function which adds the contents of all Version objects in a
list reference to an L<Grid::GPT::V1::XML|Grid::GPT::V1::XML> object.

=back

=head1 Versioning Examples

As an example consider the installed package foo which has a version
number of 5.3.  As was mentioned in the previous section, this
specifies a compatibility range of 2 to 5.  Now we want to install
package fum which depends on foo.  The following table shows how the
versioning works:


    Version specification for   Version
    Dependency foo to fum       Type           Dependency is met
    
    1                           Simple         No 
    1 to 4                      Range          No
    4 to 4                      Range          No
    3                           Simple         Yes
    3 to 6                      Range          Yes


=head1 AUTHOR

Eric Blau <eblau@ncsa.uiuc.edu> Michael Bletzinger <mbletzin@ncsa.uiuc,edu>

=head1 SEE ALSO

perl(1) GRID::GPT::V1::XML(1).

=cut
