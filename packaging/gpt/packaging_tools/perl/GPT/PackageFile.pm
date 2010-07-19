package Grid::GPT::PackageFile;

$VERSION = 1.00;

use strict;
use vars qw( $AUTOLOAD @ISA @EXPORT ); # Keep 'use strict' happy
use Carp;

require Exporter;
require AutoLoader;
require Grid::GPT::GPTObject;

@ISA = qw(Exporter AutoLoader Grid::GPT::GPTObject);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw(
);

#
# include standard modules
#

require Grid::GPT::MD5;

#
# data internal to the class
#

my $_count = 0;

#
# all of the md5 types
#

my $md5types = [ "build", "archive", "installation", "source" ];

#
# all of the keys that we don't want to clone
#

my $dontClone = [ "pkginfo" ];

#
# Class methods
#

sub get_count
{
    $_count;
}

sub _incr_count { ++$_count }
sub _decr_count { --$_count }

### new( $caller, %args )
#
# Object Constructor
#

sub new
{
    my $caller = shift;
    my(%args) = @_;
    my $caller_is_obj = ref($caller);
    my $class = $caller_is_obj || $caller;

    #
    # bless $self and up the ref count
    #

    my $self = bless {}, $class;

    if ( scalar(@_) == 0 )
    {
        $self->_incr_count();
        return $self;
    }

    #
    # handle arguments
    #

    my $pkginfo = $args{'pkginfo'};
    my $relativePath = $args{'relativePath'};

    #
    # jeez, i'd love to clone, but doing so takes up .08 seconds each time.  for each
    # entry in a filelist, that ends up taking quite a while.  i vote that we put up
    # sufficient safeguards so that the pkgnode object can't be too damaged, other than
    # just eating the processing time.
    #
    # my $pkginfo = $ppkginfo->clone();
    if ( defined($pkginfo) )
    {
        $self->{'pkginfo'} = $pkginfo;
    }

    if ( !defined($relativePath) )
    {
        confess("ERROR: relative path is undefined for file");
    }
    $self->{'relativePath'} = $relativePath;

    $self->{'path'} = undef;

    #
    # don't catalog md5 sums if we're not suppose to
    #

    my $captureMD5 = $args{'captureMD5'};
    if ( !defined($captureMD5) or $captureMD5 )
    {
        $self->{'captureMD5'} = 1;
    }
    else
    {
        $self->{'captureMD5'} = 0;
    }

    #
    # active files by default
    #

    $self->active(1);

    $self->_incr_count();

    return $self;
}

sub DESTROY
{
    $_[0]->_decr_count();
}

sub AUTOLOAD {
    use vars qw($AUTOLOAD);
    my $self = shift;
    my $type = ref($self) || croak "$self is not an obj";
    my $name = $AUTOLOAD;
    $name =~ s/.*://;   # strip fully-qualified portion
    unless (exists $self->{$name} ) {
        croak "Can't access `$name' field in obj of class $type";
    }
    if (@_) {
        return $self->{$name} = shift;
    } else {
        return $self->{$name};
    }
}

END { }

#
# Standard methods
#

sub setPkgNode
{
    my $self = shift;
    my(%args) = @_;

    my $node = $args{'node'};

    #
    # note: we also want to allow for the case where we are passed an undefined package
    # node object.
    #

    $self->{'pkginfo'} = $node;
}

### active( $value )
#
# This subroutine is used to set the value of the 'active' property on the file
# object.  The value of this property is used to determine whether or not the
# file should be output to a filelist.  Also, any harvesting of filelist information
# should remove references to files that are unactive.
#

sub active
{
    my $self = shift;
    my($value) = @_;

    if (defined($value))
    {
        if ($value)
        {
            $self->{'active'} = 1;
        }
        else
        {
            $self->{'active'} = 0;
        }
    }

    return $self->{'active'};
}

sub isActive
{
    my $self = shift;

    return $self->active();
}

sub isEqual
{
    my($self, $filearg) = @_;

    if ( $self->{'path'} eq $filearg->{'path'} )
    {
        return 1;
    }

    return 0;
}

sub md5IsAllowed
{
    my $self = shift;
    my(%args) = @_;

    if ( !defined($self->{'captureMD5'}) or $self->{'captureMD5'} )
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

sub turnOffMD5
{
    my $self = shift;
    my(%args) = @_;

    $self->{'captureMD5'} = 0;
    $self->{'md5'} = {};

    return 1;
}

sub setMD5
{
    my $self = shift;
    my(%args) = @_;

    if ( ! $self->{'captureMD5'} )
    {
        return 0;
    }

    my $type = $args{'type'};
    $type =~ s:^\s+|\s+$::g;

    my $value = $args{'value'};
    $value =~ s:^\s+|\s+$::g;

    my $md5 = $self->{'md5'};

    if ( (length($type) < 1) or !grep(/^$type$/, @$md5types) )
    {
        return 0;
    }

    if (!defined($md5))
    {
        $md5 = {};
        $self->{'md5'} = $md5;
    }

    $md5->{$type} = $value;

    return 1;
}

sub setPath
{
    my $self = shift;
    my(%args) = @_;

    my $path = $args{'path'};
    $path =~ s:^\s+|\s+$::g;
    $self->{'path'} = $args{'path'};

    return $self->{'path'};
}

sub getPath
{
    my $self = shift;

    return $self->{'path'};
}

sub getPkgNode
{
    my $self = shift;

    return $self->{'pkginfo'};
}

sub getTruePath
{
    my $self = shift;

    my $str = $self->{'relativePath'} . "/" . $self->getPath();
    $str =~ s:/+:/:g;

    return $str;
}

sub hasMD5
{
    my $self = shift;
    my(%args) = @_;

    for my $t (@$md5types)
    {
        if (defined($self->{'md5'}->{$t}))
        {
            return 1;
        }
    }

    return 0;
}

sub getMD5
{
    my $self = shift;
    my(%args) = @_;

    if ( !$self->{'captureMD5'} )
    {
        return undef;
    }

    my $type = $args{'type'};

    if ( !defined($type) )
    {
        return %{$self->{'md5'}};
    }

    if ( !defined($self->{'md5'}->{$type}) )
    {
        return undef;
    }

    return $self->{'md5'}->{$type};
}

sub groomMD5
{
    my $self = shift;
    my(%args) = @_;

    if ( !$self->{'captureMD5'} )
    {
        return 0;
    }

    my $newFile = $args{'file'};

    for my $t (@$md5types)
    {
        my $oldmd5 = $self->getMD5( type => $t );
        my $newmd5 = $newFile->getMD5( type => $t );

        if ( !defined($oldmd5) && defined($newmd5) )
        {
            $self->setMD5( type => $t, value => $newmd5 );
        }
    }

    return 1;
}

sub stamp
{
    my $self = shift;
    my(%args) = @_;

    if ( !$self->{'captureMD5'} )
    {
        return 0;
    }

    my $type = $args{'type'};
    if ( !defined($type) or !grep(/^$type$/, @$md5types) )
    {
        $type = "installation";
    }

    my $path = $self->getTruePath();
    if ( -e $path )
    {
        my $md5 = new Grid::GPT::MD5();
        $self->setMD5( type => $type, value => $md5->checksum(file => $path) );
    }

    return 1;
}

### clone( )
#
# special clone function to avoid cloning the pkgnode information
#

sub clone
{
    my $self = shift;

    my $file = new Grid::GPT::PackageFile();
    my @keys = keys %{$self};
    my @cloneKeys = map { $_ } grep {
                                        my $x = $_;
                                        !grep(/^$x$/, @$dontClone);
                                    } @keys;

    for my $k (@cloneKeys)
    {
        $file->{$k} = Grid::GPT::GPTObject::replicate($self->{$k});
    }

    return $file;
}

1; # Ensure that the module can be successfully use'd

__END__

=head1 NAME

Grid::GPT::PackageFile - Perl extension for an entry in any given filelist

=head1 SYNOPSIS

  use Grid::GPT::PackageFile;
  my $destFile = new Grid::GPT::PackageFile(
                        pkginfo => $self->{'pkginfo'},
                        relativePath => $self->{'relativePath'},
                        );

  #
  # to set/get the path of the file object.  getTruePath() returns the full path
  # to the file based on the context in which it was created.
  #

  $destFile->setPath( path => $path );
  $destFile->getPath();
  $destFile->getTruePath();

  #
  # to get the package node object to which the file is 'connected'
  #

  $destFile->getPkgNode();

  #
  # to create a stamp of the file in its current state
  #

  $destFile->stamp();

  #
  # to groom MD5 information from a file object ($srcFile) into this one ($destFile)
  #

  $destFile->groomMD5( file => $srcFile );

=head1 DESCRIPTION

I<Grid::GPT::PackageFile> is used to store information about each entry
that is read in from each of the filelist types within the PackageFilelist
object.  It is designed to be used across multiple types of filelists,
each offering differing featuresets.  Therefore, it currently has a nub
of 'featureset' functionality which is reflected in the turnOffMd5()
function.  Hopefully this can be used as a model for future development
across GPT.

Additionally, due to Perl's garbage collection mechanism, it has become
difficult to easily delete any PackageFile object since it will inevitably
be referenced from many different data structures.  Instead, an active()
method is defined on the object and is called during the 'cleanup' phase
of any work by a filelist object in which the file object is referenced.

=head1 AUTHOR

Chase Phillips <cphillip@ncsa.uiuc.edu>

=head1 SEE ALSO

perl(1) Grid::GPT::PackageFilelist::flat1(1) Grid::GPT::PackageFilelist::xml1(1) Grid::GPT::PackageFilelist(1) Grid::GPT::GPTFilelist(1)

=cut
