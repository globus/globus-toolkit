package Grid::GPT::GPTFilelist;

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

require Grid::GPT::PackageFile;

#
# data internal to the class
#

my $_count = 0;

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
 
    #
    # increment refcount
    #

    $self->_incr_count();

    return $self;
}

sub DESTROY
{
    $_[0]->_decr_count();
}

sub AUTOLOAD
{
}

END { }

#
# Standard methods
#

sub verifyStructure
{
    my $self = shift;
    my(%args) = @_;

    if ( ! defined($self->{'filePaths'}) )
    {
        $self->{'filePaths'} = {};
    }

    if ( ! defined($self->{'filePathsList'}) )
    {
        $self->{'filePathsList'} = [];
    }

    if ( ! defined($self->{'fileNodes'}) )
    {
        $self->{'fileNodes'} = {};
    }

    if ( ! defined($self->{'conflicts'}) )
    {
        $self->{'conflicts'} = {};
    }
}

sub reset
{
    my $self = shift;
    my(%args) = @_;

    if ( defined($self->{'filePaths'}) )
    {
        $self->{'filePaths'} = {};
    }

    if ( defined($self->{'filePathsList'}) )
    {
        $self->{'filePathsList'} = [];
    }

    if ( defined($self->{'fileNodes'}) )
    {
        $self->{'fileNodes'} = {};
    }

    if ( defined($self->{'conflicts'}) )
    {
        $self->{'conflicts'} = {};
    }
}

### addFile( file => $file )
#
# Add file to our internal listing of files.
#

sub addFile
{
    my $self = shift;
    my(%args) = @_;

    my $file = $args{'file'};

    if ( !defined($file) )
    {
        die("ERROR: file in package list is undefined");
    }

    $self->addToPaths(file => $file);
    $self->addToNodes(file => $file);

    return 1;
}

sub addToPaths
{
    my $self = shift;
    my(%args) = @_;

    my $file = $args{'file'};
    my $path = $file->getPath();

    $self->verifyStructure();

    if ( ! defined($self->{'filePaths'}->{$path}) )
    {
        $self->{'filePaths'}->{$path} = [];
    }
    else
    {
        $self->addConflict( file => $file );
    }

    push(@{$self->{'filePaths'}->{$path}}, $file);

    #
    # we also store the filepath in an array for quick path checks
    #

    if ( !grep(/^\Q$path\E$/, @{$self->{'filePathsList'}}) )
    {
        push(@{$self->{'filePathsList'}}, $path);
    }
}

sub addToNodes
{
    my $self = shift;
    my(%args) = @_;

    my $file = $args{'file'};
    my $node = $file->getPkgNode();

    if (!defined($node))
    {
       return;
    }

    $self->verifyStructure();

    if ( ! defined($self->{'fileNodes'}->{$node}) )
    {
        $self->{'fileNodes'}->{$node} = [];
    }

    push(@{$self->{'fileNodes'}->{$node}}, $file);
}

sub addConflict
{
    my $self = shift;
    my(%args) = @_;

    my $file = $args{'file'};
    my $node = $file->getPkgNode();

    if (!defined($node))
    {
        return;
    }

    if ( !defined($file) )
    {
        die("ERROR: file in package list is undefined");
    }

    $self->verifyStructure();

    if ( ! defined($self->{'conflicts'}->{$node}) )
    {
        $self->{'conflicts'}->{$node} = [];
    }

    push(@{$self->{'conflicts'}->{$node}}, $file);
    $self->{'conflictPresent'} = 1;
}

sub getConflicts
{
    my $self = shift;
    my(%args) = @_;

    my $node = $args{'node'};

    if ( !defined($node) )
    {
        die("ERROR: node object must be defined in getPackageConflicts");
    }

    my $list = [];

    if ( !$self->conflictPresent() )
    {
        return $list;
    }

    if ( ! defined($self->{'conflicts'}->{$node}) )
    {
        return $list;
    }

    for my $file (@{$self->{'conflicts'}->{$node}})
    {
        push(@$list, $file);
    }

    return $list;
}

sub conflictPresent
{
    my $self = shift;
    my(%args) = @_;

    if ( defined($self->{'conflictPresent'}) and $self->{'conflictPresent'} )
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

### getList( )
#
# Return a reference to an array that contains all of the files in the
# current filelist
#

sub getList
{
    my $self = shift;
    my(%args) = @_;

    my $file;
    my $list = [];

    for my $path (keys %{$self->{'filePaths'}})
    {
        if ( ! defined( $self->{'filePaths'}->{$path} ) )
        {
            next;
        }

        my $list = $self->{'filePaths'}->{$path};

        for my $file (@$list)
        {
            if ( defined($file) and defined($file) )
            {
                die("ERROR: file object is undefined in GPTFilelist");
            }

            if ( $file->isActive() )
            {
                push(@$list, $file);
            }
        }
    }

    return $list;
}

sub isEmpty
{
    my $self = shift;

    #
    # pull our filelist array into our scope
    #

    my $filelist = $self->getList();

    if ( scalar(@$filelist) eq 0 )
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

### getPackageConflicts( node => $node )
#
# Based on a package node, compare its PackageFilelist object with our internal filelist
# to see if there are any file conflicts.  If there are, create a conflict array that contains
# the files in our filelist that conflict with the package node's.
#

sub getPackageConflicts
{
    my $self = shift;
    my(%args) = @_;

    my $node = $args{'node'};

    if ( !defined($node) )
    {
        die("ERROR: node object must be defined in getPackageConflicts");
    }

    my $nodeFilelist = $node->filelist()->getFilelistObjects();
    my $conflictList = [];

    for my $nodeFile (@$nodeFilelist)
    {
        my $nodeFilePath = $nodeFile->getPath();

        if ( grep(/^$nodeFilePath$/, @{$self->getFilePathsList()}) )
        {
            push(@$conflictList, $self->getFileObject(path => $nodeFilePath));
        }
    }

    return $conflictList;
}

### getFilePathsList( )
#
# Return a reference to our internal array of known file paths
#

sub getFilePathsList
{
    my $self = shift;

    $self->verifyStructure();

    return $self->{'filePathsList'};
}

### getFileObject( path => $path )
#
# Return the first file object in our internal listing for a given path, or an undefined
# reference if the path doen't exist in our hash.
#

sub getFileObject
{
    my $self = shift;
    my(%args) = @_;

    my $path = $args{'path'};

    if ( !defined($self->{'filePaths'}) or !defined($self->{'filePaths'}->{$path}) )
    {
        return undef;
    }

    return $self->{'filePaths'}->{$path}->[0];
}

### translatePathToPkgNode( path => $path )
#
# Given a path, return the package node associated with that file object in our internal
# listing.
#

sub translatePathToPkgNode
{
    my $self = shift;
    my(%args) = @_;

    my $path = $args{'path'};

    $path =~ s:/+:/:g;
    $path =~ s:^/::g;

    my $file = $self->getFileObject( path => $path );
    return $file->getPkgNode();
}

### removeFilePath( path => $path )
#
# Set the file object(s) matching $path in our internal filelist to unactive
#

sub removeFilePath
{
    my($self, %args) = @_;

    #
    # handle arguments
    #

    my $filePath = $args{'path'};

    $self->verifyStructure();

    #
    # if the filePath doesn't exist, we don't have anything to do.  return an error.
    #

    if ( ! defined($self->{'filePaths'}->{$filePath}) )
    {
        return -1;
    }

    #
    # for each file object we have under the given filePath, set them to unactive
    #

    for my $f (@{$self->{'filePaths'}->{$filePath}})
    {
        $f->active(0);
    }

    return 1;
}

### cleanupList( )
#
# Remove references in our master filelist to deactivated file objects.
#

sub cleanupList
{
    my $self = shift;

    #
    # This subroutine needs to be filled out.  I foresee that upon removing a file, we add
    # descriptors to an array, which, upon triage-time, we can parse to delete any references
    # to the file object itself.
    #
}

1; # Ensure that the module can be successfully use'd

__END__

=head1 NAME

Grid::GPT::GPTFilelist - Perl extension for storing a master filelist

=head1 SYNOPSIS

  use Grid::GPT::GPTFilelist;
  my $masterFilelist = new Grid::GPT::GPTFilelist( );

  #
  # To compare the filelist contained within a node and those files already
  # in the master filelist...
  #

  my $conflictList = $masterFilelist->getPackageConflicts( node => $node );

  #
  # Given a path, the GPTFilelist object can translate it into the package node
  # that currently 'owns' that path.  Selection of which package owns any path
  # is FCFS, so get 'em while they're hot!
  #

  my $path = $masterFilelist->translatePathToPkgNode( path => $path );

  #
  # Given any path in a master filelist's domain, remove all file objects that
  # state that as their path.  ("remove" here only deactivates.  The real removing
  # happens when a cleanup of the filelist internals occurs.)
  #

  $masterFilelist->removeFilePath( path => $path );

  #
  # To add a file to the master filelist call the following method.  This method
  # is generally only called from within each of the PackageFilelist objects'
  # internals.
  #

  $masterFilelist->addFile( file => $file );

=head1 DESCRIPTION

I<Grid::GPT::GPTFilelist> is intended for use as a master filelist object.  It is
used mainly within the PkgSet object to track and manipulate all of the file objects
which have been read in for a given installation.  Only general functionality is
offered, yet, because of the high number of file objects for any given installation,
optimization occurs by cataloging the file objects when they are added to the
filelist.  This means a cleanup phase must occur to remove stale file references
after removeFilePath() has been called for any given path.

=head1 AUTHOR

Chase Phillips <cphillip@ncsa.uiuc.edu>

=head1 SEE ALSO

perl(1) Grid::GPT::PackageFilelist(1) Grid::GPT::PackageFile(1)

=cut
