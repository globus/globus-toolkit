package Grid::GPT::MD5;

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

require Digest::MD5;

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

sub compare
{
    my $self = shift;
    my(%args) = @_;
    my( $ctx, $files );
    my( $cksum_curr, $cksum_last );

    $ctx = new Digest::MD5();
    $files = $args{'files'};

    for my $file (@$files)
    {
        $cksum_curr = $self->checksum(file => $file);
        if ( defined($cksum_last) && ( length($cksum_last) > 0 ) )
        {
            if ( $cksum_curr != $cksum_last )
            {
                return 0;
            }
        }
        $cksum_last = $cksum_curr;
    }

    return 1;
}

sub checksum
{
    my $self = shift;
    my(%args) = @_;
    my($ctx, $file);

    $ctx = new Digest::MD5();

    $file = $args{'file'};
    open(FILE, $file);
    binmode(FILE);

    $ctx->addfile(*FILE);
    return $ctx->hexdigest();
}

1; # Ensure that the module can be successfully use'd

__END__

=head1 NAME

Grid::GPT::MD5 - Perl extension for computing MD5 checksums.

=head1 SYNOPSIS

  use Grid::GPT::MD5;
  my $md5 = new Grid::GPT::MD5();

  #
  # returns the MD5 checksum of the file associated with given path
  #

  my $checksum = $md5->checksum( file => $file );

=head1 DESCRIPTION

I<Grid::GPT::MD5> is a wrapper class around the MD5 mechanism chosen
for release with GPT.  In case there is some issue with this mechanism,
or it needs to be replaced, all calls into it happen here first, and
allow us (the GPT developers) greater control over the backend MD5
functionality.

=head1 AUTHOR

Chase Phillips <cphillip@ncsa.uiuc.edu>

=head1 SEE ALSO

perl(1) Grid::GPT::PackageFile(1) Digest::MD5(1)

=cut
