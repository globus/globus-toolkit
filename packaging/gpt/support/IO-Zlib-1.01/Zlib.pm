# IO::Zlib.pm
#
# Copyright (c) 1998-2001 Tom Hughes <tom@compton.nu>.
# All rights reserved. This program is free software; you can redistribute
# it and/or modify it under the same terms as Perl itself.

package IO::Zlib;

=head1 NAME

IO::Zlib - IO:: style interface to L<Compress::Zlib>

=head1 SYNOPSIS

With any version of Perl 5 you can use the basic OO interface:

    use IO::Zlib;

    $fh = new IO::Zlib;
    if ($fh->open("file.gz", "rb")) {
        print <$fh>;
        $fh->close;
    }

    $fh = IO::Zlib->new("file.gz", "wb9");
    if (defined $fh) {
        print $fh "bar\n";
        $fh->close;
    }

    $fh = IO::Zlib->new("file.gz", "rb");
    if (defined $fh) {
        print <$fh>;
        undef $fh;       # automatically closes the file
    }

With Perl 5.004 you can also use the TIEHANDLE interface to access
compressed files just like ordinary files:

    use IO::Zlib;

    tie *FILE, 'IO::Zlib', "file.gz", "wb";
    print FILE "line 1\nline2\n";

    tie *FILE, 'IO::Zlib', "file.gz", "rb";
    while (<FILE>) { print "LINE: ", $_ };

=head1 DESCRIPTION

C<IO::Zlib> provides an IO:: style interface to L<Compress::Zlib> and
hence to gzip/zlib compressed files. It provides many of the same methods
as the L<IO::Handle> interface.

=head1 CONSTRUCTOR

=over 4

=item new ( [ARGS] )

Creates an C<IO::Zlib> object. If it receives any parameters, they are
passed to the method C<open>; if the open fails, the object is destroyed.
Otherwise, it is returned to the caller.

=back

=head1 METHODS

=over 4

=item open ( FILENAME, MODE )

C<open> takes two arguments. The first is the name of the file to open
and the second is the open mode. The mode can be anything acceptable to
L<Compress::Zlib> and by extension anything acceptable to I<zlib> (that
basically means POSIX fopen() style mode strings plus an optional number
to indicate the compression level).

=item opened

Returns true if the object currently refers to a opened file.

=item close

Close the file associated with the object and disassociate
the file from the handle.
Done automatically on destroy.

=item getc

Return the next character from the file, or undef if none remain.

=item getline

Return the next line from the file, or undef on end of string.
Can safely be called in an array context.
Currently ignores $/ ($INPUT_RECORD_SEPARATOR or $RS when L<English>
is in use) and treats lines as delimited by "\n".

=item getlines

Get all remaining lines from the file.
It will croak() if accidentally called in a scalar context.

=item print ( ARGS... )

Print ARGS to the  file.

=item read ( BUF, NBYTES, [OFFSET] )

Read some bytes from the file.
Returns the number of bytes actually read, 0 on end-of-file, undef on error.

=item eof

Returns true if the handle is currently positioned at end of file?

=item seek ( OFFSET, WHENCE )

Seek to a given position in the stream.
Not yet supported.

=item tell

Return the current position in the stream, as a numeric offset.
Not yet supported.

=item setpos ( POS )

Set the current position, using the opaque value returned by C<getpos()>.
Not yet supported.

=item getpos ( POS )

Return the current position in the string, as an opaque object.
Not yet supported.

=back

=head1 SEE ALSO

L<perlfunc>,
L<perlop/"I/O Operators">,
L<IO::Handle>,
L<Compress::Zlib>

=head1 HISTORY

Created by Tom Hughes E<lt>F<tom@compton.nu>E<gt>.

=head1 COPYRIGHT

Copyright (c) 1998-2001 Tom Hughes E<lt>F<tom@compton.nu>E<gt>.
All rights reserved. This program is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.

=cut

require 5.004;

use strict;
use vars qw($VERSION $AUTOLOAD @ISA);

use Carp;
use Compress::Zlib;
use Symbol;
use Tie::Handle;

$VERSION = "1.01";

@ISA = qw(Tie::Handle);

sub TIEHANDLE
{
    my $class = shift;
    my @args = @_;

    my $self = bless {}, $class;

    return @args ? $self->OPEN(@args) : $self;
}

sub DESTROY
{
}

sub OPEN
{
    my $self = shift;
    my $filename = shift;
    my $mode = shift;

    croak "open() needs a filename" unless defined($filename);

    $self->{'file'} = gzopen($filename,$mode);
    $self->{'eof'} = 0;

    return defined($self->{'file'}) ? $self : undef;
}

sub CLOSE
{
    my $self = shift;

    return undef unless defined($self->{'file'});

    my $status = $self->{'file'}->gzclose();

    delete $self->{'file'};
    delete $self->{'eof'};

    return ($status == 0) ? 1 : undef;
}

sub READ
{
    my $self = shift;
    my $bufref = \$_[0];
    my $nbytes = $_[1];
    my $offset = $_[2];

    croak "NBYTES must be specified" unless defined($nbytes);
    croak "OFFSET not supported" if defined($offset) && $offset != 0;

    return 0 if $self->{'eof'};

    my $bytesread = $self->{'file'}->gzread($$bufref,$nbytes);

    return undef if $bytesread < 0;

    $self->{'eof'} = 1 if $bytesread < $nbytes;

    return $bytesread;
}

sub READLINE
{
    my $self = shift;

    my $line;

    return () if $self->{'file'}->gzreadline($line) <= 0;

    return $line unless wantarray;

    my @lines = $line;

    while ($self->{'file'}->gzreadline($line) > 0)
    {
        push @lines, $line;
    }

    return @lines;
}

sub WRITE
{
    my $self = shift;
    my $buf = shift;
    my $length = shift;
    my $offset = shift;

    croak "bad LENGTH" unless $length <= length($buf);
    croak "OFFSET not supported" if defined($offset) && $offset != 0;

    return $self->{'file'}->gzwrite(substr($buf,0,$length));
}

sub EOF
{
    my $self = shift;

    return $self->{'eof'};
}

sub new
{
    my $class = shift;
    my @args = @_;

    my $self = gensym();

    tie *{$self}, $class, @args;

    return tied(${$self}) ? bless $self, $class : undef;
}

sub getline
{
    my $self = shift;

    return scalar tied(*{$self})->READLINE();
}

sub getlines
{
    my $self = shift;

    croak unless wantarray;

    return tied(*{$self})->READLINE();
}

sub opened
{
    my $self = shift;

    return defined tied(*{$self})->{'file'};
}

sub AUTOLOAD
{
    my $self = shift;

    $AUTOLOAD =~ s/.*:://;
    $AUTOLOAD =~ tr/a-z/A-Z/;

    return tied(*{$self})->$AUTOLOAD(@_);
}

1;
