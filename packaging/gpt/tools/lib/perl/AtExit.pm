##############################################################################
# AtExit.pm -- a Perl5 module to provide C-style atexit() processing
#
# Copyright (c) 1996 Andrew Langmead. All rights reserved.
# This file is part of "AtExit". AtExit is free software;
# you can redistribute it and/or modify it under the same
# terms as Perl itself.
##############################################################################

package AtExit;

require 5.002;

$VERSION = 2.01;

use vars qw( $VERSION
             @ISA
             @EXPORT
             @EXPORT_OK
             @EXIT_SUBS
             $EXITING
             $IGNORE_WHEN_EXITING
           );

use strict;
#use diagnostics;
use Exporter;

@ISA    = qw( Exporter );
@EXPORT = qw( atexit rmexit );
@EXPORT_OK = qw( atexit rmexit exit_subs is_exiting ignore_when_exiting );

## Class/Package-level exit attrs
my %EXIT_ATTRS = (
    'EXIT_SUBS' => [],
    'EXITING'   => 0,
    'IGNORE_WHEN_EXITING' => 1
);

## Aliases to the above for @EXIT_SUBS and $EXITING
## (for backward compatibility)
*EXIT_SUBS = $EXIT_ATTRS{EXIT_SUBS};
*EXITING   = \$EXIT_ATTRS{EXITING};
*IGNORE_WHEN_EXITING = \$EXIT_ATTRS{IGNORE_WHEN_EXITING};

sub new {
    ## Determine if we were called via an object-ref or a classname
    my $this = shift;
    my $class = ref($this) || $this;

    ## Bless ourselves into the desired class and perform any initialization
    my $self = {
                 'EXIT_SUBS' => [],
                 'EXITING'   => 0,
                 'IGNORE_WHEN_EXITING' => 1
               };
    bless $self, $class;
    $self->atexit(@_)  if @_;
    return $self;
}

sub exit_subs {
    ## If called as an object, get the object-ref
    my $self = (@_  and  ref $_[0]) ? shift : \%EXIT_ATTRS;

    return  $self->{EXIT_SUBS};
}

sub is_exiting {
    ## If called as an object, get the object-ref
    my $self = (@_  and  ref $_[0]) ? shift : \%EXIT_ATTRS;

    return  $self->{EXITING};
}

sub ignore_when_exiting {
    ## If called as an object, get the object-ref
    my $self = (@_  and  ref $_[0]) ? shift : \%EXIT_ATTRS;

    ## Discard the class-name if its the first arg
    unless ($self  or  @_ == 0) {
       local  $_  = $_[0];
       shift  if (defined $_  and  $_  and  /[A-Za-z_]/);
    }

    $self->{IGNORE_WHEN_EXITING} = shift  if @_;
    return  $self->{IGNORE_WHEN_EXITING};
}

sub atexit {
    ## If called as an object, get the object-ref
    local $_ = ref $_[0];
    my $self = ($_ and $_ ne 'CODE') ? shift : \%EXIT_ATTRS;

    ## Get the remaining arguments
    my ($exit_sub, @args) = @_;

    return  0  if ($self->{EXITING}  and  $self->{IGNORE_WHEN_EXITING});

    unless (ref $exit_sub) {
       ## Caller gave us a sub name instead of a sub reference.
       ## Need to make sure we have the callers package prefix
       ## prepended if one wasn't given.
       my $pkg = '';
       $pkg = (caller)[0] . "::"  unless $exit_sub =~ /::/o;

       ## Now turn the sub name into a hard sub reference.
       $exit_sub = eval "\\&$pkg$exit_sub";
       undef $exit_sub  if ($@);
    }
    return  0  unless (defined $exit_sub) && (ref($exit_sub) eq 'CODE');

    ## If arguments were given, wrap the invocation up in a closure
    my $subref = (@args > 0) ? sub { &$exit_sub(@args); } : $exit_sub;

    ## Now put this sub-ref on the queue and return what we just registered
    unshift(@{ $self->{EXIT_SUBS} }, $subref);
    return  $subref;
}

sub rmexit {
    ## If called as an object, get the object-ref
    local $_ = ref $_[0];
    my $self = ($_ and $_ ne 'CODE') ? shift : \%EXIT_ATTRS;

    ## Get remaining arguments
    my @subrefs = @_;

    ## Unregister each sub in the given list.
    ##   [ I suppose I could come up with a faster way to do this than
    ##     doing a separate iteration for each argument, but I wont
    ##     worry about that just yet. ]
    ##
    my ($unregistered, $i) = (0, 0);
    my $exit_subs = $self->{EXIT_SUBS};
    if (@subrefs == 0) {
        ## Remove *all* exit-handlers
        $unregistered = scalar(@$exit_subs);
        $exit_subs = $self->{EXIT_SUBS} = [];
    }
    else {
        my $subref;
        foreach $subref (@subrefs) {
            next unless (ref($subref) eq 'CODE');
            ## Iterate over the queue and remove the first match
            for ($i = 0; $i < @$exit_subs; ++$i) {
                if ($subref == $exit_subs->[$i]) {
                    splice(@$exit_subs, $i, 1);
                    ++$unregistered;
                    last;
                }
            }
        }
    }
    return  $unregistered;
}

sub do_atexit {
    ## If called as an object, get the object-ref
    my $self = (@_  and  ref $_[0]) ? shift : \%EXIT_ATTRS;

    $self->{EXITING} = 1;

    ## Handle atexit() stuff in reverse order of registration
    my $exit_subs = $self->{EXIT_SUBS};
    my $subref;
    while (defined($exit_subs)  and  @$exit_subs > 0) {
        $subref = shift @$exit_subs;
        &$subref();
    }

    $self->{EXITING} = 0;
}

sub DESTROY {
    my $self = shift;
    $self->do_atexit();
    return undef;
}

END {
    do_atexit();
}

1;

__END__

=head1 NAME

B<atexit>, B<AtExit> -- perform exit processing for a program or object

=head1 SYNOPSIS

 use AtExit;

 sub cleanup {
     my @args = @_;
     print "cleanup() executing: args = @args\n";
 }
 
 ## Register subroutines to be called when this program exits

 $_ = atexit(\&cleanup, "This call was registered first");
 print "first call to atexit() returned $_\n";

 $_ = atexit("cleanup", "This call was registered second");
 print "second call to atexit() returned $_\n";

 $_ = atexit("cleanup", "This call should've been unregistered by rmexit");
 rmexit($_)  or  warn "couldnt' unregister exit-sub $_!";

 if (@ARGV == 0) {
    ## Register subroutines to be called when this lexical scope is exited
    my $scope1 = AtExit->new( \&cleanup, "Scope 1, Callback 1" );
    {
       ## Do the same for this nested scope
       my $scope2 = AtExit->new;
       $_ = $scope2->atexit( \&cleanup, "Scope 2, Callback 1" );
       $scope1->atexit( \&cleanup, "Scope 1, Callback 2");
       $scope2->atexit( \&cleanup, "Scope 2, Callback 2" );
       $scope2->rmexit($_) or warn "couldn't unregister exit-sub $_!";

       print "*** Leaving Scope 2 ***\n";
     }
     print "*** Finished Scope 2 ***\n";
     print "*** Leaving Scope 1 ***\n";
 }
 print "*** Finished Scope 1 ***\n"  if (@ARGV == 0);

 END {
     print "*** Now performing program-exit processing ***\n";
 }

=head1 DESCRIPTION

The B<AtExit> module provides ANSI-C style exit processing modeled after
the C<atexit> function in the standard C library (see L<atexit(3C)>).
Various exit processing routines may be registered by calling
B<atexit> and passing it the desired subroutine along with any
desired arguments. Then, at program-exit time, the subroutines registered
with B<atexit> are invoked with their given arguments in the
I<reverse> order of registration (last one registered is invoked first).
Registering the same subroutine more than once will cause that subroutine
to be invoked once for each registration.

An B<AtExit> object can be created in any scope. When invoked as a
function, B<atexit> registers callbacks to be
executed at I<program-exit> time. But when invoked as an object-method
(using the C<$object-E<gt>method_name> syntax),
callbacks registered with an B<AtExit> object are executed at
I<object-destruction time>! The rules for order of execution of the
registered subroutines are the same for objects during
object-destruction, as for the program during program-termination.

The B<atexit> function/method should be passed a subroutine name or
reference, optionally followed by the list of arguments with which to
invoke it at program/object exit time.  Anonymous subroutine references
passed to B<atexit> act as "closures" (which are described in
L<perlref>).  If a subroutine I<name> is specified (as opposed to a
subroutine reference) then, unless the subroutine name has an explicit
package prefix, it is assumed to be the name of a subroutine in the
caller's current package.  A reference to the specified subroutine is
obtained, and, if invocation arguments were specified, it is "wrapped
up" in a closure which invokes the subroutine with the specified
arguments.  The resulting subroutine reference is added to the front of
the list of exit-handling subroutines for the program (C<atexit>) or
the B<AtExit> object (C<$exitObject-E<gt>atexit>) and the reference is
then returned to the caller (just in case you might want to unregister
it later using B<rmexit>. If the given subroutine could I<not> be
registered, then the value zero is returned.

The B<rmexit> function/method should be passed one or more subroutine
references, each of which was returned by a previous call to
B<atexit>. For each argument given, B<rmexit> will look in the list
of exit-handling subroutines for the program (B<rmexit>) or the
B<AtExit> object (C<$exitObject-E<gt>rmexit>) and remove the first
matching entry from the list. If no arguments are given,
I<then all program or object exit-handlers are unregistered!>
The value returned will be the number of subroutines that were
successfully unregistered.

At object destruction time, the C<DESTROY{}> subroutine in the
B<AtExit> module iterates over the subroutine references in the
B<AtExit> object and invokes each one in turn (each subroutine is
removed from the front of the queue immediately before it is invoked).
At program-exit time, the C<END{}> block in the B<AtExit> module
iterates over the subroutines in the array returned by the
B<exit_subs> method and invokes each one in turn (each subroutine is
removed from the front of the queue immediately before it is invoked).
Note that in both cases (program-exit, and object-destruction) the
subroutines in this queue are invoked in first-to-last order (the
I<reverse> order in which they were registered with B<atexit>).

=head2 Adding and removing callbacks during exit/destruction time.

The method B<ignore_when_exiting> specifies how exit-callback
registration and unregistration will be handled during program-exit
or object-destruction time, while exit-callbacks are in process
of being invoked.

When invoked as a class method (e.g., C<AtExit-E<gt>ignore_when_exiting>),
B<ignore_when_exiting> corresponds to the handling of calls to
B<atexit> and B<rmexit> during program-termination. But when invoked as
an I<object> method (e.g., C<$exitObject-E<gt>ignore_when_exiting>), then
B<ignore_when_exiting> corresponds to the handling of calls to
B<atexit> and B<rmexit> during I<object-destruction> for the particular
object.

By default, B<ignore_when_exiting> returns a non-zero value, which
causes B<atexit> to I<ignore> any calls made to it during this time
(a value of zero will be returned). This behavior is consistent with
that of the standard C library function of the same name. If desired
however, the user may enable the registration of subroutines by
B<atexit> during this time by invoking B<ignore_when_exiting> and
passing it an argument of 0, C<"">, or C<undef> (for example,
C<AtExit-E<gt>ignore_when_exiting(0)> or
C<$exitObject-E<gt>ignore_when_exiting(0)>,
Just remember that any subroutines registered with B<atexit> be
placed at the I<front> of the queue of yet-to-be-invoked
exit-processing subroutines for the program (B<atexit>) or the
B<AtExit> object (C<$exitObject-E<gt>atexit>).

Regardless of when it is invoked, B<rmexit> will I<always> attempt to
unregister the given subroutines (even when called during
program/object exit processing).  Keep in mind however that if it is
invoked during program/object exit then it will I<fail> to unregister
any subroutines that have I<already been invoked> (since those
subroutine calls have already been removed from the corresponding list
of exit-handling subroutines).

The method B<is_exiting> may consulted examined to determine if
routines registered using B<atexit> are currently in the process of
being invoked. It will be non-zero if they are and zero otherwise. When
invoked as a class method (e.g., C<AtExit-E<gt>is_exiting>), the return
value will correspond to program-exit processing; but when invoked as
an I<object> method (e.g., C<$exitObject-E<gt>is_exiting>) the return
value will correspond to object-destruction processing for the given
object.

If, for any reason, the list of registered callback needs to be directly
accessed or manipulated, the B<exit_subs> function will return a reference
to the list of program-exit callbacks. When invoked as a method, B<exit_subs>
will return a reference to the list of object-destruction callbacks for the
corresponding object.

=head1 EXPORTS

For backward compatibility, B<atexit> and B<rmexit> are exported
by default. I<Note> however that B<exit_subs>, B<is_exiting>, and
B<ignore_when_exiting> are I<not> exported by default, and should
be invoked as class methods (e.g. C<AtExit-E<gt>is_exiting>) if
they are to manipulate program-exit information (rather than
object-destruction) and not explicitly imported.

=head1 CAVEATS

=head1 Program-termination and Object-destruction

The usual Perl way of doing program/module-exit processing is through
the use of C<END{}> blocks
(see L<perlmod/"Package Constructors and Destructors">).
The B<AtExit> module implements its program-exit processing with with
an C<END{}> block that invokes all the subroutines registered by
B<atexit> in the array whose referenced is returned by C<exit_subs>.

For an object, object-destruction processing is implemented by having the
C<DESTROY> method for the object invoke all the subroutines registered
by C<$exitObject-E<gt>atexit>. This occurs when the object loses it's
last reference, which is not necessarily at program end time.

For objects defined in the global context, if any other C<END{}> block
processing is specified in the user's code or in any other packages it
uses, then the order in which the exit processing takes place is
subject to Perl's rules for the order in which objects loose their last
references and C<END{}> blocks are processed. This may affect when
subroutines registered with B<atexit> are invoked with respect to other
exit processing that is to be performed. In particular, if B<rmexit> is
invoked from within an C<END{}> block that executes I<after> the
B<AtExit> object was destroyed, then the corresponding subroutine will
not be registered and will never be invoked by the B<AtExit> module's
destructor code.

=head1 C<END{}> block processing order

C<END{}> blocks, including those in other packages, get called in the
reverse order in which they appear in the code. (B<atexit> subroutines
get called in the reverse order in which they are registered.) If a
package gets read via "use", it will act as if the C<END{}> block was
defined at that particular part of the "main" code.  Packages read via
"require" will be executed after the code of "main" has been parsed and
will be seen last so will execute first (they get executed in the
context of the package in which they exist).

It is important to note that C<END{}> blocks and object destruction
only get called on normal termination (which includes calls to B<die>
or B<Carp::croak>). They do I<not> get called when the program
terminates I<abnormally> (due to a signal for example) unless special
arrangements have been made by the programmer (e.g. using a signal
handler -- see L<perlvar/"%SIG{expr}">).

=head1 SEE ALSO

L<atexit(3C)> describes the B<atexit> function for the standard C
library (the actual Unix manual section in which it appears may differ
from platform to platform - try sections 3C, 3, 2C, and 2).  Further
information on anonymous subroutines ("closures") may be found in
L<perlref>.  For more information on C<END{}> blocks, see
L<perlmod/"Package Constructors and Destructors">.  See
L<perlvar/"%SIG{expr}"> for handling abnormal program termination.

=head1 AUTHOR

Andrew Langmead E<lt>aml@world.std.comE<gt> (initial draft).

Brad Appleton E<lt>bradapp@enteract.comE<gt> (Version 1.02 and 2.00).

Michael A. Chase E<lt>mchase@ix.netcom.comE<gt> (Version 2.00).

=cut
