=head1 NAME

Globus::Testing::Timer - subsecond resolution timers

=head1 SYNOPSIS

 use Globus::Testing::Timer;

 $timer = new Globus::Testing::Timer();
 $timer->start();
 $timer->stop();
 $timer->print();

=head1 DESCRIPTION

The Globus::Testing::Timer module provides subsecond timers for use for timing
the performance of code. These measure the interval between a call to
the C<start> and C<stop> methods of a timer object. The timers do not
accumulate times from multiple calls to C<start> and C<stop>

=over 4

=cut

package Globus::Testing::Timer;

use Carp;
use strict 'vars';
use vars qw/$AUTOLOAD/;
require 'syscall.ph';

=item sub new()

Create a new timer object.

=cut
sub new($)
{
    my $type = shift;

    my $self={
	start => 0,
	stop => 0,
    };
    return bless $self,$type;
}

=item sub start

Start timing. The timer records the current wallclock time.

=cut
sub start($)
{
    my $self = shift;
    my $TIMEVAL_T = "LL";
    my $start = pack($TIMEVAL_T, ());
    my $sec = 0;
    my $usec = 0;

    syscall( &SYS_gettimeofday, $start, 0) != -1
	or die "gettimeofday: $!";

    ($sec, $usec) = unpack("LL", $start);

    $self->{'start'}=$sec+$usec/1e6;
    
    return;
}

=item sub stop

Stop timing. The timer records the current wallclock time.

=cut
sub stop($)
{
    my $self = shift;
    my $TIMEVAL_T = "LL";
    my $stop = pack($TIMEVAL_T, ());
    my $sec = 0;
    my $usec = 0;
    
    syscall( &SYS_gettimeofday, $stop, 0) != -1
	or die "gettimeofday: $!";

    ($sec, $usec) = unpack("LL", $stop);

    $self->{'stop'}=$sec+$usec/1e6;
    
    return ($self->{'stop'} - $self->{'start'}); 
}

=item sub print

Print accumulated time. This time is equal to the difference between the
starting and stopping times.

=cut
sub print($)
{
    my $self = shift;
    print $self->{'stop'};
    print "\n";
    print $self->{'start'};
    print "\n";
    print ($self->{'stop'} - $self->{'start'}); 
    print "\n";
}
