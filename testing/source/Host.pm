
package Globus::Testing::Host;

use Globus::Testing::Gram;
use Carp;
use strict 'vars';
use vars qw/$AUTOLOAD/;

sub new 
{
   my $type=shift;
   my $self={
	     execution => [],
	     capabilities => [],
	     perl => undef,
	     jobmanagers => []
	    };
   return bless $self,$type;
}

sub match($$)
{
   my $self = shift;
   my $type = ref($self) || croak "$self is not an object";
   my $query = shift;

   if(intersect($self->execution(),$query->{"execution"}) &&
      (intersect($self->capabilities(),$query->{"capabilities"}) == 
       @{$query->{"capabilities"}}) &&
      (intersect($self->jobmanagers(),$query->{"jobmanagers"}) == 
       @{$query->{"jobmanagers"}}))
   {
      return 1;
   }
   return 0;
}

sub intersect
{
   my $i;
   my $j;
   my @matches;

   foreach $i (@{$_[0]})
   {
      foreach $j (@{$_[1]})
      {
	 $i eq $j && push(@matches, $j);
      }
   }
   return @matches;
}

sub AUTOLOAD 
{
   my $self = shift;
   my $type = ref($self) || croak "$self is not an object";
   my $name = $AUTOLOAD;
   $name =~ s/.*://;

   if(@_)
   {
      if(ref($self->{$name}) eq "ARRAY")
      {
	 return push(@{$self->{$name}},@_);
      }
      else
      {
	 return $self->{$name} = shift;
      }
   }
   else
   {
      return $self->{$name};
   }
}

sub print_obj
{
   my $self = shift;
   my $type = ref($self) || croak "$self is not an object";
   print "execution: @{$self->{execution}}\n";
   print "capabilities: @{$self->{capabilities}}\n";
   print "jobmanagers: @{$self->{jobmanagers}}\n";
   foreach (@{$self->{jobmanagers}})
   {
      print "Gram variables for jobmanager $_:\n\n";
      ($self->{$_})->print_obj;
   }
}



1;
