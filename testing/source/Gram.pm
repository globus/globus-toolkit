
package Globus::Testing::Gram;

use Carp;
use strict 'vars';
use vars qw/$AUTOLOAD/;

sub new 
{
   my $type=shift;
   my $self={
	     contact => undef,
	     queue => undef,
	     project => undef,
	     maxtime => undef
	    };
   return bless $self,$type;
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
   foreach (keys(%{$self}))
   {
      print "\t$_: $self->{$_}\n";
   }
}


1;









