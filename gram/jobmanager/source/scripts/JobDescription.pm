# This package provides an implementation of the JobDescription interface
# using a simple perl-syntax job description file. This object could
# be replaced with another implementation using RSL or XML job descriptions
# without upsetting the job manager script implementations.

use IO::File;
use Globus::GRAM::Error;

package Globus::GRAM::JobDescription;

sub new
{
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $desc_fn = shift;
    my $desc_values;
    my $self;

    $self = require "$desc_fn";
    $self->{_description_file} = $desc_fn;

    bless $self, $class;

    return $self;
}

sub add
{
    my $self = shift;
    my $attr = shift;
    my $value = shift;

    $attr =~ s/_//g;
    $attr = lc($attr);

    $self->{$attr} = [$value];
}

sub save
{
    my $self = shift;
    my $file = new IO::File(">$self->{_description_file}.new");

    $file->print("\$description = {\n");

    foreach (keys %{$self})
    {
	$file->print("    '$_' => ");
	
	$self->print_recursive($file, $self->{$_});
	$file->print(",\n");
    }
    $file->print("};\n");
    $file->close();

    rename("$self->{_description_file}.new", $self->{_description_file});

    return 0;
}

sub print_recursive
{
    my $self = shift;
    my $file = shift;
    my $value = shift;
    my $first = 1;

    if(ref($value) eq "SCALAR")
    {
	$file->print($value);
    }
    elsif(ref($value) eq "ARRAY")
    {
	$file->print("[ ");
	foreach (@{$value})
	{
	    $file->print(", ") if (!$first);
	    $first = 0;
	    $self->print_recursive($file, $_);
	}
	$file->print(" ]");
    }
    elsif(ref($value) eq "HASH")
    {
	$file->print("(");

	foreach (keys %{$value})
	{
	    $file->print(", ") if (!$first);
	    $first = 0;
	    $file->print("'$_' => ");
	    $self->print_recursive($file, $value->{$_});
	}
    }
    elsif(!ref($value))
    {
	$file->print("'$value'");
    }
    return;
}

sub AUTOLOAD
{
    use vars qw($AUTOLOAD);
    my $self = shift;
    my $name = $AUTOLOAD;
    $name =~ s/.*://;

    $name =~ s/_//g;
    $name = lc($name);


    if((! ref($self)) ||(! exists($self->{$name})))
    {
	return undef;
    }
    if(scalar(@{$self->{$name}} == 1))
    {
	# If there is only a single value in the value array for this
	# attribute, return that value
	# This makes things like $description->directory() act as expected.
	return @{$self->{$name}}[0];
    }
    else
    {
	# Return a list containing the contents of the value array for
	# this attribute.
	# This makes things like $description->environment() act as expected.
	return @{$self->{$name}};
    }
}

1;
