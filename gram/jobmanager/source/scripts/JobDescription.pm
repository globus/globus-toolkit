#
# Globus::GRAM::JobDescription
#
# CVS Information
#     $Source$
#     $Date$
#     $Revision$
#     $Author$

use IO::File;
use Globus::GRAM::Error;

=head1 NAME

Globus::GRAM::JobDescription - GRAM Job Description

=head1 SYNOPSIS

    use Globus::GRAM::JobDescription;

    $description = new Globus::GRAM::JobDescription($filename);
    $executable = $description->executable();
    $description->add('jobid', $job_id);
    $description->save();

=head1 DESCRIPTION

This object contains the parameters of a job request in a simple
object wrapper. The object may be queried to determine the value of
any RSL parameter, may be updated with new parameters, and may be saved
in the filesystem for later use.

=head2 Methods

=over 4

=cut

package Globus::GRAM::JobDescription;

=item new Globus::GRAM::JobDescription(I<$filename>)

A JobDescription is constructed from a 
file consisting of a Perl hash of parameter => array mappings. Every
value in the Job Description is stored internally as an array, even single
literals, similar to the way an RSL tree is parsed in C. An example of such
a file is

    $description =
    {
	executable  => [ '/bin/echo' ], 
	arguments   => [ 'hello', 'world' ],
	environment => [
	                   [
			       'GLOBUS_GRAM_JOB_CONTACT',
			       'https://globus.org:1234/2345/4332'
			   ]
		       ]
    };

which corresponds to the rsl fragment

    &(executable  = /bin/echo)
     (arguments   = hello world)
     (environment =
         (GLOBUS_GRAM_JOB_CONTACT 'https://globus.org:1234/2345/4332')
     )

=cut

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

=item $description->I<add>('name', I<$value [, $value]>);

Add a parameter to a job description. The parameter will be normalized
internally so that the access methods described below will work with
this new parameter. As an example,

    @description->add('job_id', $jobid)

will create a new paremeter in the JobDescription, which can be accessed
by calling the I<$description->job_id>() method.

=cut

sub add
{
    my $self = shift;
    my $attr = shift;
    my $value = shift;

    $attr =~ s/_//g;
    $attr = lc($attr);

    $self->{$attr} = [$value];
}

=item $description->I<save>()

Save the JobDescription, including any added parameters, to the file
passed to the constructor.

=cut

sub save
{
    my $self = shift;
    my $filename = shift or "$self->{_description_file}.new";
    my $file = new IO::File(">$filename");

    $file->print("\$description = {\n");

    foreach (keys %{$self})
    {
	$file->print("    '$_' => ");
	
	$self->print_recursive($file, $self->{$_});
	$file->print(",\n");
    }
    $file->print("};\n");
    $file->close();

    if($filename eq "$self->{_description_file}.new")
    {
	rename("$self->{_description_file}.new", $self->{_description_file});
    }

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

=item $description->I<parameter>()

For any parameter defined in the JobDescription can be accessed by calling
the method named by the parameter. The method names are automatically created
when the JobDescription is created, and may be invoked with arbitrary
SillyCaps or underscores. That is, the parameter gram_myjob may be accessed
by the GramMyJob, grammyjob, or gram_my_job method names (and others). In
contrast to the description of how JobDescription objects are constructed
above, the return from a parameter method will be a scalar value if only
one value exists in the array. For example, using the description of
executable in the previous section, the method call

    $description->executable()

would return the scalar '/bin/echo', and not the array [ '/bin/echo' ].

Also, arrays will be cast to lists in their return, so the method call

    $description->arguments()

would return the list ( 'hello', 'world' ) and not the array
[ 'hello', 'world' ].

An undefined or empty parameter invocation will return I<undef>.

=cut

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
    if(wantarray)
    {
	# Return a list containing the contents of the value array for
	# this attribute.
	# This makes things like $description->environment() act as expected.
	return @{$self->{$name}};
    }
    elsif(scalar(@{$self->{$name}}) == 1 && !ref($self->{$name}[0]))
    {
	# If there is only a single value in the value array for this
	# attribute, return that value
	# This makes things like $description->directory() act as expected.
	return @{$self->{$name}}[0];
    }
    else
    {
	return undef;
    }
}
1;

__END__

=back

=cut
