#
# Globus::GRAM::JobDescription
#
# CVS Information
#     $Source$
#     $Date$
#     $Revision$
#     $Author$

=head1 NAME

Globus::GRAM::JobDescription - GRAM Job Description

=head1 SYNOPSIS

    use Globus::GRAM::JobDescription;

    $hash = { executable => [ '/bin/echo' ], arguments => [ 'hello' ] };
    $description = new Globus::GRAM::JobDescription($filename);
    $description = new Globus::GRAM::JobDescription($hash);
    $executable = $description->executable();
    $description->add($new_attribute, $new_value);
    $description->save();
    $description->save($filename);
    $description->print_recursive($file_handle);

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

When the library_path RSL attribute is specified, this object modifies
the environment RSL attribute value to append its value to any system specific
variables.

=cut

sub new
{
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $desc = shift;
    my $self = {};

    if (defined ($desc))
    {
        if ( ref ( $desc ) eq "HASH" )
        {
            foreach my $Key ( keys %{$desc} )
            {
                $self->{$Key} = $desc->{$Key};
            }
        }
        else
        {
            my $desc_fn = $desc;
            $self = require "$desc_fn";
            $self->{_description_file} = $desc_fn;
        }
    }

    bless $self, $class;

    if ($self->expand_globus_home()) {
        my $home = (getpwuid($<))[7];
        foreach my $key (keys %{$self}) {
            if ($key =~ m/^[^_]/) {
                my $arrayref = $self->{$key};

                for ($i = 0; $i < scalar(@{$arrayref}); $i++) {
                    $arrayref->[$i] =~ s/\${GLOBUS_USER_HOME}/$home/g;
                }
            }
        }
    }
    
    if ($self->expand_globus_location()) {
        my $home = $ENV{GLOBUS_LOCATION};
        foreach my $key (keys %{$self}) {
            if ($key =~ m/^[^_]/) {
                my $arrayref = $self->{$key};

                for ($i = 0; $i < scalar(@{$arrayref}); $i++) {
                    $arrayref->[$i] =~ s/\${GLOBUS_LOCATION}/$home/g;
                }
            }
        }
    }      

    $self->fix_library_path_environment();

    return $self;
}

=item $description->I<add>('name', I<$value>);

Add a parameter to a job description. The parameter will be normalized
internally so that the access methods described below will work with
this new parameter. As an example,

    $description->add('new_attribute', $new_value)

will create a new attribute in the JobDescription, which can be accessed
by calling the I<$description->new_attribute>() method.

=cut

sub add
{
    my $self = shift;
    my $attr = shift;
    my $value = shift;

    $attr =~ s/_//g;
    $attr = lc($attr);

    if ( ref($value) eq 'ARRAY' ) {
        $self->{$attr} = $value;
    } else {
        $self->{$attr} = [ $value ];
    }
}

=item I<$value> $description->I<get>('name');

Get a parameter from a job description. As an example,

    $description->get('attribute')

will return the appropriate attribute in the JobDescription by name.

=cut

sub get
{
    my $self = shift;
    my $attr = shift;

    $attr =~ s/_//g;
    $attr = lc($attr);

    return $self->{$attr};
}

=item $description->I<save>([$filename])

Save the JobDescription, including any added parameters, to the file
named by $filename if present, or replacing the file used in constructing
the object.

=cut

sub save
{
    my $self = shift;
    my $filename = shift || "$self->{_description_file}.new";
    local(*OUT);	     	# protect

    if ( open( OUT, '>' . $filename ) ) 
    {
	print OUT '$description = {', "\n";
	foreach ( keys %{$self} ) 
	{
	    print OUT '   \'', $_, '\' => ';
	    $self->print_recursive( \*OUT, $self->{$_} );
	    print OUT ",\n";
	}

	print OUT "};\n";
	close(OUT);

    } else {
	# FIXME: what shall we do, if we cannot open the file?
    }

    if ( exists($self->{_description_file}) )
    {
        if ( $filename eq "$self->{_description_file}.new" )
        {
            rename("$self->{_description_file}.new",
                    $self->{_description_file});
        }
    }

    return 0;
}

=item $description->I<print_recursive>($file_handle)

Write the value of the job description object to the file handle
specified in the argument list.

=cut

sub print_recursive
{
    my $self = shift;
    my $fh = shift;			# with ..::File, \*FILE or *FILE{IO}
    my $value = shift;
    my $first = 1;

    if ( ref($value) eq 'SCALAR' )
    {
	print $fh $value;
    }
    elsif(ref($value) eq 'ARRAY')
    {
	print $fh '[ ';
	foreach (@{$value})
	{
	    print $fh ', ' if (!$first);
	    $first = 0;
	    $self->print_recursive($fh, $_);
	}
	print $fh ' ]';
    }
    elsif(ref($value) eq 'HASH')
    {
	print $fh '(';

	foreach (keys %{$value})
	{
	    print $fh ', ' if (!$first);
	    $first = 0;
	    print $fh "'$_' => ";
	    $self->print_recursive($fh, $value->{$_});
	}
    }
    elsif(!ref($value))
    {
        $value =~ s|'|\\'|g;
	print $fh "'$value'";
    }
    return;
}

=item $description->I<parameter>()

For any parameter defined in the JobDescription can be accessed by calling
the method named by the parameter. The method names are automatically created
when the JobDescription is created, and may be invoked with arbitrary
SillyCaps or underscores. That is, the parameter gram_myjob may be accessed
by the GramMyJob, grammyjob, or gram_my_job method names (and others).

If the attributes does not in this object, then undef will be returned.

In a list context, this returns the list of values associated
with an attribute.

In a scalar context, if the attribute's value consist of a single literal,
then that literal will be returned, otherwise undef will be returned.

For example, from a JobDescription called $d constructed from a
description file containing

    {
	executable => [ '/bin/echo' ],
	arguments  => [ 'hello', 'world' ]
    }

The following will hold:

    $executable = $d->executable()    # '/bin/echo'
    $arguments = $d->arguments()      # undef
    @executable = $d->executable()    # ('/bin/echo')
    @arguments = $d->arguments()      # ('hello', 'world')
    $not_present = $d->not_present()  # undef
    @not_present = $d->not_present()  # ()

To test for existence of a value:

    @not_present = $d->not_present()
    print "Not defined\n" if(!defined($not_present[0]));

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
	if(wantarray)
	{
	    return ();
	}
	else
	{
	    return undef;
	}
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

# Internal method to merge the library_path RSL attribute and any values in the
# environment RSL attribute which explicitly name system library path variables.
# The result will be modifications to the environment RSL attribute value
# with the library_path values appended to any existing system-specific library
# path settings in the original RSL. For example
# if we found 
# &(environment = (LD_LIBRARY_PATH foo))
#  (library_path = bar)
# in the RSL, and LD_LIBRARY_PATH was one of the system-specific library paths
# for this OS, we'll modify the RSL to be
# &(environment = (LD_LIBRARY_PATH foo:bar))
#  (library_path = bar)
# 
# The $library_map values are mostly based on
# http://www.fortran-2000.com/ArnaudRecipes/sharedlib.html
# and also LD_LIBRARY_PATH for some popular BSDs
sub fix_library_path_environment
{
    my $self = shift;
    my @environment = $self->environment();
    my $library_map = {
        'linux' => [ 'LD_LIBRARY_PATH'],
        'hpux' => [ 'SHLIB_PATH', 'LD_LIBRARY_PATH' ],
        'solaris' => [ 'LD_LIBRARY_PATH', 'LD_LIBRARY_PATH_64' ],
        'aix' => [ 'LIBPATH' ],
        'irix' => [ 'LD_LIBRARY_PATH', 'LD_LIBRARYN32_PATH', 'LD_LIBRARY64_PATH' ],
        'darwin' => [ 'DYLD_LIBRARY_PATH' ],
        'freebsd' => [ 'LD_LIBRARY_PATH' ],
        'openbsd' => [ 'LD_LIBRARY_PATH' ]
    };
    my $library_path = join(':', $self->library_path());

    # Only bother doing anything if the library_path RSL attribute is 
    # present, and we know something about how the OS finds dynamic libraries
    # $^O is The name of the operating system under which this copy of Perl
    # was built
    if ($library_path ne '' && exists($library_map->{$^O})) {
        foreach my $var (@{$library_map->{$^O}}) {
            # environment is an list of [ $name, $value ] pairs. This pulls
            # out the value that matches the current OS-specific envvar name
            my @libref = grep { $_->[0] eq $var } @environment;

            if (exists $libref[0])
            {
                # user specified both environment=($var ...) and
                # library_path=$library_path so we'll append $library_path
                # to the corresponding environment variable definition
                $libref[0]->[1] .= ":$library_path";
            }
            else
            {
                # user didn't specify both library_path and
                # environment=($var $library_path), so we just add it to the
                # environment
                push(@environment, [$var, $library_path]);
            }
        }
        # @environment is a list of references so modifications above will
        # modify the RSL; however, if we add new references (the else case
        # above), they won't be in the list in this object. 
        $self->add('environment', \@environment);
    }
}

1;

__END__

=back

=cut
