use IO::File;

my $type = 0;
my $package = undef;

while(<>)
{
    next if(/^#[^#]/);
    if(/^##[^#]/ && $type)
    {
        # documentation
    }
    if(/^##[^#]/)
    {
	chomp;
	($type, $typedoc) = (split(/\s+/, $_, 3))[1,2] ;
	$type =~ s/globus_gram_protocol_//;
	$type =~ s/_t$//;
	$newtype="";
	$basetype=uc($type . '_');

	foreach (split(/_/, $type))
	{
	    $newtype .= ucfirst;
	}
	if($package)
	{
	    $package->print("1;\n");
	    $package->close();
	}
	$package = new IO::File(">$newtype.pm");

	if($newtype eq "Error")
	{
	    $package->print("package Globus::GRAM::$newtype;\n

			    sub new
			    {
				my \$proto = shift;
				my \$class = ref(\$proto) || \$proto;
				my \$self = {};
				my \$value = shift;
				my \$string = shift;

				\$self->{value} = \$value if defined(\$value);
				\$self->{string} = \$string if defined(\$string);
				bless \$self, \$class;

				return \$self;
			    }
			    sub string
			    {
				my \$self = shift;

				return \$self->{string};
			    }
			    sub value
			    {
				my \$self = shift;

				return \$self->{value};
			    }\n");
	}
	else
	{
	    $package->print("package Globus::GRAM::$newtype;\n\n");
	}

	next;
    }
    if(/^###\s*(.*)/)
    {
	next;
    }
    if(/=/)
    {
	chomp;
	my @pair = split(/=/);
	$pair[0] =~ s/GLOBUS_GRAM_PROTOCOL_//;
	$pair[0] =~ s/$basetype//;
	if($basetype eq 'ERROR_')
	{
	    $package->print("sub $pair[0]
	                    {
			        return new Globus::GRAM::Error($pair[1]);
			    }\n\n");
	}
	else
	{
	    $package->print("sub $pair[0]\n{\n    return $pair[1];\n}\n\n");
	}
    }
}
$package->print("1;\n");
$package->close();
