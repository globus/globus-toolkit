package Globus::GRAM::StdioMerger;

use strict;
use Globus::Core::Paths;
use File::Copy;

sub SEEK_SET {0;} # ugly non-portable hack to avoid "use Fcntl"

sub new
{
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $dir = shift;
    my $stdout = shift;
    my $stderr = shift;
    my $self  = {};

    $self->{STDOUT_FILES} = [];
    $self->{STDERR_FILES} = [];
    $self->{STDOUT} = $stdout;
    $self->{STDERR} = $stderr;
    $self->{DIR} = $dir;

    $self->{MERGE_FILENAME} = "$dir/stdio_merge_metadata";

    bless $self, $class;

    if( -s $self->{MERGE_FILENAME})
    {
	$self->load_state();
    }

    return $self;
}

sub add_file
{
    my $self = shift;
    my $type = shift;
    my $array;
    my $index;
    my $format = "\%s/std\%s\%03d";
    my $new_name;

    if($type eq 'out')
    {
	$array = $self->{STDOUT_FILES};
    }
    else
    {
	$array = $self->{STDERR_FILES};
    }
    $index = scalar(@{$array});

    $new_name = sprintf($format, $self->{DIR}, $type, $index);

    if($new_name eq '')
    {
	return undef;
    }

    push(@{$array}, [ "$type", $new_name, 0 ]);

    $self->store_state();

    return $new_name;
}

sub poll
{
    my $self = shift;
    my $final = shift;

    local(*FH);
    open(FH, '>>' . $self->{STDERR});

    $self->poll_list('STDOUT', $final);
    $self->poll_list('STDERR', $final);

    $self->store_state();
    close(FH);
}

sub poll_list
{
    my $self = shift;
    my $which = shift;
    my $final = shift;

    local(*OUT);
    open(OUT, '>>' . $self->{$which});
    select((select(OUT),$|=1)[$[]); # autoflush=1

    foreach my $record (@{$self->{$which . '_FILES'}})
    {
        my @stat = CORE::stat($record->[1]);
        next if @stat == 0;

        local(*FH);
        open(FH, '<'. $record->[1]);

	# We want to merge up to the last newline ... but if
	# we're in the DONE state, then we want to poll until
	# EOF
	do
	{
	    if($stat[7] > $record->[2])
	    {
		my($buffer, $buffersize, $writable);

		# file has grown... merge in new data
		$buffersize = $stat[7] - $record->[2];
		$buffersize = 4096 if $buffersize > 4096;

                seek(FH, $record->[2], SEEK_SET);
                read(FH, $buffer, $buffersize);

		$writable = $buffer;

		# We want to do line buffering, so we'll just 
		# strip off all data after the last newline
		if(! $final)
		{
		    my @writable;

		    @writable = split(//, $writable);
		    while(@writable)
		    {
			$_ = pop(@writable);
			if($_ eq "\n")
			{
			    push(@writable, "\n");
			    last;
			}
		    }
		    $writable = join('', @writable);
		}
		$record->[2] += length($writable);

		print OUT $writable;
	    }
	}
	while($final && ($record->[2] < $stat[7]));
        close(FH);
    }
    close(OUT);
}

sub store_state
{
    my $self = shift;
    my $tmp_filename = $self->{MERGE_FILENAME} . '.tmp';
    my $format = '%s "%s" %s' . "\n";

    local(*TMP);
    open(TMP, '>' . $tmp_filename);

    foreach(@{$self->{STDOUT_FILES}}, @{$self->{STDERR_FILES}})
    {
	printf TMP $format, $_->[0], $_->[1], $_->[2];
    }
    close(TMP);

    rename($tmp_filename, $self->{MERGE_FILENAME});

    return 0;
}

sub load_state
{
    my $self = shift;

    local(*IN);
    open(IN, '<' . $self->{MERGE_FILENAME});

    while(<IN>)
    {
	m/^(out|err)\s+"([^"]+)"\s+([0-9]+)$/ or next;
	my ($type, $local_filename, $offset) = ($1, $2, $3);

	if($type eq 'out')
	{
	    push(@{$self->{STDOUT_FILES}}, [$type, $local_filename, $offset]);
	}
	elsif($type eq 'err')
	{
	    push(@{$self->{STDERR_FILES}}, [$type, $local_filename, $offset]);
	}
    }
    close IN;

    return 0;
}

sub pipe_out_cmd
{
    my @result;
    local(*READ);

    my $pid = open( READ, "-|" );
    return undef unless defined $pid;

    if ( $pid )
    {
        # parent
        chomp(@result = <READ>);
        close(READ);
    } else {
        # child
        open( STDERR, '>>/dev/null' );
        select(STDERR); $|=1;
        select(STDOUT); $|=1;
        if (!  exec { $_[0] } @_ )
        {
            exit(127);
        }
    }
    wantarray ? @result : $result[0];
}

1;
