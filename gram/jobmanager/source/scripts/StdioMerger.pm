use Globus::Core::Paths;

use File::stat;
use File::Copy;

package Globus::GRAM::StdioMerger;

my $cache_pgm = "$Globus::Core::Paths::bindir/globus-gass-cache";

sub new
{
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $tag = shift;
    my $stdout = shift;
    my $stderr = shift;
    my $merge_urlname = "x-gass-cache://$tag/dev/stdio_merge";
    my $self  = {};

    $self->{STDOUT_FILES} = [];
    $self->{STDERR_FILES} = [];
    $self->{CACHE_TAG} = $tag;
    $self->{STDOUT} = $stdout;
    $self->{STDERR} = $stderr;

    $self->{MERGE_FILENAME} = &lookup_or_add_in_cache($merge_urlname, $tag);

    bless $self, $class;

    if($self->{MERGE_FILENAME} eq '')
    {
	return undef;
    }
    $stat = File::stat::stat($self->{MERGE_FILENAME});

    if($stat->size > 0)
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
    my $format = "x-gass-cache://\%s/dev/std\%s/\%03d";
    my $new_url;
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

    $new_url = sprintf($format, $self->{CACHE_TAG}, $type, $index);
    $new_name = &lookup_or_add_in_cache($new_url, $self->{CACHE_TAG});

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
    my $stderr = new IO::File($self->{STDERR}, 'a');
    my $record;

    $self->poll_list('STDOUT', $final);
    $self->poll_list('STDERR', $final);

    $self->store_state();
}

sub poll_list
{
    my $self = shift;
    my $which = shift;
    my $final = shift;
    my $record;
    my $output = new IO::File($self->{$which}, 'a');
    my $tmpfile;

    foreach $record (@{$self->{$which . '_FILES'}})
    {
	$stat = File::stat::stat($record->[1]) or next;
	$tmpfile = new IO::File($record->[1], 'r');

	# We want to merge up to the last newline ... but if
	# we're in the DONE state, then we want to poll until
	# EOF
	do
	{
	    if($stat->size > $record->[2])
	    {
		my($buffer, $buffersize, $writable);

		# file has grown... merge in new data
		$buffersize = $stat->size - $record->[2];
		$buffersize = 4096 if $buffersize > 4096;

		$tmpfile->seek($record->[2], SEEK_SET);
		$tmpfile->read($buffer, $buffersize);

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

		$output->print($writable);
	    }
	}
	while($final && ($record->[2] < $stat->size));
	$tmpfile->close();
    }
    $output->close();
}

sub store_state
{
    my $self = shift;
    my $tmp_filename = $self->{MERGE_FILENAME} . '.tmp';
    my $tmp_file = new IO::File($tmp_filename, 'w');

    foreach(@{$self->{STDOUT_FILES}}, @{$self->{STDERR_FILES}})
    {
	my $format = '%s "%s" %s' . "\n";
	$tmp_file->print(sprintf($format, $_->[0], $_->[1], $_->[2]));
    }
    $tmp_file->close();

    rename($tmp_filename, $self->{MERGE_FILENAME});

    return 0;
}

sub load_state
{
    my $self = shift;
    my $file = new IO::File($self->{MERGE_FILENAME}, 'r');

    while(<$file>)
    {
	m/^(out|err)\s+"([^"]+)"\s+([0-9]+)$/ or next;
	($type, $local_filename, $offset) = ($1, $2, $3);

	if($type eq 'out')
	{
	    push(@{$self->{STDOUT_FILES}}, [$type, $local_filename, $offset]);
	}
	elsif($type eq 'err')
	{
	    push(@{$self->{STDERR_FILES}}, [$type, $local_filename, $offset]);
	}
    }
    $file->close();

    return 0;
}

sub lookup_or_add_in_cache
{
    my $url = shift;
    my $tag = shift;
    my $result;

    chomp($result = `$cache_pgm -query -t $tag $url`);
    if($result eq '')
    {
	system("$cache_pgm -add -n $url -t $tag file:/dev/null");
    }
    chomp($result = `$cache_pgm -query -t $tag $url`);
    if($result eq '')
    {
	return undef;
    }
    else
    {
	return $result;
    }
}

1;
