package Globus::URL;

use strict;

sub new($$)
{
    my $class = shift;
    my $url = shift;
    my $self = {};
    my $safe = '$+-';
    my $alpha = "[a-zA-Z]";
    my $extra = '*\(),!';
    my $userpass = '\G(?:([*\()a-zA-Z0-9$+-]*)(?::([*\()a-zA-Z0-9$+-]*))\@)?';
    my $hostport = '\G([a-zA-Z.-][a-zA-Z.0-9-]*)(?::(\d+))?';

    if($url eq "")
    {
        return 0;
    }

    $self->{url} = $url;

    $url =~ m|^([a-z0-9+.-]*):|g or return undef;
    
    # Parse scheme
    $self->{scheme}=$1;
    if($self->{scheme} ne "file")
    {
        $url =~ m|\G//|g;
    }

    if($self->{scheme} eq "ftp" ||
       $self->{scheme} eq "gsiftp")
    {
	  if($url =~ m,$userpass,g)
	     {
	       $self->{username} = $1;
	       $self->{password} = $2;
	     }
	     else
	     {
	       return undef;
	     }
    }
    if($self->{scheme} eq 'ftp' ||
       $self->{scheme} eq 'gsiftp' ||
       $self->{scheme} eq 'http' ||
       $self->{scheme} eq 'https')
    {
        if($url =~ m,$hostport,g)
	{
            $self->{host} = $1;
            $self->{port} = $2;
	}
	else
	{
            return undef;
	}

	$url =~ m/\G(.*)/gc;
	$self->{path} = $1;
    }
    elsif($self->{scheme} =~ m/^nexus$/)
    {
	# port required for x-nexus URL
        if($url =~ m,$hostport,g)
	{
            $self->{host} = $1;
            $self->{port} = $2 or return undef;
	}
	else
	{
            return undef;
	}
    }
    elsif($self->{scheme} =~ m/^ldap$/)
    {
        if($url =~ m/\G([a-zA-Z]|-|.)(?::(\d+))?/gc)
	{
            $self->{host} = $1;
            $self->{port} = $2;
	}
	else
	{
            return undef;
	}
	
	if($url !~ m,\G/,g)
	{
	    return undef;
	}
        my $myre = "$safe|$extra|$alpha|\\d";
        if($url =~ m,\G($myre)\?($myre)\?($myre)\?($myre),g)
	{
            $self->{dn} = $1;
            $self->{attributes} = $1;
            $self->{scope} = $1;
            $self->{filter} = $1;
	}
        else
	{
	    return undef;
	}
    }
    elsif($self->{scheme} =~ m/^file$/)
    {
        if($url =~ m,\G//([\da-zA-Z-]),g)
	{
            $self->{host} = $1;
	}
        $url =~ m/\G(.*)/gc;
        $self->{path} = $1;
    }
    elsif($self->{scheme} =~ m/^x-gass-cache$/)
    {
        $url =~ m/\G(.*)/gc;
        $self->{url_specific} = $1;
    }
    else
    {
        if($url =~ m/\G([a-zA-Z]|-|.)(?::(\d+))?/gc)
	{
            $self->{host} = $1;
            $self->{port} = $2;
	}
	else
	{
            return undef;
	}
        $url =~ m/\G(.*)/gc;
        $self->{path} = $1;
    }
    bless $self, $class;
}

sub to_string($)
{
    my $self = shift;
    my $url;

    $url = $self->{scheme};
    if(defined($self->{host}))
    {
        $url .= "://";
    }
    else
    {
        $url .= ":";
    }
    if(defined($self->{username}) || defined($self->{password}))
    {
	$url .= "$self->{username}:$self->{password}\@";
    }
    $url .= $self->{host};
    $url .= ":$self->{port}" if defined($self->{port});

    $url .= $self->{path};
    $url .= $self->{dn}."?".$self->{attributes}."?".$self->{scope}."?".
            $self->{attributes} if exists($self->{dn});

    return $url;
}

1;
