#! /usr/bin/perl

package FtpTestLib;

BEGIN { push(@INC, $ENV{GLOBUS_LOCATION} . '/lib/perl'); }

my $self = {};

use strict;

use POSIX;
use Carp;
use Sys::Hostname;
use Data::Dumper;
use File::Copy;

use Cwd;

# These are globus test support modules.
# use Globus::URL;
# use Globus::Testing::HostDB;
# use Globus::Testing::Startup;

=head1 NAME

FTPTestLib - Helper library for writing FTP tests.

=head1 SYNOPSIS

use FtpTestLib;

push_proxy($new_proxy);

pop_proxy();

compare_local_files($original, $copy);

=head1 DESCRIPTION

The FTPTestLib module provides a set of subroutes for writing tests of 
the ftp test library. The following subroutines are available:

=cut

=over 4

=item  push_proxy($)

Save the current value of the X509_USER_PROXY environment variable in
a stack and set it to the passed argument. If the argument is not defined,
then delete the proxy variable.

=cut
sub push_proxy($)
{
    push(@{$self->{proxy}}, $ENV{X509_USER_PROXY});
    if(scalar(@_) > 0)
    {
        $ENV{X509_USER_PROXY} = $_[0];
    }
    else
    {
        delete($ENV{X509_USER_PROXY});
    }
}

=pod

=item pop_proxy()

Restore the value of the X509_USER_PROXY environment variable from a
previous call to push_proxy. If the proxy was undefined when
push_proxy was called, then it will be removed from the environment.

=cut
sub pop_proxy()
{
    my $proxy = pop(@{$self->{proxy}});

    if(defined($proxy))
    {
        $ENV{X509_USER_PROXY} = $proxy;
    }
    else
    {
        delete($ENV{X509_USER_PROXY});
    }
}

=pod

=item compare_local_files($original, $copy)

Verify that a copy of a file is identical to the original.

=over 8

=item $original

The file name of the original copy of the data.

=item $copy

The file name of the new copy of the data. Any plugin-generated output
is first filtered from the copy before the comparison is made.

=back

If the files are identical, this function returns an empty string;
otherwise a shell comment-string containing information about the
differences is returned.

=cut
sub compare_local_files($$)
{
    my($a,$b) = @_;
    my $diffs;

    if(-B $a or -B $b)
    {
	$diffs = `perl -pe 's/\\[restart plugin\\].*\\n//' < $b | cmp '$a' -`;
    }
    else
    {
        $diffs = `perl -pe 's/\\[restart plugin\\].*\\n//' < $b | diff '$a' -`;
    }

    if($? != 0)
    {
        "\n#Differences between $a and output." .
        join("\n#", split(/\n/, $diffs));
    }
    else
    {
        "";
    }
}

sub stage_source_url()
{
    my $test_url = "gsiftp://localhost/etc/group";

    my $local_copy = POSIX::tmpnam();

    copy("/etc/group", $local_copy);

    ($test_url, $local_copy);
}

sub ftp_commands()
{
    return ('SITE', 'TYPE', 'MODE', 'SIZE', 'DCAU', 'PROT', 'BUFSIZE',
            'OPTS', 'PASV', 'PORT', 'REST', 'RETR', 'STOR', 'ERET', 'ESTO',
            'LIST', 'NLST', 'MDTM', 'MKD', 'RMD', 'RNFR', 'RNTO', 'NOOP' );
}


=back

=cut

sub END
{
    if(exists($self->{host_db}))
    {
        delete $self->{host_db};
    }
}
1;
