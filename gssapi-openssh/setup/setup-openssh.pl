#!/usr/bin/perl -w
#
# fixpaths  - substitute makefile variables into text files

#
# Set up path prefixes for use in the path translations
#

$prefix = "/home/cphillip/gsi-openssh/install";
$exec_prefix = "$prefix";
$bindir = "$exec_prefix/bin";
$libexecdir = "$exec_prefix/libexec";
$sysconfdir = "$prefix/etc";
$piddir = "/var/run";
$xauth_path = "/usr/bin/X11/xauth";

sub fixpaths
{
    #
    # Set up path translations for the installation files
    #

    %def = (
        "/etc/ssh_config" => "${sysconfdir}/ssh_config",
        "/etc/ssh_known_hosts" => "${sysconfdir}/ssh_known_hosts",
        "/etc/sshd_config" => "${sysconfdir}/sshd_config",
        "/usr/libexec" => "${libexecdir}",
        "/etc/shosts.equiv" => "${sysconfdir}/shosts.equiv",
        "/etc/ssh_host_key" => "${sysconfdir}/ssh_host_key",
        "/etc/ssh_host_dsa_key" => "${sysconfdir}/ssh_host_dsa_key",
        "/etc/ssh_host_rsa_key" => "${sysconfdir}/ssh_host_rsa_key",
        "/var/run/sshd.pid" => "${piddir}/sshd.pid",
        "/etc/moduli" => "${sysconfdir}/moduli",
        "/etc/sshrc" => "${sysconfdir}/sshrc",
        "/usr/X11R6/bin/xauth" => "${xauth_path}",
        "/usr/bin:/bin:/usr/sbin:/sbin" => "/usr/bin:/bin:/usr/sbin:/sbin:${bindir}",
        );

    print "dumping list of path translations..\n";
    for $s (keys(%def))
    {
        print "$s = " . $def{$s} . "\n";
    }

    #
    # Files on which to perform path translations
    #

    @files = (
        "ssh_config",
        "sshd_config",
        "moduli",
        "scp.1",
        "ssh-add.1",
        "ssh-agent.1",
        "ssh-keygen.1",
        "ssh-keyscan.1",
        "ssh.1",
        "sshd.8",
        "sftp-server.8",
        "sftp.1",
        );

    print "\ntranslating files..\n";
    for $f (@files)
    {
        $f =~ /(.*\/)*(.*)$/;
        $g = "$f.out";

        open(IN, "<$f") || die ("$0: input file $f missing!\n");

        if ( -e $g )
        {
            print "$g already exists, skipping.\n";
        }
        else
        {
            open(OUT, ">$g") || die ("$0: unable to open output file $g!\n");

            while (<IN>)
            {
                for $s (keys(%def))
                {
                    s#$s#$def{$s}#;
                } # for $s
                print OUT "$_";
            } # while <IN>

            close(OUT);
        }

        close(IN);
    } # for $f

    return 0;
}

sub runkeygen
{
    print "\nkey gen routine starting..\n";
    if ( -e "${sysconfdir}/ssh_host_key" )
    {
        print "${sysconfdir}/ssh_host_key already exists, skipping.\n";
    }
    else
    {
        # if $sysconfdir/ssh_host_key doesn't exist..
        system("$bindir/ssh-keygen -t rsa1 -f $sysconfdir/ssh_host_key -N \"\"");
    }

    if ( -e "${sysconfdir}/ssh_host_dsa_key" )
    {
        print "${sysconfdir}/ssh_host_dsa_key already exists, skipping.\n";
    }
    else
    {
        # if $sysconfdir/ssh_host_dsa_key doesn't exist..
        system("$bindir/ssh-keygen -t dsa -f $sysconfdir/ssh_host_dsa_key -N \"\"");
    }

    if ( -e "${sysconfdir}/ssh_host_rsa_key" )
    {
        print "${sysconfdir}/ssh_host_rsa_key already exists, skipping.\n";
    }
    else
    {
        # if $sysconfdir/ssh_host_rsa_key doesn't exist..
        system("$bindir/ssh-keygen -t rsa -f $sysconfdir/ssh_host_rsa_key -N \"\"");
    }

    return 0;
}

fixpaths();

runkeygen();
