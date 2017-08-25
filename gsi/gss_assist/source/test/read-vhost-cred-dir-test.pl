#! /usr/bin/perl

use strict;
use warnings;

use Test::More;
use File::Temp;

my $testprog = "./read-vhost-cred-dir-test";

sub parse_cred_list
{
    my @s = split(/\n/, $_[0]);
    my $count;
    my @list;
    my $state = 0;
    my ($cert_accum, $key_accum) = ('','');

    chomp($count = shift @s);
    $count =~ s/^count=//;
    $count = int($count);


    foreach (@s) {
        if ($state == 0 && /BEGIN CERTIFICATE/)
        {
            $cert_accum = "$_\n";
            $key_accum = '';
            $state = 1;
        } elsif ($state == 1 && !/END CERTIFICATE/) {
            $cert_accum .= "$_\n";
        } elsif ($state == 1 && /END CERTIFICATE/) {
            $cert_accum .= "$_";
            $state = 2;
        } elsif ($state == 2 && /BEGIN PRIVATE KEY/) {
            $key_accum = "$_\n";
        } elsif ($state == 2 && !/END PRIVATE KEY/) {
            $key_accum .= "$_\n";
        } elsif ($state == 2 && /END PRIVATE KEY/) {
            $key_accum .= $_;
            push(@list, {CERT => $cert_accum, KEY => $key_accum});
            $state = 0;
        }
    }
    return @list;
}

sub non_existent_dir {
    my $tempdir = File::Temp::tempdir(CLEANUP => 0);
    my ($output, $rc);

    rmdir $tempdir;

    $ENV{X509_VHOST_CRED_DIR} = $tempdir;

    chomp($output = `$testprog 2>&1`);
    $rc = $? >> 8;

    diag($output);

    ok($rc != 0, "non_existent_dir");
}

sub empty_vhost_dir {
    my $tempdir = File::Temp::tempdir(CLEANUP => 1);
    my ($output, $rc);

    $ENV{X509_VHOST_CRED_DIR} = $tempdir;

    chomp($output = `$testprog 2>&1`);
    $rc = $? >> 8;

    diag($output);

    ok($rc == 0 && $output eq 'count=0', "empty_vhost_dir");
}

sub non_pem_files {
    my $tempdir = File::Temp::tempdir(CLEANUP => 1);
    my ($nonpem, $nonpemfile) = ("$tempdir/nonpem");
    my ($output, $rc);

    $ENV{X509_VHOST_CRED_DIR} = $tempdir;

    open($nonpemfile, ">$nonpem");
    print $nonpemfile "Hello\n";
    close($nonpemfile);


    chomp($output = `$testprog 2>&1`);
    $rc = $? >> 8;

    diag($output);

    ok($rc == 0 && $output eq 'count=0', "non_pem_files");
}

sub single_cred {
    my $tempdir = File::Temp::tempdir(CLEANUP => 1);
    my ($in);
    my ($cred, $credfile) = ("$tempdir/cred.pem");
    my ($cert_string, $key_string) = ('','');
    my ($output, $rc);
    my @expected_cred_list;
    my @cred_list;
    my $umask = umask(077);

    $ENV{X509_VHOST_CRED_DIR} = $tempdir;

    open($credfile, ">$cred");

    open($in, "<testcred.cert");
    while (<$in>) {
        $cert_string .= $_;
        print $credfile $_;
    }
    close($in);
    chomp($cert_string);

    open($in, "openssl pkey -in testcred.key|");
    while (<$in>) {
        $key_string .= $_;
        print $credfile $_;
    }
    chomp($key_string);
    close($in);

    push(@expected_cred_list, {CERT => $cert_string, KEY => $key_string});

    close($credfile);

    chomp($output = `$testprog 2>&1`);
    $rc = $? >> 8;
    if ($rc == 0)
    {
        @cred_list = parse_cred_list($output);
    }
    else
    {
        diag($output);
    }

    is_deeply([$rc, @cred_list], [0, @expected_cred_list], "single_cred");
    umask($umask);
}

sub mix_cred_and_non_pem {
    my $tempdir = File::Temp::tempdir(CLEANUP => 1);
    my ($in);
    my ($cred, $credfile) = ("$tempdir/cred.pem");
    my $junkfile;
    my ($cert_string, $key_string) = ('','');
    my ($output, $rc);
    my @expected_cred_list;
    my @cred_list;
    my $umask = umask(077);

    $ENV{X509_VHOST_CRED_DIR} = $tempdir;

    open($credfile, ">$cred");

    open($in, "<testcred.cert");
    while (<$in>) {
        $cert_string .= $_;
        print $credfile $_;
    }
    close($in);
    chomp($cert_string);

    open($in, "openssl pkey -in testcred.key|");
    while (<$in>) {
        $key_string .= $_;
        print $credfile $_;
    }
    chomp($key_string);
    close($in);

    push(@expected_cred_list, {CERT => $cert_string, KEY => $key_string});

    close($credfile);

    open($junkfile, ">$tempdir/README");
    print $junkfile "hello\n";
    close($junkfile);

    chomp($output = `$testprog 2>&1`);
    $rc = $? >> 8;
    @cred_list = parse_cred_list($output);


    is_deeply(
            [$rc, @cred_list], [0, @expected_cred_list],
            "mix_cred_and_non_pem");
    umask($umask);
}

sub multiple_cred {
    my $tempdir = File::Temp::tempdir(CLEANUP => 1);
    my ($in);
    my ($cred, $credfile);
    my $junkfile;
    my ($cert_string, $key_string) = ('','');
    my ($output, $rc);
    my @expected_cred_list;
    my @cred_list;
    my $umask = umask(077);

    $ENV{X509_VHOST_CRED_DIR} = $tempdir;

    foreach my $name ("testcred1", "testcred2") {
        open($credfile, ">$tempdir/$name.pem");
        open($in, "<$name.cert");
        $cert_string = '';
        $key_string = '';
        while (<$in>) {
            $cert_string .= $_;
            print $credfile $_;
        }
        close($in);
        chomp($cert_string);

        open($in, "openssl pkey -in $name.key|");
        while (<$in>) {
            $key_string .= $_;
            print $credfile $_;
        }
        chomp($key_string);
        close($in);

        push(@expected_cred_list, {CERT => $cert_string, KEY => $key_string});
        close($credfile);
    }
    @expected_cred_list =
                sort {$a->{CERT} cmp $b->{CERT} } @expected_cred_list;


    chomp($output = `$testprog 2>&1`);
    $rc = $? >> 8;
    if ($rc == 0) {
        @cred_list = sort {$a->{CERT} cmp $b->{CERT} } parse_cred_list($output);
    } else {
        diag($output);
    }


    is_deeply(
            [$rc, @cred_list], [0, @expected_cred_list],
            "multiple_cred");
    umask($umask);
}

my @tests = qw(
    non_existent_dir
    empty_vhost_dir
    non_pem_files
    single_cred
    mix_cred_and_non_pem 
    multiple_cred
);

plan tests => scalar(@tests);


foreach (@tests) {
    eval $_;
    if ($@) {
        print STDERR $@;
    }
}
