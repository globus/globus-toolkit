#! /usr/bin/perl

@GLOBUS_PERL_INITIALIZER@
END {exit(0);}

use Globus::Core::Paths;
use IO::File;
use Sys::Hostname;
use Test::More;
use File::Compare;
use File::Temp qw(tempdir);

my (@tests, @todo) = ();
my $contact = $ENV{CONTACT_STRING};
my $testtmp = tempdir( CLEANUP => 1 );

my $testdatadir = $0;
if ($testdatadir =~ m|/|)
{
    $testdatadir =~ s|/+[^/]*$||;
}
else
{
    $testdatadir = '.';
}
my $verbose = 0;

my @test_cases=qw(
    stdio001 stdio002 stdio003 stdio004 stdio005
    stdio006 stdio007 stdio008 stdio009 stdio010
    stdio011 stdio012 stdio013 stdio014 stdio015
    stdio016 stdio017 stdio018 stdio019
);

sub test_rsl
{
    my $testname = shift;
    my $additional_rsl = shift;
    my $testrsl = "$testname.rsl";
    my $additionalrslfile = "$testtmp/$testname.rsl";
    my $test_rsl_fp = new IO::File("$testdatadir/$testrsl", '<');
    my $rsl_list;
    my $out_count;
    my $all_rsl;
    my $need_ftp = 0;

    $rsl_list = join('', <$test_rsl_fp>);
    $rsl_list =~ s/&//;
    $rsl_list =~ m/\(\*\s+(\d+)\s+\*\)/;
    $out_count = $1;

    if ($rsl_list =~ m/TEST_FTP_PREFIX/)
    {
        $need_ftp = 1;
    }

    $test_rsl_fp->close();

    $all_rsl = '&';

    # need to put the RSL substitutions in the additional RSL
    # before the main RSL clauses
    if($additional_rsl ne '')
    {
	$all_rsl .= "$additional_rsl\n";
    }
    $all_rsl .= $rsl_list;
    
    if($verbose)
    {
	print "# Submitting job\n";

	foreach(split(/\n/, $all_rsl))
	{
	    print "#    $_\n";
	}
    }

    SKIP: {
        skip "No ftp server available", 1, if
            ($need_ftp && !exists $ENV{TEST_FTP_PREFIX});
        ok(run_and_compare($testname, $all_rsl, $out_count) == 0, $testname);
    }
}

sub run_and_compare
{
    my $testname = shift;
    my $rsl = shift;
    my $out_count = shift;
    my $rc;

    system("globusrun", "-s", "-r", $contact, $rsl);

    $rc = $? >> 8;

    if($rc == 0)
    {
	for(my $i = 0; $i < $out_count; $i++)
	{
	    my $out_name = sprintf("%s.%03d",
	                           "$testtmp/$testname.out",
				   $i+1);
	    my $err_name = sprintf("%s.%03d",
	                           "$testtmp/$testname.err",
				   $i+1);
            my $canonical_out = "$testdatadir/$testname.out";
            my $canonical_err = "$testdatadir/$testname.err";

	    if(File::Compare::compare($out_name, $canonical_out) != 0)
	    {
		$rc = sprintf("comparison of output file %d failed", $i+1);
                system("cat $out_name");
                system("cat $canonical_out");
		last;
	    }
	    if(File::Compare::compare($err_name, $canonical_err) != 0)
	    {
		$rc = sprintf("comparison of error file %d failed", $i+1);
                system("cat $err_name");
                system("cat $canonical_err");
		last;
	    }
	}
    }
    return $rc;
}

foreach(@test_cases)
{
    my $test_ftp_prefix = $ENV{TEST_FTP_PREFIX};
    my %rsl_substitutions = ();

    $rsl_substitutions{TEST_STDOUT} = "$testtmp/$_.out";
    $rsl_substitutions{TEST_STDERR} = "$testtmp/$_.err";
    $rsl_substitutions{TEST_FTP_PREFIX} = "$ENV{TEST_FTP_PREFIX}/%2F" 
        if exists $ENV{TEST_FTP_PREFIX};

    my $testtmprsl
        = "(rsl_substitution = " 
        . join('', 
            map { "($_ \\\"$rsl_substitutions{$_}\\\")" } keys %rsl_substitutions)
        . ")";

    push(@tests, "test_rsl(\"$_\", \"$testtmprsl\")");
}
if(@ARGV)
{
    my @doit;

    $verbose = 1;

    foreach(@ARGV)
    {
        if(/^(\d+)-(\d+)$/)
        {
            foreach($1 .. $2)
            {
               push(@doit, $_);
            }
        }
        elsif(/^(\d+)$/)
        {
            push(@doit, $1);
        }
    }
    plan tests => scalar(@doit);

    foreach (@doit)
    {
        eval "&$tests[$_-1]";
    }
}
else
{
    plan tests => scalar(@tests), todo => \@todo;

    foreach (@tests)
    {
	eval "&$_";
    }
}
