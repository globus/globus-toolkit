#! /usr/bin/env perl

use Test;
use File::Path;
use File::Compare;

my (@tests, @todo) = ();
my $contact = $ENV{CONTACT_STRING};
my $testtmp = &make_tmpdir();
my $verbose = 0;

my $test_dir = "$ENV{GLOBUS_LOCATION}/test/globus_scheduler_event_generator_test";
my $test_exe = "seg-api-test";

sub api_test
{
    my $file = shift;

    system("./$test_exe $file > $testtmp/output");
    ok(File::Compare::compare("$testtmp/output", $file) == 0);
}

push(@tests, 'api_test("seg_api_test_data.txt")');

plan tests => scalar(@tests);

foreach(@tests) {
    eval "&$_";
}

sub make_tmpdir
{
    my $root;
    my $suffix = '/seg_test_';
    my $created = 0;
    my $tmpname;
    my @acceptable = split(//, "abcdefghijklmnopqrstuvwxyz".
			       "ABCDEFGHIJKLMNOPQRSTUVWXYZ".
			       "0123456789");
    if(exists($ENV{TMPDIR}))
    {
	$root = $ENV{TMPDIR};
    }
    else
    {
	$root = '/tmp';
    }
    while($created == 0)
    {
	$tmpname = $root . $suffix .
	           $acceptable[rand() * $#acceptable] .
	           $acceptable[rand() * $#acceptable] .
	           $acceptable[rand() * $#acceptable] .
	           $acceptable[rand() * $#acceptable] .
	           $acceptable[rand() * $#acceptable] .
	           $acceptable[rand() * $#acceptable];
	$created = mkdir($tmpname, 0700);
	if($created)
	{
	    if(-l $tmpname or ! -d $tmpname or ! -o $tmpname)
	    {
		$created = 0;
	    }
	}
    }
    return $tmpname;
}

END
{
    if(-d $testtmp and -o $testtmp)
    {
	File::Path::rmtree($testtmp);
    }
}
