use Test;
use File::Temp qw(tempdir);
use File::Copy;

my @test_cases = qw(
    00.00.gup
    01.01.gup
    03.01.gup
    03.02.gup
    03.03.gup
    04.01.gup
    04.02.gup
    05.01.gup
    06.00.gup
    07.00.gup
    08.00.gup
    09.09.gup
    10.01.gup);

my $uploader = "$ENV{GLOBUS_LOCATION}/sbin/globus-usage-uploader";

sub test_upload
{
    my $test = shift;
    my $res;

    $res = `$uploader -d $test -n`;
    print STDERR $res;

    ok($? == 0);
}

plan tests => scalar(@test_cases);

my $test_dir = tempdir(CLEANUP => 1);

for (my $i = 0; $i < scalar(@test_cases); $i++) {
    my $dir = "$test_dir/19700101";
    mkdir $dir, 0755;
    copy($test_cases[$i], sprintf("$dir/%02d", $i));
    test_upload($dir);
}
