package Globus::Core::Paths;

require Exporter;

@ISA = qw(Exporter);

@EXPORT = qw($exec_prefix $prefix
             $sbindir $bindir
	     $libdir $libexecdir $includedir
	     $datadir $sysconfdir $sharedstatedir
	     $localstatedir
	     $tmpdir
	     $local_tmpdir
	     $secure_tmpdir);

$exec_prefix=$ENV{GLOBUS_LOCATION};
$prefix=$ENV{GLOBUS_LOCATION};
$sbindir="${exec_prefix}/sbin";
$bindir="${exec_prefix}/bin";
$libdir="${exec_prefix}/lib";
$libexecdir="${exec_prefix}/libexec";
$includedir="${exec_prefix}/include";
$datadir="${prefix}/share";
$sysconfdir="${prefix}/etc";
$sharedstatedir="${prefix}/com";
$localstatedir="${prefix}/var";
$tmpdir="/tmp";
$local_tmpdir="/tmp";
$secure_tmpdir="/Users/lukasz/tmp/gcmu/scratch/gt/tmp";

1;
