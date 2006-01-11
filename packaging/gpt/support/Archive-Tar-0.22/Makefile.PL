#! - perl -
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile
    (
     'NAME' => 'Archive::Tar',
     'VERSION_FROM' => 'Tar.pm', # finds $VERSION
     'EXE_FILES' => ['ptar'],
     'dist' => { COMPRESS => 'gzip -9f', SUFFIX => 'gz' },
     $] >= 5.005 ? ('AUTHOR' => 'Stephen Zander <gibreel@pobox.com>',
		    'ABSTRACT' => 'Manipulates TAR archives') : ()
    );
