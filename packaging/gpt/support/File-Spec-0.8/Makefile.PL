use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'File::Spec',
    'VERSION_FROM'	=> 'Spec.pm',
    'LIBS'	=> [''],   # e.g., '-lm' 
    'DEFINE'	=> '',     # e.g., '-DHAVE_SOMETHING' 
    'INC'	=> '',     # e.g., '-I/usr/include/other' 
#    'PM'	=> {'Spec.pm'	=> '$(INST_LIBDIR)/File/Spec.pm',
#    			'OS2.pm'	=> '$(INST_LIBDIR)/File/Spec/OS2.pm',
#    			'Win32.pm'	=> '$(INST_LIBDIR)/File/Spec/Win32.pm',
#    			'VMS.pm'	=> '$(INST_LIBDIR)/File/Spec/VMS.pm',
#   			'Unix.pm'	=> '$(INST_LIBDIR)/File/Spec/Unix.pm',
#    			}
);
