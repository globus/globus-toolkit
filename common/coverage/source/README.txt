Coverage Report Generator

I. Overview
   The script globus-coverage will generate an HTML report from profiling
   data collected by gcc and gcov.

   The report generator uses the HTML::Template perl module. Details
   about this module can be found at CPAN:
   http://search.cpan.org/~samtregar/HTML-Template-2.8/. To install,
   download and unpack the tarball, then install:
   perl Makefile.PL PREFIX=~
   and add the subdirectory of ~/lib which contains HTML/Template.pm to the
   PERL5LIB environment variable.

II. Building GT with profiling flavor
   - Build a core flavor with gcc with the --enable-profiling and
     --enable-debug flags.
   - Build the toolkit and tests with the flavor made above using gpt-build
     or a source installer. DO NOT REMOVE THE BUILD DIRECTORIES.
   - Don't forget to build this globus_coverage package

III. Generating reports.
   - After the toolkit is built and setup, run the test cases as normal.
     The profiler will write traces into the build directories as the
     test programs are run.
   - run the script globus-coverage to generate the reports:
Usage: globus-coverage [OPTION] package-directory [package-directory ...]
Options:
 -b | --bundle-name NAME     Use NAME as the bundle name for the coverage
                             report [default=Summary].
 -h | --help                 Print this help message.
 -o | --output-dir DIR       Place report output in DIR [default=coverage].
 -p | --parser-class CLASS   Use the specified profiling parser module
                             [default="Globus::Coverage::GCovParser"].

     The bundle-name value is used for the title of the top level index page.
     The output-dir is where the report will be written. It will be created
     if not present, and will write index.html + files for the various packages
     and source files in the packages.
     The package-directory arguments are a list of package build directories
     where the profiling flavor of the packages were built. Each package must
     be listed separately. Non-package dirs will be ignored, as will packages
     which contain no executable code (such as setup packages). For C WS Core,
     in an installer dir, I use the command
         find source-trees/wsrf/c -name pkgdata | sed -e 's/\/pkgdata//'
     to generate an appropriate list.

IIII. The report format
   The report will consist of an index file (index.html) which contains an
   overview of all profiled package, a package file called
   package-<package_name>.html for each package, a source file function summary
   file summary-<filename.ext>.html for each profiled file, and an annotated
   source file source-<filename.ext>.html for each profiled file. These files
   all contain percentages of the file/functions/branches which have been
   covered by the tests. Note that the branch counts are a bit confused because
   of macro expansions.
