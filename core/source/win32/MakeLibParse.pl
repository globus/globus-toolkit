# -----------------------------------------------------------------------------
#
#   Linux Script To Extract Global Exports From Built Libraries
#
#       Initial Creation    01/21/2004      R. Gaffaney
#
#          Note: This script runs on the Linux machine and extracts exported 
#             symbols from the library files created by the Linux build.
#         
#             On Linux side sure to set GLOBUS_LOCATION, e.g.:
#         
#                  GLOBUS_LOCATION=/sandbox/gaffaney
#                  export GLOBUS_LOCATION
#
# -----------------------------------------------------------------------------

# Directives
use warnings;
use strict;

# Subroutines
sub AddEntries();

# Variables
my $ArgCount;
my $FlavorName;
my $GlobusLocation;
my $ModuleType;
my $SourceLocation;
my $Win32Location;

# Temp Variables
my @temp;
my $record;


# ---------------------------
# Get Command Line Arguments
# ---------------------------

# Should Be Two Command Line Arguments
$ArgCount = $#ARGV + 1;
if($ArgCount != 2) {
    print "\nInvalid Command Line\n\n";
    print "   Format: MakeLibParser GLOBUS_LOCATION LinuxFlavor\n\n";
    exit();
    }
    
# Grab The Command Line Parameters
$GlobusLocation = $ARGV[0];
$FlavorName = $ARGV[1];

# Display Values
print "\nCommand Line Parameters:\n";
print "Globus Location:     ", $GlobusLocation, "\n";
print "Linux Flavor Name:   ", $FlavorName, "\n";

# Open The LibParse.pl Script File
if(!open(LIBPARSER,'>',"libparse.pl")) {
    print "Can't Open Script File \"libparse.pl\"\n";
    exit(0);
    }

# Open The MoveExports.bat Batch File
if(!open(MOVEXPORTS,'>',"MoveExports.bat")) {
    print "Can't Open Batch File \"MoveExports.bat\"\n";
    exit(0);
    }

# Open The Modules File
if(!open(MODULES,"WinModules")) {
    print "Can't Open Modules File \"WinModules\"\n";
    exit(0);
    }

# Recurse The Modules File
while (<MODULES>) {
    # Kill EOL    
    chomp($_);
    
    # Look For A Module Record Block
    if(/^ModuleType/) {
        @temp = split;
        
        # Capture Module Type
        $ModuleType = $temp[1];
        
        # Capture The Source Location
        $record = <MODULES>;
        chomp $record;
        @temp = split / +/, $record;
        if($temp[0] eq "SourceLocation") {
            $SourceLocation = $temp[1];
            # ToDo: Should Verify Parameter Here
            }
        else {
            print "Globus Module Parameter Not Found\n";
            exit(0);
            }
        
        # Capture The Win32 Location
        $record = <MODULES>;
        chomp $record;
        @temp = split / +/, $record;
        if($temp[0] eq "Win32Location") {
            $Win32Location = $temp[1];
            # ToDo: Should Verify Parameter Here
            }
        else {
            print "Globus Module Parameter Not Found\n";
            exit(0);
            }
            
        # Create LibParse and Batch File Entries For This Module
		AddEntries();
      
        } # if ModuleType
    } # while <MODULES>

# Close the Modules File
close(MODULES);

# Close the LibParser File
close(LIBPARSER);

# Close the Batch File
close(MOVEXPORTS);


# Add Parse And Batch File Entry Subroutine
sub AddEntries()
{
my $FullSourcePath;
my $FullWin32Path;
my $BaseLibraryName;

# Temp Variables
my @stemp;

    # Build Full Paths
    $FullSourcePath = $GlobusLocation . $SourceLocation;
    $FullWin32Path  = $GlobusLocation . $Win32Location;
    
    # Change The Working Directory To The Source Path
    if(!chdir $FullSourcePath) {
        print "Can't Change Directory To ", $FullSourcePath, "\n";
        exit();
        }
    
    # Open Makefile.am
    if(!open(MAKEFILE_AM,"Makefile.am")) {
        print "Can't Open Makefile.am\n\n";
        exit();
        }

    #
    # Parse Makefile.am
    #
    while (<MAKEFILE_AM>) {
        @stemp = {};
            
        # Capture Base Library Name
        if(/^lib_LTLIBRARIES/) {
            # Split The Fields
            @stemp = split;

            # Extract Flavor Name
            @stemp = split /\$\(GLOBUS_FLAVOR_NAME\)/,$stemp[2];
            $BaseLibraryName = $stemp[0];

            #
            # Library Parse Script Entries
            #
            
            # Create The Lib Parse Entry
            print LIBPARSER "\n";
            print LIBPARSER "system \"nm $BaseLibraryName$FlavorName.so \\\> temp.symbols\";\n ";
            print LIBPARSER "\n";
            
            # Open The Symbols File
            print LIBPARSER "if\(!open\(SYMBOLS,\"temp.symbols\"\)\) \{\n";
            print LIBPARSER "    print \"Can't Open temp.symbols\\n\";\n";
            print LIBPARSER "    exit\(\);\n";
            print LIBPARSER "    \}\n";
            print LIBPARSER "\n";
                
            # Open The Exports File For This Library
            print LIBPARSER "if\(!open\(EXPORTS,\'\>\',\"$BaseLibraryName.exports\"\)\) \{\n";
            print LIBPARSER "    print \"Can't Open $BaseLibraryName.exports\\n\";\n";
            print LIBPARSER "    exit\(\);\n";
            print LIBPARSER "    \}\n";
            print LIBPARSER "\n";
                
            # Capture The Global Code Symbols To The Exports File 
            print LIBPARSER "while \(\<SYMBOLS\>\) \{\n";
            print LIBPARSER "    \@temp = split;\n";
            print LIBPARSER "    if\(\$temp[1] eq \"T\"\) \{\n";
            print LIBPARSER "        print EXPORTS \"\$temp[2]\\n\";\n";
            print LIBPARSER "        \}\n";
            print LIBPARSER "    \}\n";
            print LIBPARSER "\n";
            
            # CLose The Symbols File
            print LIBPARSER "close\(SYMBOLS\);\n";
            
            # Delete The Symbols File
            print LIBPARSER "system \"rm temp.symbols\";\n ";
            print LIBPARSER "\n";
            
            # CLose The Exports File
            print LIBPARSER "close\(EXPORTS\);\n";
            print LIBPARSER "\n";
            
            #
            # Batch File Entries
            #
            
            # Delete Residual Winmake.export File
            print MOVEXPORTS "del Winmake.exports\n";
            
           	# Copy The File From The Linux Box
            print MOVEXPORTS "\%2\\pscp \-pw \%3  \%1$BaseLibraryName.exports Winmake.exports\n";
            
            # Create The win32 Directory If It Doesn't Exist
            # This Step is necessary because CVS Checkout doesn't create all necessary win32 
            # subdirectories. This will fail when the win32 directories are created by CVS
            print MOVEXPORTS "md $FullWin32Path\\win32\n";
            
            # Move The File To The Win32 Directory For This Module
            print MOVEXPORTS "copy Winmake.exports $FullWin32Path\\*.*\n";
            
            } # if(lib_LTLIBRARIES)
            
        } # while <MAKEFILE_AM>
}

