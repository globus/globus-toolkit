# -----------------------------------------------------------------------------
#
#   Windows Globus Build Script
#
#   12/12/2003 R. Gaffaney   Initial Creation          
#   01/03/2004 R. Gaffaney   Changes To Parser         
#   01/05/2004 R. Gaffaney   Output Batch File         
#   01/07/2004 R. Gaffaney   Handle DLLs               
#   01/26/2004 R. Gaffaney   DLL Export Logic          
#   02/02/2004 R. Gaffaney   Executable Logic          
#   02/17/2004 R. Gaffaney   wininclude_HEADERS        
#   02/17/2004 R. Gaffaney   Split Batch Files         
#   02/17/2004 R. Gaffaney   Split Log Files           
#   02/18/2004 R. Gaffaney   Log nmake Returns         
#   03/04/2004 R. Gaffaney   Unique Make Names         
#   04/01/2004 R. Gaffaney   DLL Export Issues         
#   12/07/2005 M. Colligan   Enhance log output        
#   12/08/2005 M. Colligan   Make make files pretty, add "Exclude" capability 
#   12/12/2005 M. Colligan   Consolidate duplicate code in subs 
#   01/31/2006 T. Wayne      Remove _MBCS compiler directive
#   02/10/2006 T. Wayne      Fixed lib output in exe log
#
# -----------------------------------------------------------------------------

# Directives
use warnings;
use strict;

# -----------------------------------------------------------------------------
#  Dont forget to update this variable when you change this script !!!
#  This info shows up in the generated BAT and MAK file headers.
# -----------------------------------------------------------------------------
my $WinCVSBuild_Version = "Version 2.5 10_Feb_2006";


# Globals
my $BaseSourcesName;
my @ProgramSources;
my $ProgramSourceCount;
my @ProgramDependencies;
my $ProgramDependencyCount;

my $FullSourcePath;
my $FullWin32Path;
my @SourceFiles;
my $SourceFileCount = 0;
my @HeaderFiles;
my $HeaderFileCount = 0;
my @WinSourceFiles;
my $WinSourceFileCount = 0;
my @WinHeaderFiles;
my $WinHeaderFileCount = 0;
my @WinExcludeFiles;
my $WinExcludeFileCount = 0;
my $BaseLibraryName;
my $FullLibraryName;
my @DLLExports;
my $DLLExportCount = 0;
my @DLLExportExclusions;
my $DLLExportExclusionCount = 0;
my @DLLDependency;
my $DLLDependencyCount = 0;


# Variables
my $ArgCount;
my $GlobusLocation;
my $VersionNumber;
my $FlavorName;
my $GlobusThreading;
my $BuildConfig;
my $LibraryType;
my $CRuntimeLib;
my $ModuleType;
my $SourceLocation;
my $Win32Location;
my $LibSuffix = "_Lib";
my $ExeSuffix = "_Exe";


# -----------------------------------------------------------------------------
# main()
# {

# Temp Variables
my @temp;
my $found;
my $record;


# ---------------------------
# Get Command Line Arguments
# ---------------------------

# Should Be Three Command Line Arguments
$ArgCount = $#ARGV + 1;
if($ArgCount != 3) {
    print "\nInvalid Command Line\n\n";
    print "   Format: WinCVSBuild GLOBUS_LOCATION WinFlavor \n\n";
    exit();
    }
    
# Grab The Command Line Parameters
$GlobusLocation = $ARGV[0];
$FlavorName = $ARGV[1];
$VersionNumber = $ARGV[2];
# ToDo: Confirm Values?

# Display Values
print "\nCommand Line Parameters:\n";
print "Globus Location:     ", $GlobusLocation, "\n";
print "Flavor Name:         ", $FlavorName, "\n";
print "Version Number:      ", $VersionNumber, "\n\n";


# ---------------------------------------
# Find The Flavor In The WinFlavors File
# ---------------------------------------

# Open The Flavors File
if(!open(FLAVORS,"WinFlavors")) {
    print "Can't Open Flavors File \"WinFlavors\"\n";    
    exit();
    }

# Try To Find The Flavor Entered On The Command Line
$found = 0;
while (<FLAVORS>) {
    # Kill EOL    
    chomp($_);
    
    # Check All Flavors
    if(/^FlavorName/) {
        @temp = split;
        
        # Capture Flavor List
        if($temp[1] eq $FlavorName) {
            # Got A Match
            $found = 1;
            
            # Capture Flavor Name
            $FlavorName = $temp[1];
            
            # Capture Globus Threading
            $record = <FLAVORS>;
            chomp $record;
            @temp = split / +/, $record;
            if($temp[0] eq "GlobusThreading") {
                $GlobusThreading = $temp[1];
                # ToDo: Should Verify Parameter Here
                }
            else {
                print "Globus Threading Parameter Not Found\n";
                exit();
                }

            # Capture Build Configuration
            $record = <FLAVORS>;
            chomp $record;
            @temp = split / +/, $record;
            if($temp[0] eq "BuildConfig") {
                $BuildConfig = $temp[1];
                # ToDo: Should Verify Parameter Here
                }
            else {
                print "Build Configuration Parameter Not Found\n";
                exit();
                }

            # Capture Library Type
            $record = <FLAVORS>;
            chomp $record;
            @temp = split / +/, $record;
            if($temp[0] eq "LibraryType") {
                $LibraryType = $temp[1];
                # ToDo: Should Verify Parameter Here
                }
            else {
                print "Library Type Parameter Not Found\n";
                exit();
                }

            # Capture C Runtime Library
            $record = <FLAVORS>;
            chomp $record;
            @temp = split / +/, $record;
            if($temp[0] eq "CRuntimeLib") {
                $CRuntimeLib = $temp[1];
                # ToDo: Should Verify Parameter Here
                }
            else {
                print "C Runtime Library Parameter Not Found\n";
                exit();
                }
            }
        } # FlavorName
    } # while <FLAVORS>

# Abort If No Valid Flavor
if($found eq 0) {
    print "No Valid Flavor Specified - See WinFlavors Defintion File\n";
    exit();
    }
else {
    print "Flavor Parameters:\n";
    print "Flavor Name:         ", $FlavorName, "\n";
    print "Globus Threading:    ", $GlobusThreading, "\n";
    print "Build Configuration: ", $BuildConfig, "\n";
    print "Library Type:        ", $LibraryType, "\n";
    print "C Runtime Library:   \/", $CRuntimeLib, "\n\n";
    }

# --------------------------------------------
# Create Batch Files To Execute The Makefiles
# --------------------------------------------

# Open\Create The Lib Batch File
if(!open (LIBBATCHEXEC,"> WinCVSBuildLibs\-$FlavorName.bat")) {
    print "Can't Open Batch File \"WinCVSBuildLibs\-$FlavorName.bat\"\n";    
    exit();
    }

# Write A Header To The Batch File
print LIBBATCHEXEC "\@echo off\n";
print LIBBATCHEXEC "rem ========================================================== \n";
print LIBBATCHEXEC "rem WinCVSBuildLibs\-$FlavorName.bat                           \n";
print LIBBATCHEXEC "rem                                                            \n";
print LIBBATCHEXEC "rem This file was generated by WinCVSBuild.pl                  \n";
print LIBBATCHEXEC "rem                                                            \n";
print LIBBATCHEXEC "rem $WinCVSBuild_Version                                       \n";
print LIBBATCHEXEC "rem                                                            \n";
print LIBBATCHEXEC "rem using Makefile.am and Winmake.am                           \n";
print LIBBATCHEXEC "rem ========================================================== \n";
print LIBBATCHEXEC "rem                                                            \n";
print LIBBATCHEXEC "\n";


# Write Header To The Log File
print LIBBATCHEXEC "echo ================================================================ \> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n";
print LIBBATCHEXEC "echo = BEGIN BATCH BUILD ============================================ \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n";
print LIBBATCHEXEC "echo ================================================================ \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n";
print LIBBATCHEXEC "\n";

# Open\Create The Lib Batch File
if(!open (EXEBATCHEXEC,"> WinCVSBuildExes\-$FlavorName.bat")) {
    print "Can't Open Batch File \"WinCVSBuildExes\-$FlavorName.bat\"\n";    
    exit();
    }

# Write A Header To The Batch File
print EXEBATCHEXEC "\@echo off\n";
print EXEBATCHEXEC "rem ========================================================== \n";
print EXEBATCHEXEC "rem WinCVSBuildExes\-$FlavorName.bat                           \n";
print EXEBATCHEXEC "rem                                                            \n";
print EXEBATCHEXEC "rem This file was generated by WinCVSBuild.pl                  \n";
print EXEBATCHEXEC "rem                                                            \n";
print EXEBATCHEXEC "rem $WinCVSBuild_Version                                       \n";
print EXEBATCHEXEC "rem                                                            \n";
print EXEBATCHEXEC "rem using Makefile.am and Winmake.am                           \n";
print EXEBATCHEXEC "rem ========================================================== \n";
print EXEBATCHEXEC "rem                                                            \n";
print EXEBATCHEXEC "\n";

# Write Header To The Log File
print EXEBATCHEXEC "echo ================================================================ \> $GlobusLocation\\core\\source\\win32\\$FlavorName$ExeSuffix.log\n";
print EXEBATCHEXEC "echo = BEGIN BATCH BUILD ============================================ \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$ExeSuffix.log\n";
print EXEBATCHEXEC "echo ================================================================ \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$ExeSuffix.log\n";
print EXEBATCHEXEC "\n";

# -------------------------------------
# Spin Through The Windows Modules File
# -------------------------------------

# Open The Modules File
if(!open(MODULES,"WinModules")) {
    print "Can't Open Modules File \"WinModules\"\n";
    exit(0);
    }

# Recurse The Modules File
while (<MODULES>) {
    # Kill EOL    
    chomp($_);
    
    # clear the globals contents
    @SourceFiles             = {};
    $SourceFileCount         = 0;
    @HeaderFiles             = {};
    $HeaderFileCount         = 0;
    @WinSourceFiles          = {};
    $WinSourceFileCount      = 0;
    @WinHeaderFiles          = {};
    $WinHeaderFileCount      = 0;
    @WinExcludeFiles         = {};
    $WinExcludeFileCount     = 0;
    @DLLExports              = {};
    $DLLExportCount          = 0;
    @DLLExportExclusions     = {};
    $DLLExportExclusionCount = 0;
    @DLLDependency           = {};
    $DLLDependencyCount      = 0;
    
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
            
        # Create The Makefile For This Module
        if($ModuleType eq "library") {
            print "Creating Makefile For Library Module At $SourceLocation\n";
            if($LibraryType eq "static") {
                CreateStaticLibMakeFile();
                }
            else {
                CreateDynamicLibMakeFile();
                }
            }
            
        # Executibles
        else {
            print "Creating Makefiles For Program Modules At $SourceLocation\n";
			ParseProgramMakeFile();
            }
        
        } # if ModuleType
    } # while <MODULES>

# Close the Modules File
close(MODULES);

# Go Back To The Script Home Directory
my $ScriptHomeDirectory = $GlobusLocation . "\\core\\source\\win32";
if(!chdir $ScriptHomeDirectory) {
    print "Can't Change Directory To ", $ScriptHomeDirectory, "\n";
    exit();
    }

# ---------------------------------------------
# Spin Through The Windows Modules File (Again)
# ---------------------------------------------

# Open The Modules File (Again)
if(!open(MODULES,"WinModules")) {
    print "Can't Open Modules File \"WinModules\"\n";
    exit(0);
    }

# Recurse The Modules File
# Note: This is the second the WinModules File - was easier than figuring out
#       how to do an array of structures in Perl on the first pass. This logic
#       should be fixed when time permits.
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
            
        # Execute The Makefile For This Module
        if($ModuleType eq "library") {
			ExecuteMakeFile();
            }
            
        # Programs Handled Above
        else {
            # (Scripts For Programs Are Created "In Line")
            }
        
        } # if ModuleType
    } # while <MODULES>
    
# Write Batch File Trailers
print LIBBATCHEXEC "echo ================================================================ \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n";
print LIBBATCHEXEC "echo = END LIB BATCH BUILD ========================================== \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n";
print LIBBATCHEXEC "echo ================================================================ \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n";
print LIBBATCHEXEC "\n";

print EXEBATCHEXEC "echo ================================================================ \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$ExeSuffix.log\n";
print EXEBATCHEXEC "echo = END EXE BATCH BUILD ========================================== \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$ExeSuffix.log\n";
print EXEBATCHEXEC "echo ================================================================ \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$ExeSuffix.log\n";
print EXEBATCHEXEC "\n";

# }
# End Of main()
# -----------------------------------------------------------------------------


# -------------------------------------------------------------------------------------
# CreateStaticLibMakeFile
#
# Build A Static Library Makefile
#
#   Note: This subroutine assumes one library module per Makefile.am.
#         This is currently true, but as Charles Bacon pointed out may
#         not be true forever.
#
# -------------------------------------------------------------------------------------
sub CreateStaticLibMakeFile 
{

# Temp Variables
my @stemp;
my $string;
my $i;
my $j;
my $Exclude;

    # Build Full Paths To Source And Win32 Directories
    $FullSourcePath = $GlobusLocation . $SourceLocation;
    $FullWin32Path = $GlobusLocation . $Win32Location;
    
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
    ParseMakefileam();
    # ------------------------------------------------------
    # ------------------------------------------------------

    #
    # Parse Winmake.am
    #
    ParseWinMakeamCommon();
    
        
    #
    # Create The Winmake.mak
    #
    
    # Open\Create The Makefile
    if(!open (WINMAKE,"> winmake_$FlavorName.mak")) {
        print "Can't Open Makefile \"winmake_$FlavorName.mak\"\n";    
        exit();
        }

    # Print A Header To The Makefile
    printMakeHeader();
    printExcludeFiles();

    # Predefined Constants
    print WINMAKE "CPP=cl.exe\n";
    if($BuildConfig eq "debug") {
        print WINMAKE "OUTDIR=.\\Debug\n";
        print WINMAKE "INTDIR=.\\Debug\n";
        }
    else {
        print WINMAKE "OUTDIR=.\\Release\n";
        print WINMAKE "INTDIR=.\\Release\n";
        }
    print WINMAKE "\n";

    # Build Full Library Name - Last field is Flavor name
    $FullLibraryName = $BaseLibraryName . $FlavorName;

    # Top Level Dependency - Note: Last field is Flavor Dependent
    print WINMAKE "# ================================================  \n";
    print WINMAKE "#                 ALL   \n";
    print WINMAKE "# ================================================  \n";
    print WINMAKE "ALL : \"\$(OUTDIR)\\$FullLibraryName.lib\"\n";
    print WINMAKE "\n";

    # Clean Build
    print WINMAKE "# ================================================  \n";
    print WINMAKE "#                 CLEAN   \n";
    print WINMAKE "# ================================================  \n";
    print WINMAKE "CLEAN :\n";
    
    # Makefile.am Files
    foreach  $i (@SourceFiles)  {
        # Split The Base name From The Suffix
        @stemp = split /\./,$i;
        
        # Only Make Entries For C Files
        if($stemp[1] eq "c" || $stemp[1] eq "C") {
       	    # Make Sure its not in WinExcludeFiles
            $Exclude = 0;
            foreach  $j (@WinExcludeFiles)  {
              	# Check For Exclusion
                if( $j eq $i ) {
                	$Exclude = 1;
                  last;
                }
            } # foreach  $j (@WinExcludeFiles)
                    
            # If Not Excluded, erase the object
            if(!$Exclude) {
                print WINMAKE "    \-\@ if exist \"\$(INTDIR)\\", $stemp[0], ".obj\" del /f /q \"\$(INTDIR)\\", $stemp[0], ".obj\" \n";
            } 
        }
    }
        
    # Winmake.am Files
    if($WinSourceFileCount) {
        foreach  $i (@WinSourceFiles)  {
            # Split The Base name From The Suffix
            @stemp = split /\./,$i;
            
            # Only Make Entries For C Files
            if($stemp[1] eq "c" || $stemp[1] eq "C") {
                print WINMAKE "    \-\@ if exist \"\$(INTDIR)\\", $stemp[0], ".obj\" del /f /q \"\$(INTDIR)\\", $stemp[0], ".obj\" \n";
                }
            }
        }
    print WINMAKE "\n";

    # Copy Header Files To \Include Directory, If Any
    print WINMAKE "# ================================================  \n";
    print WINMAKE "#                 COPY   \n";
    print WINMAKE "# ================================================  \n";
    print WINMAKE "COPY :\n";

    # Globus Global Header Files
    if($HeaderFileCount > 0) {
        foreach  $i (@HeaderFiles)  {
            print WINMAKE "    \-copy \"$i\" \"$GlobusLocation\\include\\*\.*\"\n";
            }
        }
        
    # Windows Global Header Files
    if($WinHeaderFileCount > 0) {
        foreach  $i (@WinHeaderFiles)  {
            print WINMAKE "    \-copy \"$FullWin32Path\\$i\" \"$GlobusLocation\\include\\*\.*\"\n";
            }
        }
    
    print WINMAKE "\n";

    # Create Output Directory If It Doesn't Exist
    print WINMAKE "# ================================================  \n";
    print WINMAKE "# Create Output Directory If It Doesn't Exist  \n";
    print WINMAKE "# ================================================  \n";
    print WINMAKE "\"\$\(OUTDIR\)\" : \n";
    print WINMAKE "    if not exist \"\$\(OUTDIR\)\/\$\(NULL\)\" mkdir \"\$\(OUTDIR\)\"\n";
    print WINMAKE "\n";

    # Determine Compile Options Per Flavor Spec
    my $IncludeString = "/I \"$GlobusLocation\\include\" /I \"$GlobusLocation\\include\\$GlobusThreading\" /I \"$FullWin32Path\" ";
    my $FlagsPre;
    my $FlagsPost;
    if($BuildConfig eq "debug") {
        $FlagsPre  = "/nologo /W3 /$CRuntimeLib /GX /Od /Gd /Z7 ";
        $FlagsPost = "/D \"WIN32\" /D \"_DEBUG\" /D \"_LIB\" /Fo\"\$\(INTDIR\)\\\\\" /Fd\"\$\(INTDIR\)\\\\\" /FD /GZ /c";
        }
     else {
        $FlagsPre  = "/nologo /$CRuntimeLib /W3 /GX /O2 /Gd ";
        $FlagsPost = "/D \"WIN32\" /D \"NDEBUG\" /D \"_LIB\" /Fo\"\$\(INTDIR\)\\\\\" /Fd\"\$\(INTDIR\)\\\\\" /FD /c";
        }

    # Create The Compile String
    print WINMAKE "# ================================================  \n";
    print WINMAKE "# Compile String   \n";
    print WINMAKE "# ================================================  \n";
    print WINMAKE "CPP_PROJ=", $FlagsPre, $IncludeString, $FlagsPost, "\n";
    print WINMAKE "\n";

    # Library
    print WINMAKE "# ================================================  \n";
    print WINMAKE "# Library   \n";
    print WINMAKE "# ================================================  \n";
    print WINMAKE "LIB32=link.exe \-lib\n";
    print WINMAKE "LIB32_FLAGS=/nologo /out:\"\$\(OUTDIR\)\\$FullLibraryName.lib\"\n";
    print WINMAKE "LIB32_OBJS=";
    
    # Makefile.am Files
    foreach  $i (@SourceFiles)  {
        # Split The Base name From The Suffix
        @stemp = split /\./,$i;

        # Only Make Entries For C Files
        if($stemp[1] eq "c" || $stemp[1] eq "C") {
            # ------------------------------------------
          	# Make Sure its not in WinExcludeFiles
            # ------------------------------------------
            $Exclude = 0;
            foreach  $j (@WinExcludeFiles)  {
              	# Check For Exclusion
                if( $j eq $i ) {
                   $Exclude = 1;
                   last; # get out
                }
            } # foreach  $j (@WinExcludeFiles)
                
            # If Not Excluded, build it
	    if(!$Exclude) {
               print WINMAKE " \\\n";
               print WINMAKE "    \"\$(INTDIR)\\", $stemp[0], ".obj\"";
       	    }
        }
    }
    # Winmake.am Files
    if($WinSourceFileCount) {
        foreach  $i (@WinSourceFiles)  {
            # Split The Base name From The Suffix
            @stemp = split /\./,$i;
            
            # Only Make Entries For C Files
            if($stemp[1] eq "c" || $stemp[1] eq "C") {
                print WINMAKE " \\\n";
                print WINMAKE "    \"\$(INTDIR)\\", $stemp[0], ".obj\"";
            }
        }
    }
    print WINMAKE "\n\n";

    # Link Dependencies
    print WINMAKE "# ================================================  \n";
    print WINMAKE "# Dependencies   \n";
    print WINMAKE "# ================================================  \n";
    print WINMAKE "\"\$\(OUTDIR\)\\$FullLibraryName.lib\" : \"\$\(OUTDIR\)\" \$\(DEF_FILE\) \$\(LIB32_OBJS\)\n";
    print WINMAKE "   \$\(LIB32\) \@\<\<\n";
    print WINMAKE "   \$\(LIB32_FLAGS\) \$\(DEF_FLAGS\) \$\(LIB32_OBJS\)\n";
    print WINMAKE "\<\<\n";
    print WINMAKE "\n";

    print WINMAKE "SOURCE=\"\$\(InputPath\)\"\n";
    print WINMAKE "DS_POSTBUILD_DEP=\$\(INTDIR\)\\postbld.dep\n";
    print WINMAKE "\n";

    print WINMAKE "ALL : \$\(DS_POSTBUILD_DEP\)\n";
    print WINMAKE "\n";

    print WINMAKE "\$\(DS_POSTBUILD_DEP\) : \"\$\(OUTDIR\)\\$FullLibraryName.lib\"\n";
    if($BuildConfig eq "debug") {
        print WINMAKE "    copy \$\(OUTDIR\)\\$FullLibraryName.lib $GlobusLocation\\lib\\*\.*\n";
        }
    else {
        print WINMAKE "    copy \$\(OUTDIR\)\\$FullLibraryName.lib $GlobusLocation\\lib\\*\.*\n";
        }
    print WINMAKE "\n";

    # Inferences
    print WINMAKE "# ================================================  \n";
    print WINMAKE "# Inferences   \n";
    print WINMAKE "# ================================================  \n";
    print WINMAKE "\.c{\$\(INTDIR\)}\.obj::\n";
    print WINMAKE "   \$\(CPP\) \@\<\<\n";
    print WINMAKE "   \$\(CPP_PROJ\) \$\<\n";
    print WINMAKE "\<\<\n";
    print WINMAKE "\n";

    print WINMAKE "\.c{\$\(INTDIR\)}\.sbr::\n";
    print WINMAKE "   \$\(CPP\) \@\<\<\n";
    print WINMAKE "   \$\(CPP_PROJ\) \$\<\n";
    print WINMAKE "\<\<\n";
    print WINMAKE "\n";

    # Compilation - Makefile.am Files
    print WINMAKE "# ================================================  \n";
    print WINMAKE "# Compilations from Makefile.am   \n";
    print WINMAKE "# ================================================  \n";
    foreach  $i (@SourceFiles)  {
        # Split The Base name From The Suffix
        @stemp = split /\./,$i;
        
        # Only Make Entries For C Files
        if($stemp[1] eq "c" || $stemp[1] eq "C") {
            # ------------------------------------------
          	# Make Sure its not in WinExcludeFiles
            # ------------------------------------------
            $Exclude = 0;
            foreach  $j (@WinExcludeFiles)  {
              	# Check For Exclusion
                if( $j eq $i ) {
                	$Exclude = 1;
                  last;
                }
            } # foreach  $j (@WinExcludeFiles)
                
      	    # If Not Excluded, build it
            if(!$Exclude) {
               print WINMAKE "SOURCE=$i\n";
               print WINMAKE "\"\$\(INTDIR\)\\$stemp[0].obj\" : \$\(SOURCE\) \"\$\(INTDIR\)\"\n";
               print WINMAKE "   \$\(CPP\) \$\(CPP_PROJ\) \$\(SOURCE\)\n\n";
            } else {
               print WINMAKE "# ================================================  \n";
               print WINMAKE "# Exclude exists in winmake.am $i \n";
               print WINMAKE "# SOURCE=$i\n";
               print WINMAKE "# \n";
               print WINMAKE "#      \"\$\(INTDIR\)\\$stemp[0].obj\" : \$\(SOURCE\) \"\$\(INTDIR\)\"\n";
               print WINMAKE "#         \$\(CPP\) \$\(CPP_PROJ\) \$\(SOURCE\)\n";
               print WINMAKE "# ================================================  \n\n";
            } # if(!$Exclude)
        }
    }
        
    # Compilation - Winmake.am Files
    print WINMAKE "# ================================================  \n";
    print WINMAKE "# Compilations from Winmake.am   \n";
    print WINMAKE "# ================================================  \n";
    if($WinSourceFileCount) {
        foreach  $i (@WinSourceFiles)  {
            # Split The Base name From The Suffix
            @stemp = split /\./,$i;
            
            # Only Make Entries For C Files
            if($stemp[1] eq "c" || $stemp[1] eq "C") {
                print WINMAKE "SOURCE=$FullWin32Path\\$i\n";
                print WINMAKE "\"\$\(INTDIR\)\\$stemp[0].obj\" : \$\(SOURCE\) \"\$\(INTDIR\)\"\n";
                print WINMAKE "   \$\(CPP\) \$\(CPP_PROJ\) \$\(SOURCE\)\n\n";
            }
        } # foreach  $i (@WinSourceFiles)
    } else {
       print WINMAKE "# NONE  \n";

    } # if($WinSourceFileCount)
} # CreateStaticLibMakeFile 
    
    
# -------------------------------------------------------------------------------------
# Build A Dynamic Library Makefile
#
#   Note: This subroutine assumes one library module per Makefile.am.
#         This is currently true, but may not be true forever.
#
#
#
#
# -------------------------------------------------------------------------------------
sub CreateDynamicLibMakeFile 
{

# Temp Variables
my @stemp;
my $string;
my $i;
my $j;
my $Exclude;

    # Build Full Paths To Source And Win32 Directories
    $FullSourcePath = $GlobusLocation . $SourceLocation;
    $FullWin32Path = $GlobusLocation . $Win32Location;
    
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
    ParseMakefileam();
    # ------------------------------------------------------
    # ------------------------------------------------------

    #
    # Parse Winmake.am
    #
    ParseWinMakeamCommon();
    ParseWinMakeamDLL();        
    #
    # Parse Winmake.exports
    #
    
    
    if(!open(EXPORTS,"$FullWin32Path\\Winmake.exports")) {
        # Not Fatal: Some Libraries May Not Have Exports At First
        # ToDo: Noisy - Remove This Later
        print "    Warning: No \"Winmake.exports\" in ", $FullWin32Path, " - Using default rules.\n";
        }

    # Spin Through Winmake.exports
    else {
        while (<EXPORTS>) {
          	# Initialize
            @stemp = {};
            @stemp = split;
            
            # Make Sure The Line Is Not Empty
            if($stemp[0]) {
             	  # Make Sure The Export Is Not In The Export Exclusion
                $Exclude = 0;
                foreach  $i (@DLLExportExclusions)  {
                	  # Check For Exclusioin
                    if($i eq $stemp[0]) {
                    	  $Exclude = 1;
                        last;
                    }
                } # ExportExclusions
                    
                # If Not Excluded Capture The Export
                if(!$Exclude) {
	                 $DLLExports[$DLLExportCount++] = $stemp[0];
                } # Not Excluded
						} # Not Empt+y
        } # while<EXPORTS>
            
        # Close Exports
        close(EXPORTS);
    } # else (open(EXPORTS))


    # Build Full Library Name - Last field is Flavor name
    $FullLibraryName = $BaseLibraryName . $FlavorName;
        
    #
    # Create The Definition File
    #
    
    # Open\Create The Def File
    if(!open (DEFFILE,"> $FullWin32Path\\$FullLibraryName.def")) {
        print "Can't Open Definition File \"$FullLibraryName.def\"\n";    
        exit();
        }
    
    # LIBRARY
    print DEFFILE "\nLIBRARY         $FullLibraryName.dll\n\n";

    # DESCRIPTION
    print DEFFILE "DESCRIPTION     'WinGlobus Dynamic Library \- http://www\.globus\.org/'\n\n";

    # EXPORTS
    print DEFFILE "EXPORTS\n";
    foreach  $i (@DLLExports)  {
        print DEFFILE "                $i\n";
        }
    print DEFFILE "\n\n";
    
    # Close The File
    close DEFFILE;
    
    #
    # Create The Winmake.mak
    #
    
    # Open\Create The Makefile
    if(!open (WINMAKE,"> winmake_$FlavorName.mak")) {
        print "Can't Open Makefile \"winmake_$FlavorName.mak\"\n";    
        exit();
        }

    # Print A Header To The Makefile
    printMakeHeader();
    printExcludeFiles();

    # Predefined Constants
    print WINMAKE "CPP=cl.exe\n";
    if($BuildConfig eq "debug") {
        print WINMAKE "OUTDIR=.\\Debug\n";
        print WINMAKE "INTDIR=.\\Debug\n";
        }
    else {
        print WINMAKE "OUTDIR=.\\Release\n";
        print WINMAKE "INTDIR=.\\Release\n";
        }
    print WINMAKE "\n";

    # Top Level Dependency - Note: Last field is Flavor Dependent
    print WINMAKE "# ================================================  \n";
    print WINMAKE "#                 ALL   \n";
    print WINMAKE "# ================================================  \n";
    print WINMAKE "ALL : \"\$(OUTDIR)\\$FullLibraryName.dll\"\n";
    print WINMAKE "\n";

    # Clean Build
    print WINMAKE "# ================================================  \n";
    print WINMAKE "#                 CLEAN   \n";
    print WINMAKE "# ================================================  \n";
    print WINMAKE "CLEAN :\n";
    
    # Makefile.am Files
    foreach  $i (@SourceFiles)  {
        # Split The Base name From The Suffix
        @stemp = split /\./,$i;
        
        # Only Make Entries For C Files
        if($stemp[1] eq "c" || $stemp[1] eq "C") {

       	    # Make Sure its not in WinExcludeFiles
            $Exclude = 0;
            foreach  $j (@WinExcludeFiles)  {
              	# Check For Exclusion
                if( $j eq $i ) {
                	$Exclude = 1;
                  last;
                }
            } # foreach  $j (@WinExcludeFiles)
                    
            # If Not Excluded, erase the object
            if(!$Exclude) {
                print WINMAKE "    \-\@ if exist \"\$(INTDIR)\\", $stemp[0], ".obj\" del /f /q \"\$(INTDIR)\\", $stemp[0], ".obj\" \n";
            } 

        } # if($stemp[1] eq "c" || $stemp[1] eq "C")

    } # foreach  $i (@SourceFiles)
        
    # Winmake.am Files
    if($WinSourceFileCount) {
        foreach  $i (@WinSourceFiles)  {
            # Split The Base name From The Suffix
            @stemp = split /\./,$i;
            
            # Only Make Entries For C Files
            if($stemp[1] eq "c" || $stemp[1] eq "C") {
                print WINMAKE "    \-\@ if exist \"\$(INTDIR)\\", $stemp[0], ".obj\" del /f /q \"\$(INTDIR)\\", $stemp[0], ".obj\" \n";
                }
            }
        }
    print WINMAKE "\n";


    # Copy Header Files To \Include Directory, If Any
    print WINMAKE "# ================================================  \n";
    print WINMAKE "#                 COPY   \n";
    print WINMAKE "# ================================================  \n";
    if($HeaderFileCount > 0 || $WinHeaderFileCount > 0) {
        print WINMAKE "COPY :\n";
        
        # Globus Global Header Files
        if($HeaderFileCount > 0) {
            foreach  $i (@HeaderFiles)  {
                print WINMAKE "    \-copy \"$i\" \"$GlobusLocation\\include\\*\.*\"\n";
                }
            }
            
        # Windows Global Header Files
        if($WinHeaderFileCount > 0) {
            foreach  $i (@WinHeaderFiles)  {
                print WINMAKE "    \-copy \"$FullWin32Path\\$i\" \"$GlobusLocation\\include\\*\.*\"\n";
                }
            }
            
        print WINMAKE "\n";
        }

    # Create Output Directory If It Doesn't Exist
    print WINMAKE "# ================================================  \n";
    print WINMAKE "# Create Output Directory If It Doesn't Exist  \n";
    print WINMAKE "# ================================================  \n";
    print WINMAKE "\"\$\(OUTDIR\)\" : \n";
    print WINMAKE "    if not exist \"\$\(OUTDIR\)\/\$\(NULL\)\" mkdir \"\$\(OUTDIR\)\"\n";
    print WINMAKE "\n";

    # Determine Compile Options Per Flavor Spec
    my $IncludeString = "/I \"$GlobusLocation\\include\" /I \"$GlobusLocation\\include\\$GlobusThreading\" /I \"$FullWin32Path\" ";
    my $FlagsPre;
    my $FlagsPost;
    if($BuildConfig eq "debug") {
        $FlagsPre  = "/nologo /W3 /$CRuntimeLib /GX /Od /Gd /Z7 ";
        $FlagsPost = "/D \"WIN32\" /D \"_DEBUG\" /D \"_USRDLL\" /D \"_WINDOWS\" /Fo\"\$\(INTDIR\)\\\\\" /Fd\"\$\(INTDIR\)\\\\\" /FD /GZ /c";
        }
     else {
        $FlagsPre  = "/nologo /$CRuntimeLib /W3 /GX /O2 /Gd ";
        $FlagsPost = "/D \"WIN32\" /D \"NDEBUG\" /D \"_USRDLL\" /D \"_WINDOWS\" /Fo\"\$\(INTDIR\)\\\\\" /Fd\"\$\(INTDIR\)\\\\\" /FD /c";
        }

    # Create The Compile String
    print WINMAKE "# ================================================  \n";
    print WINMAKE "# Compile String   \n";
    print WINMAKE "# ================================================  \n";
    print WINMAKE "CPP_PROJ=", $FlagsPre, $IncludeString, $FlagsPost, "\n";
    print WINMAKE "\n";

    # Temp Variables For Building Link Flags String
    my $LinkFlag0;
    my $LinkFlag1;
    my $LinkFlag2;
    my $LinkFlag3;
    my $LinkFlag4;

    # LINK32
    print WINMAKE "# ================================================  \n";
    print WINMAKE "# LINK32   \n";
    print WINMAKE "# ================================================  \n";
    print WINMAKE "LINK32=link.exe\n";
    
    # LINK32_FLAGS
    $LinkFlag0 = "";
    foreach  $i (@DLLDependency)  {
        $LinkFlag0.= "$i ";
        }
    if($BuildConfig eq "debug") {
        $LinkFlag1 = "/nologo /dll /pdb:none /debug /machine:I386";
        $LinkFlag3 = "/implib:\"\$\(OUTDIR\)\\$FullLibraryName.lib\"";
        }
    else {
        $LinkFlag1 = "/nologo /dll /machine:I386";
        $LinkFlag3 = "/implib:\"\$\(OUTDIR\)\\$FullLibraryName.lib\" /pdbtype:sept";
        }
    $LinkFlag2 = "/def:\"$FullWin32Path\\$FullLibraryName.def\"  /out:\"\$\(OUTDIR\)\\$FullLibraryName.dll\"";
    $LinkFlag4 = "/libpath:\"$GlobusLocation\\lib\"";


    print WINMAKE "# ================================================  \n";
    print WINMAKE "# LINK32_FLAGS   \n";
    print WINMAKE "# ================================================  \n";
    print WINMAKE "LINK32_FLAGS=$LinkFlag0 $LinkFlag1 $LinkFlag2 $LinkFlag3 $LinkFlag4\n";

    # DEF_FILE
    print WINMAKE "# ================================================  \n";
    print WINMAKE "# DEF_FILE   \n";
    print WINMAKE "# ================================================  \n";
    print WINMAKE "DEF_FILE=$FullWin32Path\\$BaseLibraryName$FlavorName.def\n";

    # LINK32_OBJS        
    print WINMAKE "# ================================================  \n";
    print WINMAKE "# LINK32_OBJS   \n";
    print WINMAKE "# ================================================  \n";
    print WINMAKE "LINK32_OBJS=";
    
    # Makefile.am Files
    foreach  $i (@SourceFiles)  {
        # Split The Base name From The Suffix
        @stemp = split /\./,$i;
        
        # Only Make Entries For C Files
        if($stemp[1] eq "c" || $stemp[1] eq "C") {

            # ------------------------------------------
          	# Make Sure its not in WinExcludeFiles
            # ------------------------------------------
            $Exclude = 0;
            foreach  $j (@WinExcludeFiles)  {
              	# Check For Exclusion
                if( $j eq $i ) {
                	$Exclude = 1;
                  last;
                }
            } # foreach  $j (@WinExcludeFiles)
                    
            # If Not Excluded, build it
            if(!$Exclude) {
                print WINMAKE " \\\n";
                print WINMAKE "    \"\$(INTDIR)\\", $stemp[0], ".obj\"";
            }
        }
    }
        
    # Winmake.am Files
    if($WinSourceFileCount) {
        foreach  $i (@WinSourceFiles)  {
            # Split The Base name From The Suffix
            @stemp = split /\./,$i;
            
            # Only Make Entries For C Files
            if($stemp[1] eq "c" || $stemp[1] eq "C") {
                print WINMAKE " \\\n";
                print WINMAKE "    \"\$(INTDIR)\\", $stemp[0], ".obj\"";
                }
            }
        }
    print WINMAKE "\n\n";

    # Link Dependencies
    print WINMAKE "# ================================================  \n";
    print WINMAKE "# Dependencies   \n";
    print WINMAKE "# ================================================  \n";
    print WINMAKE "\"\$\(OUTDIR\)\\$FullLibraryName.dll\" : \"\$\(OUTDIR\)\" \$\(DEF_FILE\) \$\(LINK32_OBJS\)\n";
    print WINMAKE "   \$\(LINK32\) \@\<\<\n";
    print WINMAKE "   \$\(LINK32_FLAGS\) \$\(DEF_FLAGS\) \$\(LINK32_OBJS\)\n";
    print WINMAKE "\<\<\n";
    print WINMAKE "\n";

    print WINMAKE "SOURCE=\"\$\(InputPath\)\"\n";
    print WINMAKE "DS_POSTBUILD_DEP=\$\(INTDIR\)\\postbld.dep\n";
    print WINMAKE "\n";

    print WINMAKE "ALL : \$\(DS_POSTBUILD_DEP\)\n";
    print WINMAKE "\n";

    print WINMAKE "\$\(DS_POSTBUILD_DEP\) : \"\$\(OUTDIR\)\\$FullLibraryName.lib\"\n";
    print WINMAKE "    copy \$\(OUTDIR\)\\$FullLibraryName.lib $GlobusLocation\\lib\\*\.*\n";
    print WINMAKE "    copy \$\(OUTDIR\)\\$FullLibraryName.dll $GlobusLocation\\bin\\*\.*\n";
    print WINMAKE "\n";

    # Inferences
    print WINMAKE "# ================================================  \n";
    print WINMAKE "# Inferences   \n";
    print WINMAKE "# ================================================  \n";
    print WINMAKE "\.c{\$\(INTDIR\)}\.obj::\n";
    print WINMAKE "   \$\(CPP\) \@\<\<\n";
    print WINMAKE "   \$\(CPP_PROJ\) \$\<\n";
    print WINMAKE "\<\<\n";
    print WINMAKE "\n";

    print WINMAKE "\.c{\$\(INTDIR\)}\.sbr::\n";
    print WINMAKE "   \$\(CPP\) \@\<\<\n";
    print WINMAKE "   \$\(CPP_PROJ\) \$\<\n";
    print WINMAKE "\<\<\n";
    print WINMAKE "\n";

    # Compilation - Makefile.am Files
    print WINMAKE "# ================================================  \n";
    print WINMAKE "# Compilations from Makefile.am   \n";
    print WINMAKE "# ================================================  \n";
    foreach  $i (@SourceFiles)  {
        # Split The Base name From The Suffix
        @stemp = split /\./,$i;
        
        # Only Make Entries For C Files
        if($stemp[1] eq "c" || $stemp[1] eq "C") {
            # ------------------------------------------
          	# Make Sure its not in WinExcludeFiles
            # ------------------------------------------
            $Exclude = 0;
            foreach  $j (@WinExcludeFiles)  {
              	# Check For Exclusion
                if( $j eq $i ) {
                	$Exclude = 1;
                  last;
                }
            } # foreach  $j (@WinExcludeFiles)
                
       	    # If Not Excluded, build it
      	    if(!$Exclude) {
               print WINMAKE "SOURCE=$i\n\n";
               print WINMAKE "\"\$\(INTDIR\)\\$stemp[0].obj\" : \$\(SOURCE\) \"\$\(INTDIR\)\"\n";
               print WINMAKE "   \$\(CPP\) \$\(CPP_PROJ\) \$\(SOURCE\)\n\n";
       	    } else {
               print WINMAKE "# ================================================  \n";
               print WINMAKE "# Exclude exists in winmake.am $i \n";
               print WINMAKE "# SOURCE=$i\n";
               print WINMAKE "# \n";
               print WINMAKE "#      \"\$\(INTDIR\)\\$stemp[0].obj\" : \$\(SOURCE\) \"\$\(INTDIR\)\"\n";
               print WINMAKE "#         \$\(CPP\) \$\(CPP_PROJ\) \$\(SOURCE\)\n";
               print WINMAKE "# ================================================  \n\n";
     	    }

        } # if($stemp[1] eq "c" || $stemp[1] eq "C")
        
    # Compilation - Winmake.am Files
    print WINMAKE "# ================================================  \n";
    print WINMAKE "# Compilations from Winmake.am   \n";
    print WINMAKE "# ================================================  \n";
    if($WinSourceFileCount) {
        foreach  $i (@WinSourceFiles)  {
            # Split The Base name From The Suffix
            @stemp = split /\./,$i;
            
            # Only Make Entries For C Files
            if($stemp[1] eq "c" || $stemp[1] eq "C") {
                print WINMAKE "SOURCE=$FullWin32Path\\$i\n\n";
                print WINMAKE "\"\$\(INTDIR\)\\$stemp[0].obj\" : \$\(SOURCE\) \"\$\(INTDIR\)\"\n";
                print WINMAKE "   \$\(CPP\) \$\(CPP_PROJ\) \$\(SOURCE\)\n\n";
            }
        }
    } else {
       print WINMAKE "# NONE  \n";

    }
  }       
} # CreateDynamicLibMakeFile 

# -------------------------------------------------------------------------------------
# ExecuteMakeFile
#
#
#
# -------------------------------------------------------------------------------------
sub ExecuteMakeFile
{
my @nmakeCall;

    # Change The Working Directory To That Of The Target Makefile
    print LIBBATCHEXEC "echo ================================================================\n";
    print LIBBATCHEXEC "echo == Library                                                      \n";
    print LIBBATCHEXEC "echo ==                                                              \n";
    print LIBBATCHEXEC "echo == $SourceLocation                                              \n";
    print LIBBATCHEXEC "echo ==                                                              \n";
    print LIBBATCHEXEC "echo ==                                                              \n";
    print LIBBATCHEXEC "echo ================================================================\n\n";
    print LIBBATCHEXEC "echo ================================================================\>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n";
    print LIBBATCHEXEC "echo == Library                                                      \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n";
    print LIBBATCHEXEC "echo ==                                                              \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n";
    print LIBBATCHEXEC "echo == $SourceLocation                                              \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n";
    print LIBBATCHEXEC "echo ==                                                              \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n";
    print LIBBATCHEXEC "echo ==                                                              \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n";
    print LIBBATCHEXEC "echo ================================================================\>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n\n";
    print LIBBATCHEXEC "CD $GlobusLocation$SourceLocation\n";
        
    # Embed Leader For This Makefile
    print LIBBATCHEXEC "echo BEGIN nmake $SourceLocation\\winmake_$FlavorName.mak             \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n";
    print LIBBATCHEXEC "echo  BEGIN nmake $SourceLocation\\winmake_$FlavorName.mak            \n";
    
    # Execute The Makefile
    print LIBBATCHEXEC "echo       ---------------------------------------------------------- \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n";
    print LIBBATCHEXEC "echo       NMAKE CLEAN                                                \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n";
    print LIBBATCHEXEC "echo       ---------------------------------------------------------- \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n";
    print LIBBATCHEXEC "echo       ---------------------------------------------------------- \n";
    print LIBBATCHEXEC "echo       NMAKE CLEAN                                                \n";
    print LIBBATCHEXEC "echo       ---------------------------------------------------------- \n";
    print LIBBATCHEXEC "nmake /F winmake_$FlavorName.mak CLEAN \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n";

    print LIBBATCHEXEC "echo       ---------------------------------------------------------- \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n";
    print LIBBATCHEXEC "echo       NMAKE COPY                                                 \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n";
    print LIBBATCHEXEC "echo       ---------------------------------------------------------- \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n";
    print LIBBATCHEXEC "echo       ---------------------------------------------------------- \n";
    print LIBBATCHEXEC "echo       NMAKE COPY                                                 \n";
    print LIBBATCHEXEC "echo       ---------------------------------------------------------- \n";
    print LIBBATCHEXEC "nmake /F winmake_$FlavorName.mak COPY  \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n";

    print LIBBATCHEXEC "echo       ---------------------------------------------------------- \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n";
    print LIBBATCHEXEC "echo       NMAKE ALL                                                  \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n";
    print LIBBATCHEXEC "echo       ---------------------------------------------------------- \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n";
    print LIBBATCHEXEC "echo       ---------------------------------------------------------- \n";
    print LIBBATCHEXEC "echo       NMAKE ALL                                                  \n";
    print LIBBATCHEXEC "echo       ---------------------------------------------------------- \n";
    print LIBBATCHEXEC "nmake /F winmake_$FlavorName.mak ALL   \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$LibSuffix.log\n";
    
    # Report Build Results (from nmake ALL Only)
    print LIBBATCHEXEC "if NOT ERRORLEVEL 1 echo SUCCEEDED - $FlavorName Library At: $SourceLocation \>\> $GlobusLocation\\core\\source\\win32\\BuildResults.log\n\n";
    #print LIBBATCHEXEC "if NOT ERRORLEVEL 1 echo SUCCEEDED - $FlavorName Library At: $SourceLocation \n\n";
    print LIBBATCHEXEC "if ERRORLEVEL 1 echo FAILED    - $FlavorName Library At: $SourceLocation - nmake Return: %ERRORLEVEL% \>\> $GlobusLocation\\core\\source\\win32\\BuildResults.log\n\n";
    #print LIBBATCHEXEC "if ERRORLEVEL 1 echo FAILED    - $FlavorName Library At: $SourceLocation - nmake Return: %ERRORLEVEL% \n\n";
    
    # Change The Working Directory To The 'Home' Directory
    print LIBBATCHEXEC "CD $GlobusLocation\\core\\source\\win32\n";
    print LIBBATCHEXEC "\n";
} # ExecuteMakeFile


# -------------------------------------------------------------------------------------
# ParseProgramMakeFile
#
# Parse A Program Makefile (These Can Contain Multiple Programs)
#
#    Note: This Routine Parses Makefile.am And Creates A Makefile For Each Executable In The File
#
#
#
# -------------------------------------------------------------------------------------
sub ParseProgramMakeFile 
{
my $FullSourcePath;
my $FullWin32Path;
my $Continue;
my @ProgramNames;
my $ProgramCount;

# Temp Variables
my @stemp;
my @stemp1;
my $i;

    # Build Full Paths To Source And Win32 Directories
    $FullSourcePath = $GlobusLocation . $SourceLocation;
    $FullWin32Path = $GlobusLocation . $Win32Location;

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

    # Initialize Variables
    @ProgramSources         = {};
    $ProgramSourceCount     = 0;
    @ProgramDependencies    = {};
    $ProgramDependencyCount = 0;
        
    #
    # Parse Winmake.am 
    #
    # Library Dependencies Are Needed. Note: All Programs In Makefile.am Use
    # The Same Libraries.
    #
    if(!open(WINMAKE_AM,"$FullWin32Path\\Winmake.am")) {
        print "Unable To Open \"Winmake.am\" in ", $FullWin32Path, "\n";
        # ToDo: This Is A Critical Error, Exit
        }

    # Spin Through Winmake.am
    else {
        while (<WINMAKE_AM>) {
            # Capture Library Dependencies
            if(/^LibDependencies/) {
                # Note: Winmake.am Does Not Allow A .Lib On The 'LibDependencies=' Line
            
                # Collect The Libs In The Block
                while(<WINMAKE_AM>) {
                    # Substitute For $(GLOBUS_FLAVOR_NAME) If Necessary
                    s/\$\(GLOBUS_FLAVOR_NAME\)/$FlavorName/;
                
                    # Split The Arguments
                    @stemp = {};
                    @stemp = split;
                    
                    # Capture Export
                    $ProgramDependencies[$ProgramDependencyCount++] = $stemp[0];

                    # Exit When No Trailing Continuation Symbol \
                    if(!/\\/) {
                        last;
                        }
                    } # while<WINMAKE_AM>
                } # if LibDependencies
            
            # Handle Program Only Lib Dependencies
            if(/^ProgramLibDependencies/) {
                # Note: Winmake.am Does Not Allow A .Lib On The 'ProgramLibDependencies=' Line
            
                # Collect The Libs In The Block
                while(<WINMAKE_AM>) {
                    # Substitute For $(GLOBUS_FLAVOR_NAME) If Necessary
                    s/\$\(GLOBUS_FLAVOR_NAME\)/$FlavorName/;
                
                    # Split The Arguments
                    @stemp = {};
                    @stemp = split;
                    
                    # Capture Export
                    $ProgramDependencies[$ProgramDependencyCount++] = $stemp[0];

                    # Exit When No Trailing Continuation Symbol \
                    if(!/\\/) {
                        last;
                        }
                    } # while<WINMAKE_AM>
                } # if ProgramLibDependencies
            
            } # while<WINMAKE_AM>
        } # else (open(WINMAKE_AM))

    #
    # Parse Makefile.am
    #
    $ProgramCount = 0;
    @ProgramNames = {};
    while (<MAKEFILE_AM>) {
        # Note: We Need To Create A Makefile For Every Executable. First We 
        #  	    Collect All _PROGRAMS, Then As We Find _SOURCES, We Match
        #       Them Up With A Program And Create A Makefile With The 
        #       Same Name As The Program
    
        # Capture Program File Names
        if((/_PROGRAMS/) && !(/#/)) {
            # Split The Arguments
            @stemp = split;
           
            # Capture Programs On This Line (If Any)
            $Continue = 0;
            foreach  $i (@stemp)  {
            	if($i eq "\\") {
             	    $Continue = 1;
                    }
                elsif(($i ne "\=") && ($i !~ /_PROGRAMS/)) {
                    # Replace All Dashes With Underscores
                    $i =~ s/\-/_/g;

                	# Capture Program Name
                    $ProgramNames[$ProgramCount++] = $i;
                    }
                }
                
            # Collect Programs In This Block
            if($Continue == 1) {
                while(<MAKEFILE_AM>) {
                    # Split The Arguments
                    @stemp = {};
                    @stemp = split;
                    
                    # Capture Programs On This Line (If Any)
                    foreach  $i (@stemp)  {
                    	if($i !~ /\\/) {
                            # Replace All Dashes With Underscores
                            $i =~ s/\-/_/g;

                	        # Capture Program Name
                            $ProgramNames[$ProgramCount++] = $i;
                            }
                        }
                        
                    # Exit When No Trailing Continuation Symbol \
                    if(!/\\/) {
                        last;
                        }
                    } # while<MAKEFILE.AM>
                }
            }
            
        # Capture Program Source
        if((/_SOURCES/) && !(/^#/)) {
            # Clear Out Sources Context
            @ProgramSources = {};
            $ProgramSourceCount = 0;
            
            # Split The Arguments
            @stemp = {};
            @stemp = split;
           
            # Capture Programs On This Line (If Any)
            $Continue = 0;
            foreach  $i (@stemp)  {
                # Continuation
            	if($i eq "\\") {
             	    $Continue = 1;
                    }
                    
                # _SOURCES Statement
                elsif($i =~ /_SOURCES/) {
                    @stemp1 = split /_SOURCES/,$i;
                    $BaseSourcesName = $stemp1[0];
                	}
                    
                # Source Line
                elsif($i ne "\=" & $i !~ /^\$\(/) {
                    # Capture Source
                    $ProgramSources[$ProgramSourceCount++] = $i;
                    }
                }
                
            # Collect Sources In This Block
            if($Continue == 1) {
                while(<MAKEFILE_AM>) {
                    # Split The Arguments
                    @stemp = {};
                    @stemp = split;
                    
                    # Capture Programs On This Line (If Any)
                    foreach  $i (@stemp)  {
                    	if($i !~ /\\/ & $i !~ /^\$\(/) {
                            # Capture Source
                            $ProgramSources[$ProgramSourceCount++] = $i;
                            }
                        }
                        
                    # Exit When No Trailing Continuation Symbol \
                    if(!/\\/) {
                        last;
                        }
                    } # while<MAKEFILE.AM>
                }

            # Find The Program That Owns This Source List
            foreach $i (@ProgramNames) {
                if($BaseSourcesName eq $i) {
                    # Create The Makefile For This Program
                    CreateProgramMakefile();
                    }
                }
            }
            
        } # while <MAKEFILE_AM>
    
} # ParseProgramMakeFile

# -------------------------------------------------------------------------------------
# CreateProgramMakefile
#
# Create A Makefile For One Of The Programs In Makefile.am
#
# -------------------------------------------------------------------------------------
sub CreateProgramMakefile
{
# Temp Variables
my $FullSourcePath;
my $FullWin32Path;
my @stemp;
my $i;

    # Build Full Paths To Source And Win32 Directories
    $FullSourcePath = $GlobusLocation . $SourceLocation;
    $FullWin32Path = $GlobusLocation . $Win32Location;
    
    #
    # Create The Program Makefile
    #
    
    # Open\Create The Makefile
    if(!open (PROGRAM_MAKE,"> $BaseSourcesName\-$FlavorName.mak")) {
        print "Can't Open Makefile \"$BaseSourcesName\-$FlavorName.mak\"\n";    
        exit();
        }

    # Print A Header To The Makefile
    print PROGRAM_MAKE "# ========================================================== \n";
    print PROGRAM_MAKE "# $BaseSourcesName\-$FlavorName.mak                          \n";
    print PROGRAM_MAKE "#                                                            \n";
    print PROGRAM_MAKE "# This file was generated by WinCVSBuild.pl                  \n";
    print PROGRAM_MAKE "#                                                            \n";
    print PROGRAM_MAKE "# $WinCVSBuild_Version                                       \n";
    print PROGRAM_MAKE "#                                                            \n";
    print PROGRAM_MAKE "# using Makefile.am and Winmake.am                           \n";
    print PROGRAM_MAKE "# ========================================================== \n";
    print PROGRAM_MAKE "#                                                            \n";
    print PROGRAM_MAKE "\n";

    # Predefined Constants
    print PROGRAM_MAKE "CPP=cl.exe\n";
    if($BuildConfig eq "debug") {
        print PROGRAM_MAKE "OUTDIR=.\\Debug\n";
        print PROGRAM_MAKE "INTDIR=.\\Debug\n";
        }
    else {
        print PROGRAM_MAKE "OUTDIR=.\\Release\n";
        print PROGRAM_MAKE "INTDIR=.\\Release\n";
        }
    print PROGRAM_MAKE "\n";

    # Top Level Dependency - Note: Last field is Flavor Dependent
    print PROGRAM_MAKE "ALL : \"\$(OUTDIR)\\$BaseSourcesName.exe\"\n";
    print PROGRAM_MAKE "\n";

    # Clean Build
    print PROGRAM_MAKE "CLEAN :\n";
    
    # Executable
    print PROGRAM_MAKE "    \-\@ if exist \"\$(INTDIR)\\", $BaseSourcesName, ".exe\" del /f /q \"\$(INTDIR)\\", $BaseSourcesName, ".exe\" \n";
    
    # Source Files
    foreach  $i (@ProgramSources)  {
        # Split The Base name From The Suffix
        @stemp = split /\./,$i;
        
        # Only Make Entries For C Files
        if($stemp[1] eq "c" || $stemp[1] eq "C") {
            print PROGRAM_MAKE "    \-\@ if exist \"\$(INTDIR)\\", $stemp[0], ".obj\" del /f /q \"\$(INTDIR)\\", $stemp[0], ".obj\" \n";
            }
        }
    print PROGRAM_MAKE "\n";

    # Create Output Directory If It Doesn't Exist
    print PROGRAM_MAKE "\"\$\(OUTDIR\)\" : \n";
    print PROGRAM_MAKE "    if not exist \"\$\(OUTDIR\)\/\$\(NULL\)\" mkdir \"\$\(OUTDIR\)\"\n";
    print PROGRAM_MAKE "\n";

    # Determine Compile Options Per Flavor Spec
    my $IncludeString = "/I \"$GlobusLocation\\include\" /I \"$GlobusLocation\\include\\$GlobusThreading\" /I \"$FullWin32Path\" ";
    my $FlagsPre;
    my $FlagsPost;
    if($BuildConfig eq "debug") {
        $FlagsPre  = "/nologo /W3 /$CRuntimeLib /GX /Od /Gd /Z7 ";
        $FlagsPost = "/D \"WIN32\" /D \"_DEBUG\" /D \"_CONSOLE\" /D \"_WINDOWS\" /Fo\"\$\(INTDIR\)\\\\\" /Fd\"\$\(INTDIR\)\\\\\" /FD /GZ /c";
        }
     else {
        $FlagsPre  = "/nologo /$CRuntimeLib /W3 /GX /O2 /Gd ";
        $FlagsPost = "/D \"WIN32\" /D \"NDEBUG\" /D \"_CONSOLE\" /D \"_WINDOWS\" /Fo\"\$\(INTDIR\)\\\\\" /Fd\"\$\(INTDIR\)\\\\\" /FD /c";
        }

    # Create The Compile String
    print PROGRAM_MAKE "CPP_PROJ=", $FlagsPre, $IncludeString, $FlagsPost, "\n";
    print PROGRAM_MAKE "\n";
    
    # Temp Variables For Building Link Flags String
    my $LinkFlag0;
    my $LinkFlag1;
    my $LinkFlag2;
    my $LinkFlag3;
    my $LinkFlag4;

    # LINK32
    print PROGRAM_MAKE "LINK32=link.exe\n";
    
    # LINK32_FLAGS
    $LinkFlag0 = "";
    foreach  $i (@ProgramDependencies)  {
        $LinkFlag0.= "$i ";
        }
    if($BuildConfig eq "debug") {
        $LinkFlag1 = "/nologo /subsystem:console /incremental:no /pdb:none /debug /machine:I386";
        $LinkFlag3 = "";
        }
    else {
        $LinkFlag1 = "/nologo /subsystem:console /incremental:no /machine:I386";
        $LinkFlag3 = "/pdbtype:sept";
        }
    $LinkFlag2 = "/out:\"\$\(OUTDIR\)\\$BaseSourcesName.exe\"";
    $LinkFlag4 = "/libpath:\"$GlobusLocation\\lib\"";
    print PROGRAM_MAKE "LINK32_FLAGS=$LinkFlag0 $LinkFlag1 $LinkFlag2 $LinkFlag3 $LinkFlag4\n";

    # LINK32_OBJS        
    print PROGRAM_MAKE "LINK32_OBJS=";
    
    # Makefile.am Files
    foreach  $i (@ProgramSources)  {
        # Split The Base name From The Suffix
        @stemp = split /\./,$i;
        
        # Only Make Entries For C Files
        if($stemp[1] eq "c" || $stemp[1] eq "C") {
            print PROGRAM_MAKE " \\\n";
            print PROGRAM_MAKE "    \"\$(INTDIR)\\", $stemp[0], ".obj\"";
            }
        }
    print PROGRAM_MAKE "\n\n";

    # Link Dependencies
    print PROGRAM_MAKE "\"\$\(OUTDIR\)\\$BaseSourcesName.exe\" : \"\$\(OUTDIR\)\" \$\(DEF_FILE\) \$\(LINK32_OBJS\)\n";
    print PROGRAM_MAKE "   \$\(LINK32\) \@\<\<\n";
    print PROGRAM_MAKE "   \$\(LINK32_FLAGS\) \$\(DEF_FLAGS\) \$\(LINK32_OBJS\)\n";
    print PROGRAM_MAKE "\<\<\n";
    print PROGRAM_MAKE "\n";

    print PROGRAM_MAKE "SOURCE=\"\$\(InputPath\)\"\n";
    print PROGRAM_MAKE "DS_POSTBUILD_DEP=\$\(INTDIR\)\\postbld.dep\n";
    print PROGRAM_MAKE "\n";

    print PROGRAM_MAKE "ALL : \$\(DS_POSTBUILD_DEP\)\n";
    print PROGRAM_MAKE "\n";

    print PROGRAM_MAKE "\$\(DS_POSTBUILD_DEP\) : \"\$\(OUTDIR\)\\$BaseSourcesName.exe\"\n";
    print PROGRAM_MAKE "    if not exist \"\$\(OUTDIR\)\/\$\(NULL\)\" mkdir \"\$\(OUTDIR\)\"\n";
    print PROGRAM_MAKE "    if not exist $GlobusLocation\\bin\\$FlavorName mkdir $GlobusLocation\\bin\\$FlavorName\n";
    print PROGRAM_MAKE "    copy \$\(OUTDIR\)\\$BaseSourcesName.exe $GlobusLocation\\bin\\$FlavorName\\*\.*\n";
    print PROGRAM_MAKE "\n";

    # Inferences
    print PROGRAM_MAKE "\.c{\$\(INTDIR\)}\.obj::\n";
    print PROGRAM_MAKE "   \$\(CPP\) \@\<\<\n";
    print PROGRAM_MAKE "   \$\(CPP_PROJ\) \$\<\n";
    print PROGRAM_MAKE "\<\<\n";
    print PROGRAM_MAKE "\n";

    print PROGRAM_MAKE "\.c{\$\(INTDIR\)}\.sbr::\n";
    print PROGRAM_MAKE "   \$\(CPP\) \@\<\<\n";
    print PROGRAM_MAKE "   \$\(CPP_PROJ\) \$\<\n";
    print PROGRAM_MAKE "\<\<\n";
    print PROGRAM_MAKE "\n";

    # Compilation - Makefile.am Files
    foreach  $i (@ProgramSources)  {
        # Split The Base name From The Suffix
        @stemp = split /\./,$i;
        
        # Only Make Entries For C Files
        if($stemp[1] eq "c" || $stemp[1] eq "C") {
            print PROGRAM_MAKE "SOURCE=$i\n\n";
            print PROGRAM_MAKE "\"\$\(INTDIR\)\\$stemp[0].obj\" : \$\(SOURCE\) \"\$\(INTDIR\)\"\n";
            print PROGRAM_MAKE "   \$\(CPP\) \$\(CPP_PROJ\) \$\(SOURCE\)\n\n";
            }
        }

    # Change The Working Directory To That Of The Target Makefile
    print EXEBATCHEXEC "echo ================================================================\n";
    print EXEBATCHEXEC "echo == Program                                                      \n";
    print EXEBATCHEXEC "echo ==                                                              \n";
    print EXEBATCHEXEC "echo == $SourceLocation                                              \n";
    print EXEBATCHEXEC "echo ==                                                              \n";
    print EXEBATCHEXEC "echo ==                                                              \n";
    print EXEBATCHEXEC "echo ================================================================\n\n";
    print EXEBATCHEXEC "echo ================================================================\>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$ExeSuffix.log\n";
    print EXEBATCHEXEC "echo == Program                                                      \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$ExeSuffix.log\n";
    print EXEBATCHEXEC "echo ==                                                              \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$ExeSuffix.log\n";
    print EXEBATCHEXEC "echo == $SourceLocation                                              \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$ExeSuffix.log\n";
    print EXEBATCHEXEC "echo ==                                                              \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$ExeSuffix.log\n";
    print EXEBATCHEXEC "echo ==                                                              \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$ExeSuffix.log\n";
    print EXEBATCHEXEC "echo ================================================================\>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$ExeSuffix.log\n\n";
    print EXEBATCHEXEC "CD $GlobusLocation$SourceLocation\n";
        
    # Embed Leader For This Makefile
    print EXEBATCHEXEC "echo BEGIN nmake $SourceLocation\\$BaseSourcesName\-$FlavorName.mak   \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$ExeSuffix.log\n";
    print EXEBATCHEXEC "echo BEGIN nmake $SourceLocation\\$BaseSourcesName\-$FlavorName.mak  \n";

    # Execute The Makefile
    print EXEBATCHEXEC "echo       ---------------------------------------------------------- \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$ExeSuffix.log\n";
    print EXEBATCHEXEC "echo       NMAKE CLEAN                                                \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$ExeSuffix.log\n";
    print EXEBATCHEXEC "echo       ---------------------------------------------------------- \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$ExeSuffix.log\n";
    print EXEBATCHEXEC "echo       ---------------------------------------------------------- \n";
    print EXEBATCHEXEC "echo       NMAKE CLEAN                                                \n";
    print EXEBATCHEXEC "echo       ---------------------------------------------------------- \n";
    print EXEBATCHEXEC "nmake /F $BaseSourcesName\-$FlavorName.mak CLEAN \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$ExeSuffix.log\n";

    print EXEBATCHEXEC "echo       ---------------------------------------------------------- \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$ExeSuffix.log\n";
    print EXEBATCHEXEC "echo       NMAKE ALL                                                  \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$ExeSuffix.log\n";
    print EXEBATCHEXEC "echo       ---------------------------------------------------------- \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$ExeSuffix.log\n";
    print EXEBATCHEXEC "echo       ---------------------------------------------------------- \n";
    print EXEBATCHEXEC "echo       NMAKE ALL                                                  \n";
    print EXEBATCHEXEC "echo       ---------------------------------------------------------- \n";
    print EXEBATCHEXEC "nmake /F $BaseSourcesName\-$FlavorName.mak ALL   \>\> $GlobusLocation\\core\\source\\win32\\$FlavorName$ExeSuffix.log\n";
    
    # Report Build Results (from nmake ALL Only)
    print EXEBATCHEXEC "if NOT ERRORLEVEL 1 echo SUCCEEDED - $FlavorName Executable: .\\$FlavorName\\$BaseSourcesName.exe \>\> $GlobusLocation\\core\\source\\win32\\BuildResults.log\n\n";
    print EXEBATCHEXEC "if NOT ERRORLEVEL 1 echo SUCCEEDED - $FlavorName Executable: .\\$FlavorName\\$BaseSourcesName.exe \n\n";
    print EXEBATCHEXEC "if ERRORLEVEL 1 echo FAILED    - $FlavorName Executable: .\\$FlavorName\\$BaseSourcesName.exe - nmake Return: %ERRORLEVEL%  \>\> $GlobusLocation\\core\\source\\win32\\BuildResults.log\n\n";
    print EXEBATCHEXEC "if ERRORLEVEL 1 echo FAILED    - $FlavorName Executable: .\\$FlavorName\\$BaseSourcesName.exe - nmake Return: %ERRORLEVEL%  \n\n";
    
    # Change The Working Directory To The 'Home' Directory
    print EXEBATCHEXEC "CD $GlobusLocation\\core\\source\\win32\n";
    print EXEBATCHEXEC "\n";
} # CreateProgramMakefile

# -------------------------------------------------------------------------------------
# printMakeHeader
#
#
#
#
#
#
#
# -------------------------------------------------------------------------------------
sub printMakeHeader {
    print WINMAKE "# ========================================================== \n";
    print WINMAKE "# winmake_$FlavorName.mak                                    \n";
    print WINMAKE "#                                                            \n";
    print WINMAKE "# This file was generated by WinCVSBuild.pl                  \n";
    print WINMAKE "#                                                            \n";
    print WINMAKE "# $WinCVSBuild_Version                                       \n";
    print WINMAKE "#                                                            \n";
    print WINMAKE "# using Makefile.am and Winmake.am                           \n";
    print WINMAKE "# ========================================================== \n";
    print WINMAKE "#                                                            \n";

}

# -------------------------------------------------------------------------------------
# printExcludeFiles
#
#
#
#
#
#
#
# -------------------------------------------------------------------------------------
sub printExcludeFiles {
my $j;
    print WINMAKE "\n";
    print WINMAKE "# ================================================  \n";
    print WINMAKE "# Winmake.am Exclude files  \n";
    print WINMAKE "# ================================================  \n";
    if ($WinExcludeFileCount > 0) {
      foreach  $j (@WinExcludeFiles)  {
         print WINMAKE "\#     $j \n";
      }
    } else 
    {
         print WINMAKE "\#     NO FILES EXCLUDED BY WINMAKE.AM !!! \n\n";
    }
    print WINMAKE "\n\n";

}

# -------------------------------------------------------------------------------------
# ParseMakefileam
#
#
#
#
#
#
#
# -------------------------------------------------------------------------------------
sub ParseMakefileam {
# Temp Variables
my @stemp;
my $string;
my $i;
my $j;
my $Exclude;
    #
    # Parse Makefile.am
    #
    while (<MAKEFILE_AM>) {
        # Capture Source File List (Ignore $(Sources) Assignment Statement)
        if(((/^Sources/) || (/_SOURCES/)) && !(/\$\(Sources\)/)) {
            # Split The Arguments
            @stemp = split;
            
            # Capture Source File(s) On This Line (If Any)
            foreach  $i (@stemp)  {
                if($i =~ /\.[cChH]/) {
                    $SourceFiles[$SourceFileCount++] = $i;
                    }
                }
        
            # Collect Source Files In This Block
            while(<MAKEFILE_AM>) {
                # Capture Source File
                if($_ =~ /\.[cChH]/) {
                    # Handle $(GLOBUS_THREADS) and $(GLOBUS_CALLBACK_BUILD) Macros
                    if($GlobusThreading eq "threaded") {
                        s/\$\(GLOBUS_THREADS\)/windows/;
                        s/\$\(GLOBUS_CALLBACK_BUILD\)/threads/;
                        }
                    else {
                        s/\$\(GLOBUS_THREADS\)/none/;
                        s/\$\(GLOBUS_CALLBACK_BUILD\)/nothreads/;
                        }

                    # Split The Arguments
                    @stemp = {};
                    @stemp = split;
                    
                    # Capture Source File(s) On This Line (If Any)
                    foreach  $i (@stemp)  {
                        if($i =~ /\.[cChH]/) {
                            $SourceFiles[$SourceFileCount++] = $i;
                            }
                        }
                    }
                    
                # Exit When No Trailing Continuation Symbol \
                if(!/\\/) {
                    last;
                    }
                } # while<MAKEFILE.AM>

            } # if Sources
            
        # Capture Header File List
        @stemp = {};
        if(/^flavorinclude_HEADERS/) {
            # Split The Arguments
            @stemp = {};
            @stemp = split;
            
            # Capture Header File(s) On The First Line (If Any)
            foreach  $i (@stemp)  {
                if($i =~ /\.[cChH]/) {
                    $i =~ s/ //;
                    $HeaderFiles[$HeaderFileCount++] = $i;
                    }
                }
        
            # Collect Header Files In This Block
            while(<MAKEFILE_AM>) {
                # Capture Header Files
                if($_ =~ /\.[hH]/) {
                    # Handle $(GLOBUS_THREADS) and $(GLOBUS_CALLBACK_BUILD) Macros
                    if($GlobusThreading eq "threaded") {
                        s/\$\(GLOBUS_THREADS\)/windows/;
                        s/\$\(GLOBUS_CALLBACK_BUILD\)/threads/;
                        }
                    else {
                        s/\$\(GLOBUS_THREADS\)/none/;
                        s/\$\(GLOBUS_CALLBACK_BUILD\)/nothreads/;
                        }

                    # Split The Arguments
                    @stemp = {};
                    @stemp = split;
                    
                    # Capture Header File(s) On The First Line (If Any)
                    foreach  $i (@stemp)  {
                        if($i =~ /\.[cChH]/) {
                            $i =~ s/ //;
                            $HeaderFiles[$HeaderFileCount++] = $i;
                            }
                        }
                    }
                    
                # Exit When No Trailing Continuation Symbol \
                if(!/\\/) {
                    last;
                    }
                } # while<MAKEFILE.AM>
            } # if flavorinclude_HEADERS
            
        # Capture Base Library Name
        if ((/^lib_LTLIBRARIES/) || (/^noinst_LTLIBRARIES/)) {
            # Split The Fields
            @stemp = split;

            # Extract Flavor Name
            @stemp = split /\$\(GLOBUS_FLAVOR_NAME\)/,$stemp[2];
            $BaseLibraryName = $stemp[0];
            } # if lib_LTLIBRARIES
            
        } # while <MAKEFILE_AM>

}

# -------------------------------------------------------------------------------------
# ParseWinMakeamCommon
#
#
#
#
#
#
#
# -------------------------------------------------------------------------------------
sub ParseWinMakeamCommon {
# Temp Variables
my @stemp;
my $string;
my $i;
my $j;
my $Exclude;


    if(!open(WINMAKE_AM,"$FullWin32Path\\Winmake.am")) {
        # Not Fatal: Not Needed If No Windows Only Files
        # ToDo: Noisy - Remove This Later
        print "    Warning: No \"Winmake.am\" in ", $FullWin32Path, " - Using default rules.\n";
        } 
    else {

        while (<WINMAKE_AM>) {
            # --------------------------------------------------
            # Capture Additional Linux Source File List
            # --------------------------------------------------
            if(/^Sources/) {
                # Split The Arguments
                @stemp = split;
                
                # Capture Source File(s) On This Line (If Any)
                foreach  $i (@stemp)  {
                    if($i =~ /\.[cChH]/) {
                        $SourceFiles[$SourceFileCount++] = $i;
                        }
                    }
            
                # Collect Source Files In This Block
                while(<WINMAKE_AM>) {
                    # Capture Source File
                    if($_ =~ /\.[cChH]/) {
                        # Split The Arguments
                        @stemp = {};
                        @stemp = split;
                        
                        # Capture Source File(s) On This Line (If Any)
                        foreach  $i (@stemp)  {
                            if($i =~ /\.[cChH]/) {
                                $SourceFiles[$SourceFileCount++] = $i;
                                }
                            }
                        }
                        
                    # Exit When No Trailing Continuation Symbol \
                    if(!/\\/) {
                        last;
                        }
                    } # while<WINMAKE_AM>
                } # if Sources
                
            # --------------------------------------------------
            # Capture Windows Only Sources In .\win32
            # --------------------------------------------------
            if(/^WinSources/) {
                # Split The Arguments
                @stemp = split;
                
                # Capture Source File(s) On This Line (If Any)
                foreach  $i (@stemp)  {
                    if($i =~ /\.[cChH]/) {
                        $WinSourceFiles[$WinSourceFileCount++] = $i;
                        }
                    }
            
                # Collect Source Files In This Block
                while(<WINMAKE_AM>) {
                    # Capture Source File
                    if($_ =~ /\.[cChH]/) {
                        # Split The Arguments
                        @stemp = {};
                        @stemp = split;
                        
                        # Capture Source File(s) On This Line (If Any)
                        foreach  $i (@stemp)  {
                            if($i =~ /\.[cChH]/) {
                                $WinSourceFiles[$WinSourceFileCount++] = $i;
                                }
                            }
                        }
                        
                    # Exit When No Trailing Continuation Symbol \
                    if(!/\\/) {
                        last;
                        }
                    } # while<WINMAKE_AM>
                } # if WinSources
                

            # --------------------------------------------------
            # Capture Windows Exclude ( Makefile.am files to exclude )
            # --------------------------------------------------
            if(/^Exclude/) {
                # Split The Arguments
                @stemp = split;
                
                # Capture Source File(s) On This Line (If Any)
                foreach  $i (@stemp)  {
                    if($i =~ /\.[cChH]/) {
                        $WinExcludeFiles[$WinExcludeFileCount++] = $i;
                        }
                    }
            
                # Collect Source Files In This Block
                while(<WINMAKE_AM>) {
                    # Capture Source File
                    if($_ =~ /\.[cChH]/) {
                        # Split The Arguments
                        @stemp = {};
                        @stemp = split;
                        
                        # Capture Source File(s) On This Line (If Any)
                        foreach  $i (@stemp)  {
                            if($i =~ /\.[cChH]/) {
                                $WinExcludeFiles[$WinExcludeFileCount++] = $i;
                                }
                            }
                        }
                        
                    # Exit When No Trailing Continuation Symbol \
                    if(!/\\/) {
                        last;
                        }
                    } # while<WINMAKE_AM>
                } # if Exclude

            # --------------------------------------------------
            # Capture Header File List
            # --------------------------------------------------
            @stemp = {};
            if(/^flavorinclude_HEADERS/) {
                # Split The Arguments
                @stemp = {};
                @stemp = split;
                
                # Capture Header File(s) On The First Line (If Any)
                foreach  $i (@stemp)  {
                    if($i =~ /\.[cChH]/) {
                        $i =~ s/ //;
                        $HeaderFiles[$HeaderFileCount++] = $i;
                        }
                    }
            
                # Collect Header Files In This Block
                while(<WINMAKE_AM>) {
                    # Capture Header Files
                    if($_ =~ /\.[hH]/) {
                        # Split The Arguments
                        @stemp = {};
                        @stemp = split;
                        
                        # Capture Header File(s) On The First Line (If Any)
                        foreach  $i (@stemp)  {
                            if($i =~ /\.[cChH]/) {
                                $i =~ s/ //;
                                $HeaderFiles[$HeaderFileCount++] = $i;
                                }
                            }
                        }
                        
                    # Exit When No Trailing Continuation Symbol \
                    if(!/\\/) {
                        last;
                        }
                    } # while<WINMAKE_AM>
                } # if flavorinclude_HEADERS
                
            # --------------------------------------------------
            # Capture Header File List
            # --------------------------------------------------
            @stemp = {};
            if(/^wininclude_HEADERS/) {
                # Split The Arguments
                @stemp = {};
                @stemp = split;
                
                # Capture Header File(s) On The First Line (If Any)
                foreach  $i (@stemp)  {
                    if($i =~ /\.[cChH]/) {
                        $i =~ s/ //;
                        $WinHeaderFiles[$WinHeaderFileCount++] = $i;
                        }
                    }
            
                # Collect Header Files In This Block
                while(<WINMAKE_AM>) {
                    # Capture Header Files
                    if($_ =~ /\.[hH]/) {
                        # Split The Arguments
                        @stemp = {};
                        @stemp = split;
                        
                        # Capture Header File(s) On The First Line (If Any)
                        foreach  $i (@stemp)  {
                            if($i =~ /\.[cChH]/) {
                                $i =~ s/ //;
                                $WinHeaderFiles[$WinHeaderFileCount++] = $i;
                                }
                            }
                        }
                        
                    # Exit When No Trailing Continuation Symbol \
                    if(!/\\/) {
                        last;
                        }
                    } # while<WINMAKE_AM>
                } # if wininclude_HEADERS
            } # while<WINMAKE_AM>
 }
}

# -------------------------------------------------------------------------------------
# ParseWinMakeamDLL
#
#
#
#
#
#
#
# -------------------------------------------------------------------------------------
sub ParseWinMakeamDLL {
# Temp Variables
my @stemp;
my $string;
my $i;
my $j;
my $Exclude;



    if(!open(WINMAKE_AM,"$FullWin32Path\\Winmake.am")) {
        # Not Fatal: Not Needed If No Windows Only Files
        # ToDo: Noisy - Remove This Later
        print "    Warning: No \"Winmake.am\" in ", $FullWin32Path, " - Using default rules.\n";
        }

    # Spin Through Winmake.am
    else {
            
        # --------------------------------------------------
        # Capture Windows Only Exports
        # --------------------------------------------------
        while(<MAKEFILE_AM>) {
            if(/^WinExports/) {
                # Note: Winmake.am Does Not Allow An Export On The 'WinExports=' Line
            
                # Collect The Exports In The Block
                while(<WINMAKE_AM>) {
                    # Split The Arguments
                    @stemp = {};
                    @stemp = split;
                    
                    # Capture Export
                    $DLLExports[$DLLExportCount++] = $stemp[0];
                        
                    # Exit When No Trailing Continuation Symbol \
                    if(!/\\/) {
                        last;
                        }
                    } # while<WINMAKE_AM>
                } # if WinExports
            
            # --------------------------------------------------
            # Capture DLL Export Exclusions
            # --------------------------------------------------
            if(/^ExportExclusions/) {
                # Note: Winmake.am Does Not Allow An Export On The 'ExportExclusions=' Line
            
                # Collect The Exports In The Block
                while(<WINMAKE_AM>) {
                    # Split The Arguments
                    @stemp = {};
                    @stemp = split;
                    
                    # Capture Export
                    $DLLExportExclusions[$DLLExportExclusionCount++] = $stemp[0];
                        
                    # Exit When No Trailing Continuation Symbol \
                    if(!/\\/) {
                        last;
                        }
                    } # while<WINMAKE_AM>
                } # if ExportExclusions

            # --------------------------------------------------
            # Capture Library Dependencies
            # --------------------------------------------------
            if(/^LibDependencies/) {
                # Note: Winmake.am Does Not Allow A .Lib On The 'LibDependencies=' Line
            
                # Collect The Libs In The Block
                while(<WINMAKE_AM>) {
                    # Substitute For $(GLOBUS_FLAVOR_NAME) If Necessary
                    s/\$\(GLOBUS_FLAVOR_NAME\)/$FlavorName/;
                
                    # Split The Arguments
                    @stemp = {};
                    @stemp = split;
                    
                    # Capture Export
                    $DLLDependency[$DLLDependencyCount++] = $stemp[0];
                        
                    # Exit When No Trailing Continuation Symbol \
                    if(!/\\/) {
                        last;
                        }
                    } # while<MAKEFILE.AM>
                } # if LibDependencies
            
            } # while<WINMAKE_AM>
        } # else (open(WINMAKE_AM))
}
