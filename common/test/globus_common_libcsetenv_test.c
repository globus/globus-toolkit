/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
	globus_common_libcsetenv_test.c

	Used to test the functionality in globus_libc_setenv.c

	Written by Michael Lebman
	Begun 4-3-02

*/

#include "globus_common.h"

void printOut( char string[] );
void printError( char errorString[], int errorCode, int exitingFlag );

int errorsOccurred= 0;

struct envVar
{
	char * name;
	char * value;
};

int main( int argc, char * argv[] )
{
	struct envVar vars[]= { { "var0", "val0" },
							{ "var1", "val1" },
							{ "var2", "val2" },
							{ "var3", "val3" },
							{ "var4", "val4" },
							{ "var5", "val5" },
							{ "var6", "val6" },
							{ "var7", "val7" },
							{ "var8", "val8" },
							{ "var9", "val9" },
							{ "var10", "val10" },
							{ "var11", "val11" },
							{ "var12", "val12" },
							{ "var13", "val13" },
							{ "var14", "val14" },
							{ "var15", "val15" },
							{ "var16", "val16" },
							{ "var17", "val17" },
							{ "var18", "val18" },
							{ "var19", "val19" },
							{ "var20", "val20" },
							{ "var21", "val21" },
							{ "var22", "val22" },
							{ "var23", "val23" },
							{ "var24", "val24" },
							{ "var25", "val25" },
							{ "var26", "val26" },
							{ "var27", "val27" },
							{ "var28", "val28" },
							{ "var29", "val29" },
							{ "var30", "val30" },
							{ "var31", "val31" },
							{ "var32", "val32" },
							{ "var33", "val33" },
							{ "var34", "val34" },
							{ "var35", "val35" },
							{ "var36", "val36" },
							{ "var37", "val37" },
							{ "var38", "val38" },
							{ "var39", "val39" },
							{ "var40", "val40" },
							{ "var41", "val41" },
							{ "var42", "val42" },
							{ "var43", "val43" },
							{ "var44", "val44" },
							{ "var45", "val45" },
							{ "var46", "val46" },
							{ "var47", "val47" },
							{ "var48", "val48" },
							{ "var49", "val49" } };
	int i;
	char * value;
	char temp[256];

	globus_module_activate (GLOBUS_COMMON_MODULE);

	/* check for the variables that should be in the environment */
	if ( argc > 1 )
	{
		printOut( "Checking environment variables passed in..." );
		for( i= 1; i < argc; i++ )
		{
			value= globus_libc_getenv( argv[i] );
			if ( value != NULL )
				printf( "Variable: %s; value: %s\n", argv[i], value );
			else
			{
				sprintf( temp, "globus_libc_getenv() failed; variable is %s", argv[i] );
				printError( temp, 0, 0 ); 
			}
		}
	}

	/* check for some variables that should not be in the environment */
	printOut( "Checking for environment variables that should not yet exist..." );
	for( i= 40; i < 50; i++ )
	{
		value= globus_libc_getenv( vars[i].name );
		if ( value != NULL )
			printError( "globus_libc_getenv() failed- found nonexistent variable", i, 0 ); 
	}

	/* add a bunch of variables to the environment */
	printOut( "Setting environment variables..." );
	for( i= 0; i < 50; i++ )
	{
		if ( globus_libc_setenv( vars[i].name, vars[i].value, 0 ) )
			printError( "globus_libc_setenv() failed", i, 0 ); 
	}

	/* check to see whether all of the variables were added correctly */
	printOut( "Verifying set environment variables..." );
	for( i= 0; i < 50; i++ )
	{
		value= globus_libc_getenv( vars[i].name );
		if ( value != NULL )
		{
			strcpy( temp, vars[i].name );
			temp[2]= 'l'; /* overwrite the 'r' with an 'l' */
			if ( strcmp( temp, value ) )
			{
				sprintf( temp, "globus_libc_getenv() failed; value returned is %s", value );
				printError( temp, i, 0 );
			}				
		}
		else
			printError( "globus_libc_getenv() failed", i, 0 ); 
	}

	/* unset most of the variables */
	printOut( "Unsetting environment variables..." );
	for( i= 10; i < 50; i++ )
		globus_libc_unsetenv( vars[i].name );

	/* check again for their presence; include both set and unset variables */
	printOut( "Checking set environment variables..." );
	for( i= 0; i < 10; i++ ) /* should still be present */
	{
		value= globus_libc_getenv( vars[i].name );
		if ( value == NULL )
			printError( "globus_libc_getenv() failed", i, 0 ); 
	}
	printOut( "Checking unset environment variables..." );
	for( i= 10; i < 20; i++ ) /* should be unset */
	{
		value= globus_libc_getenv( vars[i].name );
		if ( value != NULL )
			printError( "globus_libc_getenv() failed- found nonexistent variable", i, 0 ); 
	}

	globus_module_deactivate (GLOBUS_COMMON_MODULE);

	if ( errorsOccurred )
		printOut( "libc_setenv test failed" );
	else
		printOut( "libc_setenv test succeeded!" );

	return errorsOccurred;
}

void printError( char errorString[], int errorCode, int exitingFlag )
{
	fprintf( stderr, "ERROR: " );
	fprintf( stderr, errorString );
	if ( errorCode )
		fprintf( stderr, "- error code is %d", errorCode );
	if ( exitingFlag )
		fprintf( stderr, "; exiting..." );
	fprintf( stderr, "\n" );

	errorsOccurred++;
}

void printOut( char string[] )
{
	printf( string );
	printf( "\n" );
}
