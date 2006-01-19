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
	globus_common_strptime_test.c

	Used to test the functionality in globus_strptime.c

	Written by Michael Lebman
	Begun 4-2-02

*/

#include "globus_common.h"

void printOut( char string[] );
void printError( char errorString[], int errorCode, int exitingFlag );

int errorsOccurred= 0;

int main( int argc, char * argv[] )
{
	char * rc;
	char dateString[256];
	char formatString[256];
	struct tm timeStruct;

	globus_module_activate (GLOBUS_COMMON_MODULE);

	/* create timestamp strings & check them against the tm struct */
	/* "good news" version- format and data match exactly */
	strcpy( formatString, "%a %b %d %H:%M:%S %Y" );
	strcpy( dateString, "Sun May 01 20:27:01 1994" );
	printf( "Input date: %s\n", dateString );
	rc= globus_strptime( dateString, formatString, &timeStruct );
	if ( rc == GLOBUS_NULL )
		printError( "globus_strptime() failed", 0, 0 );
	else
		printf( " struct tm: %s", asctime( &timeStruct ) );

	/* neither format nor data has whitespace */
	strcpy( formatString, "%a%b%d%H:%M:%S%Y" );
	strcpy( dateString, "SunMay0120:27:011994" );
	printf( "Input date: %s\n", dateString );
	rc= globus_strptime( dateString, formatString, &timeStruct );
	if ( rc == GLOBUS_NULL )
		printError( "globus_strptime() failed", 0, 0 );
	else
		printf( " struct tm: %s", asctime( &timeStruct ) );

	/* format has whitespace but data does not */
	strcpy( formatString, "%a %b %d %H:%M:%S %Y" );
	strcpy( dateString, "SunMay0120:27:011994" );
	printf( "Input date: %s\n", dateString );
	rc= globus_strptime( dateString, formatString, &timeStruct );
	if ( rc == GLOBUS_NULL )
		printError( "globus_strptime() failed", 0, 0 );
	else
		printf( " struct tm: %s", asctime( &timeStruct ) );

	/* data has whitespace but format does not */
	strcpy( formatString, "%a%b%d%H:%M:%S%Y" );
	strcpy( dateString, "Sun May 01 20:27:01 1994" );
	printf( "Input date: %s\n", dateString );
	rc= globus_strptime( dateString, formatString, &timeStruct );
	if ( rc == GLOBUS_NULL )
		printError( "globus_strptime() failed", 0, 0 );
	else
		printf( " struct tm: %s", asctime( &timeStruct ) );


	/* variations on the format */

	strcpy( formatString, "%a %b %d %H:%M:%S %C%y" );
	strcpy( dateString, "Sun May 01 20:27:01 19 94" );
	printf( "Input date: %s\n", dateString );
	rc= globus_strptime( dateString, formatString, &timeStruct );
	if ( rc == GLOBUS_NULL )
		printError( "globus_strptime() failed", 0, 0 );
	else
		printf( " struct tm: %s", asctime( &timeStruct ) );

	strcpy( formatString, "%a %D %H:%M:%S" );
	strcpy( dateString, "Sun 5/01/94 20:27:01" );
	printf( "Input date: %s\n", dateString );
	rc= globus_strptime( dateString, formatString, &timeStruct );
	if ( rc == GLOBUS_NULL )
		printError( "globus_strptime() failed", 0, 0 );
	else
		printf( " struct tm: %s", asctime( &timeStruct ) );

	strcpy( formatString, "%a %b %d %I:%M:%S %p %Y" );
	strcpy( dateString, "Sun May 01 9:27:01 a.m. 1994" );
	printf( "Input date: %s\n", dateString );
	rc= globus_strptime( dateString, formatString, &timeStruct );
	if ( rc == GLOBUS_NULL )
		printError( "globus_strptime() failed", 0, 0 );
	else
		printf( " struct tm: %s", asctime( &timeStruct ) );

	strcpy( formatString, "%a %b %d %I:%M:%S %p %Y" );
	strcpy( dateString, "Sun May 01 9:27:01 p.m. 1994" );
	printf( "Input date: %s\n", dateString );
	rc= globus_strptime( dateString, formatString, &timeStruct );
	if ( rc == GLOBUS_NULL )
		printError( "globus_strptime() failed", 0, 0 );
	else
		printf( " struct tm: %s", asctime( &timeStruct ) );

	strcpy( formatString, "%a %b %d %I:%M:%S %Y" );
	strcpy( dateString, "Sun May 01 9:27:01 1994" );
	printf( "Input date: %s\n", dateString );
	rc= globus_strptime( dateString, formatString, &timeStruct );
	if ( rc == GLOBUS_NULL )
		printError( "globus_strptime() failed", 0, 0 );
	else
		printf( " struct tm: %s", asctime( &timeStruct ) );

	strcpy( formatString, "%a %B %d %R %Y" );
	strcpy( dateString, "Sun May 01 20:27 1994" );
	printf( "Input date: %s\n", dateString );
	rc= globus_strptime( dateString, formatString, &timeStruct );
	if ( rc == GLOBUS_NULL )
		printError( "globus_strptime() failed", 0, 0 );
	else
		printf( " struct tm: %s", asctime( &timeStruct ) );

	strcpy( formatString, "%a %b %d %T %Y" );
	strcpy( dateString, "Sun May 01 21:27:01 1994" );
	printf( "Input date: %s\n", dateString );
	rc= globus_strptime( dateString, formatString, &timeStruct );
	if ( rc == GLOBUS_NULL )
		printError( "globus_strptime() failed", 0, 0 );
	else
		printf( " struct tm: %s", asctime( &timeStruct ) );

	strcpy( formatString, "%a %b %d %H:%M:%S %y" );
	strcpy( dateString, "Sun May 01 20:27:01  94" );
	printf( "Input date: %s\n", dateString );
	rc= globus_strptime( dateString, formatString, &timeStruct );
	if ( rc == GLOBUS_NULL )
		printError( "globus_strptime() failed", 0, 0 );
	else
		printf( " struct tm: %s", asctime( &timeStruct ) );

	strcpy( formatString, "%a %b %d %H:%M:%S %y" );
	strcpy( dateString, "Sun May 01 20:27:01  2" );
	printf( "Input date: %s\n", dateString );
	rc= globus_strptime( dateString, formatString, &timeStruct );
	if ( rc == GLOBUS_NULL )
		printError( "globus_strptime() failed", 0, 0 );
	else
		printf( " struct tm: %s", asctime( &timeStruct ) );

	/* time only */
	strcpy( formatString, "%R" );
	strcpy( dateString, "20:27" );
	printf( "Input date: %s\n", dateString );
	rc= globus_strptime( dateString, formatString, &timeStruct );
	if ( rc == GLOBUS_NULL )
		printError( "globus_strptime() failed", 0, 0 );
	else
		printf( " struct tm: %s", asctime( &timeStruct ) );

	/* date only */
	strcpy( formatString, "%a %b %d %y" );
	strcpy( dateString, "Sun May 01 02" );
	printf( "Input date: %s\n", dateString );
	rc= globus_strptime( dateString, formatString, &timeStruct );
	if ( rc == GLOBUS_NULL )
		printError( "globus_strptime() failed", 0, 0 );
	else
		printf( " struct tm: %s", asctime( &timeStruct ) );

	globus_module_deactivate (GLOBUS_COMMON_MODULE);

	if ( errorsOccurred )
		printOut( "strptime test failed" );
	else
		printOut( "strptime test succeeded!" );

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
