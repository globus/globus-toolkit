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
	globus_common_handle_table_test.c

	Used to test the functionality in globus_handle_table.c

	Written by Michael Lebman
	Begun 4-1-02

	7/12/02 Added destructor() function for call to 
	 globus_handle_table_init()

*/

#include "globus_common.h"

void printOut( char string[] );
void printError( char errorString[], int errorCode, int exitingFlag );

int errorsOccurred= 0;

void destructor( void * datum )
{
	static int count= 1;
	printf( "destructor() called; count is %d\n",  count++ );
}

int main( void )
{
	globus_bool_t rc;
	int * data, i;
	globus_handle_table_t handle_table;
	int object1, object2, object3;
	int object1_count= 1;
	int object2_count= 1;
	int object3_count= 3;
	globus_handle_t object1_handle, object2_handle, object3_handle;

	globus_module_activate (GLOBUS_COMMON_MODULE);

	/* create a handle table */
	printOut( "Creating handle table..." );
	globus_handle_table_init( &handle_table, destructor );
    
	/* add some objects to reference */
	printOut( "Adding elements..." );
	object1_handle= globus_handle_table_insert( &handle_table, &object1, object1_count );
	object2_handle= globus_handle_table_insert( &handle_table, &object2, object2_count );
	object3_handle= globus_handle_table_insert( &handle_table, &object3, object3_count );

	/* increment reference counts */
	printOut( "Incrementing references..." );
	rc= globus_handle_table_increment_reference_by( &handle_table, object3_handle, 5 );
	if ( rc == GLOBUS_FALSE )
		printError( "globus_handle_table_increment_reference() failed", 0, 0 );
	object3_count+= 5;
	rc= globus_handle_table_increment_reference( &handle_table, object2_handle );
	if ( rc == GLOBUS_FALSE )
		printError( "globus_handle_table_increment_reference() failed", 0, 0 );
	object2_count++;

	/* look up some objects */
	data= (int *)globus_handle_table_lookup( &handle_table, object3_handle );
	if ( data != &object3 )
		printError( "globus_handle_table_lookup() failed", 0, 0 );
	data= (int *)globus_handle_table_lookup( &handle_table, object1_handle );
	if ( data != &object1 )
		printError( "globus_handle_table_lookup() failed", 0, 0 );
	data= (int *)globus_handle_table_lookup( &handle_table, object2_handle );
	if ( data != &object2 )
		printError( "globus_handle_table_lookup() failed", 0, 0 );

	/* remove some objects and reduce reference counts */
	printOut( "Removing references..." );
	rc= globus_handle_table_decrement_reference( &handle_table, object1_handle );
	object1_count--;
	if ( rc == GLOBUS_TRUE && object1_count == 0 )
		printError( "globus_handle_table_decrement_reference() failed for object1", 0, 0 );
	for( i= 0; i < object3_count; i++ )
	{
		rc= globus_handle_table_decrement_reference( &handle_table, object3_handle );
		if ( rc == GLOBUS_FALSE && i < object3_count - 1 )
			printError( "globus_handle_table_decrement_reference() failed for object3", 0, 0 );
	}
	object3_count= 0;
	if ( rc == GLOBUS_TRUE ) /* should have been removed from table */
		printError( "globus_handle_table_decrement_reference() failed for object3", 0, 0 );
	rc= globus_handle_table_decrement_reference( &handle_table, object2_handle );
	object2_count--;
	if ( rc == GLOBUS_FALSE && object2_count > 0 )
		printError( "globus_handle_table_decrement_reference() failed for object2", 0, 0 );

	/* perform additional lookups */
	printOut( "Looking up references..." );
	data= (int *)globus_handle_table_lookup( &handle_table, object3_handle );
	if ( data != GLOBUS_NULL ) /* should have been removed */
		printError( "globus_handle_table_lookup() failed for object3", 0, 0 );
	data= (int *)globus_handle_table_lookup( &handle_table, object1_handle );
	if ( data != GLOBUS_NULL && object1_count == 0 )
		printError( "globus_handle_table_lookup() failed for object1", 0, 0 );
	data= (int *)globus_handle_table_lookup( &handle_table, object2_handle );
	if ( data != &object2 && object2_count > 0 )
		printError( "globus_handle_table_lookup() failed for object2", 0, 0 );

	/* display the final counts */
	printf( "Final counts--\n" );
	printf( "object1_count: %d\n", object1_count );
	printf( "object2_count: %d\n", object2_count );
	printf( "object3_count: %d\n", object3_count );

	/* destroy the table*/
	printOut( "Destroying the table..." );
	globus_handle_table_destroy( &handle_table );

	globus_module_deactivate (GLOBUS_COMMON_MODULE);

	if ( errorsOccurred )
		printOut( "handle table test failed" );
	else
		printOut( "handle table test succeeded!" );

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
