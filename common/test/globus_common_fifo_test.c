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
	globus_common_fifo_test.c

	Used to test the functionality in globus_fifo.c

	Written by Michael Lebman
	Begun 3-28-02

*/

#include "globus_common.h"

void printOut( char string[] );
void printError( char errorString[], int errorCode, int exitingFlag );

void usage( char programName[] )
{
	printOut( "Usage-" );
	printf( "\t%s <number of elements(must be > 3)>\n", programName );
}

int main( int argc, char * argv[] )
{
	int * data, i;
	int currentFifoSize;
	globus_fifo_t currentFifo;
	globus_fifo_t * newFifoPtr;
	globus_fifo_t relocatedFifo;
	int rc;
	int numOfItems;
	int * middleItem;
	int middleIndex;
	int * copyData;
	int errorsOccurred= 0;

	if ( argc != 2 )
	{
		usage( argv[0] );
		return -1;
	}

	numOfItems= atoi( argv[1] );
	if ( numOfItems <= 3 )
	{
		usage( argv[0] );
		return -1;
	}

	globus_module_activate (GLOBUS_COMMON_MODULE);

	printOut( "Creating FIFO..." );

	/* create a FIFO */
	rc= globus_fifo_init( &currentFifo );
	if ( rc != 0 )
	{ 
		printError( "Could not create FIFO", 0, 1 );
		return -1;
	}

	printOut( "Verifying FIFO is empty..." );

	/* check it's size- should be zero */
	if ( !globus_fifo_empty( &currentFifo ) )
	{
		printError( "globus_fifo_empty() failed", 0, 0 );
		errorsOccurred++;
	}

	printOut( "Adding data..." );

	middleIndex= numOfItems / 2;

	/* add a bunch of data */
	for( i= 0; i < numOfItems; i++ )
	{
		data= malloc( sizeof(int) );
		if ( data == NULL )
		{
			printError( "Out of memory- could not allocate more data items", 0, 0 );
			break;
		}
		*data= i;
		rc= globus_fifo_enqueue( &currentFifo, data );
		if ( rc != 0 )
		{
			printError( "globus_fifo_enqueue() failed", rc, 1 );
			return -1;
		}

		/* store the middle item for use later */
		if ( i == middleIndex )
			middleItem= data;
	}
	currentFifoSize= i;

	printOut( "Verifying data..." );

	/* check the size */
	if ( globus_fifo_size( &currentFifo ) != currentFifoSize )
	{
		printError( "globus_fifo_size() failed", 0, 0 );
		errorsOccurred++;
	}

	/* check the first item */
	data= (int *)globus_fifo_peek( &currentFifo );
	if ( *data != 0 )
	{
		printError( "globus_fifo_peek() failed", *data, 0 );
		errorsOccurred++;
	}

	/* check the last item */
	data= (int *)globus_fifo_tail_peek( &currentFifo );
	if ( *data != currentFifoSize - 1 )
	{
		printError( "globus_fifo_tail_peek() failed", *data, 0 );
		errorsOccurred++;
	}

	printOut( "Manipulating the FIFO..." );

	/* remove an item in the middle */
	data= (int *)globus_fifo_remove( &currentFifo, middleItem );
	if ( data == NULL || *data != *middleItem )
	{
		printError( "globus_fifo_remove() failed", 0, 0 );
		errorsOccurred++;
	}

	/* remove an item at the beginning */
	data= globus_fifo_dequeue( &currentFifo );
	if ( data == NULL || *data != 0 )
	{
		printError( "globus_fifo_dequeue() failed", *data, 0 );
		errorsOccurred++;
	}

	/* remove an item at the end */
	data= (int *)globus_fifo_tail_peek( &currentFifo );
	if ( *data == currentFifoSize - 1 )
	{
		data= (int *)globus_fifo_remove( &currentFifo, data );
		if ( *data != currentFifoSize - 1 )
		{
			printError( "globus_fifo_remove() failed", *data, 0 );
			errorsOccurred++;
		}
	}
	else
	{
		printError( "globus_fifo_tail_peek() failed during attempt to remove last item", *data, 0 );
		errorsOccurred++;
	}

	printOut( "Verifying altered size..." );

	/* check the size- it should be the original size - 3 */
	currentFifoSize-= 3;
	if ( globus_fifo_size( &currentFifo ) != currentFifoSize )
	{
		printError( "globus_fifo_size() failed", 0, 0 );
		errorsOccurred++;
	}

	printOut( "Creating a copy..." );

	/* copy the FIFO to another FIFO */
	newFifoPtr= globus_fifo_copy( &currentFifo );
	if ( newFifoPtr == NULL )
	{
		printError( "globus_fifo_copy() failed", 0, 0 );
		errorsOccurred++;
	}

	/* check the size on the new FIFO */
	if ( globus_fifo_size( newFifoPtr ) != currentFifoSize )
	{
		printError( "globus_fifo_size() failed on the copy", 0, 0 );
		errorsOccurred++;
	}

	printOut( "Verifying contents of copy..." );

	/* check whether both FIFO's contain the same set of items */
	while( !globus_fifo_empty( &currentFifo ) )
	{
		data= (int *)globus_fifo_dequeue( &currentFifo );
		if ( data == NULL )
		{
			printError( "current FIFO contains null data", 0, 0 );
			errorsOccurred++;
			break;
		}
		copyData= (int *)globus_fifo_dequeue( newFifoPtr );
		if ( copyData == NULL )
		{
			printError( "copy contains null data", 0, 0 );
			errorsOccurred++;
			continue;
		}
		if ( *data != *copyData )
		{
			printError( "copy data does not equal original data", 0, 0 );
			errorsOccurred++;
		}

		/* free the data in preparation of destroying the FIFO's */
		/* NOTE: Do not destroy the copy data; the copy consists of
		    pointers to the same data, so the copy is freed when
			the original data is freed */
		free( data );
	}

	printOut( "Relocating contents of original FIFO..." );

	/* move the original FIFO to another FIFO */
	if ( globus_fifo_move( &relocatedFifo, &currentFifo ) )
		printError( "globus_fifo_move() failed", 0, 0 );

	/* destroy both FIFO's */
	globus_fifo_destroy( &currentFifo );
	globus_fifo_destroy( newFifoPtr );

	globus_module_deactivate (GLOBUS_COMMON_MODULE);

	if ( errorsOccurred )
		printOut( "FIFO test failed" );
	else
		printOut( "FIFO test succeeded!" );

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
}

void printOut( char string[] )
{
	printf( string );
	printf( "\n" );
}
