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

/* getoptWin.c - a Windows version of the Unix getopt function
 *
 *  Michael Lebman
 *  March 13, 2002
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

// globals
char * optarg;
int optind, opterr, optopt;

// forward declarations
int getOption( char * string, int currentStringIndex, char optstring[] );
int optionRequiresArgument( int optionLetter, char optstring[] );

/* Command line syntax rules:
 *
 * 1. Each command line option must be a single letter
 * 2. Each command line option must be preceded by a single dash; i.e., "-"
 * 3. If a command line option has an argument according to the command line 
 *     option string, the next token is considered to be the argument
 * 4. Option arguments may not contained embedded whitespace unless
 *     they are enclosed by double quotes
 * 5. The command line may terminate naturally or by a double dash; i.e., "--"
 * 6. Multiple command line options may be concatenated with a single dash,
 *     but only if none of the options have an argument (pun intended)
 *
*/

int getoptWin( int argc, char ** argv, char optstring[] )
{
	static int firstTimeThrough= 1;
	static int currentArgStringIndex= 0;
	int optionLetter;
	char * currentArgString;

	if ( firstTimeThrough )
	{
		optind= 1;
		firstTimeThrough= 0;
	}

	while ( optind < argc )
	{
		// get the next string in argv
		currentArgString= argv[optind];

		//printf( "optind is %d\n", optind );
		//printf( "currentArgString is %s\n", currentArgString );

		// check whether it's possibly an option
		if ( currentArgStringIndex == 0 )
		{
			// does it begin with a dash?
			if ( currentArgString[0] != '-' )
			{
				optind++; // ignore this string completely, go on
				continue;
			}
			currentArgStringIndex++;
		}

		//printf( "currentArgStringIndex is %d\n", currentArgStringIndex );
		
		optionLetter= getOption( currentArgString, currentArgStringIndex, optstring );
		if ( optionLetter == '-' ) // end of options
			return EOF;
		if ( optionLetter == '?' ) // unrecognized option
		{
			//printf( "unrecognized option\n" );

			// reset state variables
			if ( currentArgStringIndex >= strlen( currentArgString ) - 1 )
			{
				optind++;
				currentArgStringIndex= 0;
			}
			else
				currentArgStringIndex++;
			return '?';
		}
		if ( optionLetter == 0 ) // not an option (pun intended)
		{
			// reset state variables
			optind++;
			currentArgStringIndex= 0;
			continue;
		}
		// else, valid option encountered!
		if ( optionRequiresArgument( optionLetter, optstring ) )
		{
			//printf( "option requiring argument\n" );

			optarg= argv[optind+1];
			// reset state variables
			optind+= 2;
			currentArgStringIndex= 0;
			return optionLetter;
		}
		else // is this the final character in the string?
		{			
			//printf( "option without argument\n" );

			// reset state variables
			if ( currentArgStringIndex >= strlen( currentArgString ) - 1 )
				optind++;
			else
				currentArgStringIndex++;
			return optionLetter;
		}
	}

	return EOF;
}

int getOption( char * string, int currentStringIndex, char optstring[] )
{
	if ( currentStringIndex == 0 ) // first time with this string
	{
		// does it begin with a dash?
		if ( string[0] != '-' )
			return 0;
		currentStringIndex= 1;
	}

	// is the option a dash?
	if ( string[currentStringIndex] == '-' )
		return '-';

	// is the option a letter?
	if ( isalpha( string[currentStringIndex] ) == 0 )
		return 0;
	// is the letter in the option string?
	if ( strchr( optstring, string[currentStringIndex] ) == NULL )
	{
		optopt= string[currentStringIndex];
		return '?';
	}

	// success!
	return string[currentStringIndex];
}

int optionRequiresArgument( int optionLetter, char optstring[] )
{
	char * letterPointer;
	letterPointer= strchr( optstring, optionLetter );
	letterPointer++;
	if ( *letterPointer == ':' )
		return 1;

	return 0;
}
/*
void main( int argc, char ** argv )
{
	int letter;
	int i;
	char optionString[]= "abc:";

	printf( "argc is %d\n", argc );
	for( i= 0; i < argc; i++ )
		printf( "argv[%d]: %s\n", i, argv[i] );

	printf( "\n" );

	while( 1 )
	{
		letter= getoptWin( argc, argv, optionString );
		if ( letter == EOF )
		{
			printf( "End of options found\n" );
			break;
		}
		else if ( letter == '?' )
		{
			printf( "Unrecognized option: %c\n", optopt );
		}
		else
		{
			printf( "option letter is %c", letter );
			if ( optionRequiresArgument( letter, optionString ) )
				printf( "; argument is \"%s\"", optarg );
			printf( "\n" );
		}
	}
}
*/
