/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

/* getoptWin.h - header for getoptWin.c, a Windows version of the Unix getopt function
 *
 *  Michael Lebman
 *  March 13, 2002
 *
 */

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

// globals
extern char * optarg;
extern int optind, opterr, optopt;

int getoptWin( int argc, char ** argv, char optstring[] );
