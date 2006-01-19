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
