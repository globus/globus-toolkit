/*
 * Copyright (c) 1992,1994 by the University of Southern California
 * Part of GOST library
 */

#include "oldgaa_gl_internal_err.h"
#include <stdio.h>

void
oldgaa_gl__function_internal_error_helper(const char file[], int line, const char msg[])
{
    if (internal_error_handler)   
        (*internal_error_handler)(file, line, msg);   
     /* If the internal_error_handler() returns, or was not defined, then we
	display a message to stderr and abort execution. */
    if (line) {
        fprintf(stderr, "Internal error in file %s (line %d): %s\n",
                file, line, msg);
    } else {
        fprintf(stderr, msg);
    }
    /* internal_error() must never return; should break.
     */
    abort();
    /* NOTREACHED */
}


/* This is set by oldgaa_gl__fout_of_memory(). */

int oldgaa_gl__is_out_of_memory = 0;

void (*oldgaa_gl_out_of_memory_handler)(const char file[], int line) = NULL;


void
oldgaa_gl__fout_of_memory(const char file[], int line) 
{
    if (oldgaa_gl_out_of_memory_handler)
	(*oldgaa_gl_out_of_memory_handler)(file, line);
    oldgaa_gl__is_out_of_memory++;
    oldgaa_gl__function_internal_error_helper(file, line, "Out of Memory");
}

