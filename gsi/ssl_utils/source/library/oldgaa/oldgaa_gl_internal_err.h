/*
 * Copyright (c) 1991-1994 by the University of Southern California
 * Part of GOST library
 */

#ifndef OLDGAA_GL_INTERNAL_ERR_H

/* OUT OF MEMORY */
extern int gl__is_out_of_memory;    /* used internally by gl__fout_of_memory() */
extern void gl__fout_of_memory(const char file[], int lineno);

/* #define out_of_memory() \
    gl__fout_of_memory(__FILE__, __LINE__); */

extern void (*gl_out_of_memory_handler)(const char file[], int line);


/* BUFFER FULL */

#define interr_buffer_full() \
    gl__function_internal_error_helper(__FILE__, __LINE__, "A buffer filled up");
 
/*********************/

/* ASSERT */
#ifdef assert                  /* in case ASSERT.H was already included.  We
                                  want to over-ride it. */
#undef assert
#endif /* assert */

#ifndef NDEBUG
#define assert(expr) do { \
    if (!(expr)) \
          gl__function_internal_error_helper(__FILE__, __LINE__, "assertion violated: " #expr); \
} while(0)
#else /* NDEBUG */
#define assert(expr) do {;} while(0)
#endif /* NDEBUG */
/*****************************************/


/* INTERNAL_ERROR */
/* This is the main macro we call when an 'internal error' has occurred.
   This is usually a "can't happen" condition. */

#define internal_error(msg) \
    gl__function_internal_error_helper(__FILE__, __LINE__, msg)

/* There are two helpers you can set this to.  */
/* The macro version might be useful in instances where we might have blown the
   stack.  The function version is used instead of the macro version in order
   to save a bit of code space (one function call instead of that inline code).
   Each has a description below. */

/* The macro version currently (8/9/96) displays errors of the form:
    Internal error in file foo.c (line __LINE__): strange error */
/* We are trying to figure out how to handle this one.  --steve 8/9/96  */
/* 8/9/96: I don't know under what circumstances we would have LINE be zero.
   Must've happened oor I wouldn't have written it.  --swa */
/* 8/9/96: using gl__function_internal_error_helper() always now; this
   is (a) a way around the __LINE__ problem and (b) if the stack is
   really trashed (the rationale for making the internal error handler
   into inline code), then we won't be able to call write() or 
   abort() either, so the macro wouldn't buy us anything useful. */
/* I wish there were a way of getting rid of the strlen() and the
   write() in the macro version; don't think we can do this in a
   machine-independent way, though.  If you ever encounter a problem and need
   to enable this macro again to debug it, then I recommend using inline
   assembly code with the C ASM construct. */ 
/* I know I could find a way around the macro's problem in printing the
   __LINE__ appropriately, but I am not doing so, since this code is not in
   use; we use the function version exclusively */

#define gl__macro_internal_error_helper(file,line,msg) \
do { \
     /* If LINE is ZERO, then print no prefatory message. */              \
     if (line) { \
        write(2, "Internal error in file " file " (line " #line "): ",\
        sizeof "Internal error in file " file " (line " #line "): " -1);\
     }                                                  \
     write(2, msg, strlen(msg)); \
     /* If LINE is ZERO, then print no terminal \n. */              \
     if (line)                  \
        write(2, "\n", 1);        \
     if (internal_error_handler)   \
         (*internal_error_handler)(file, line, msg);   \
     /* If the internal_error_handler() ever returns, we should not continue.
        */ \
     abort(); \
} while(0)

/* Function form of internal_error.  Shrinks code size.  It is not clear that
   both this and the MACRO version are needed; they have the same
   interface. */ 

void gl__function_internal_error_helper(const char file[], int linenumber, const char mesg[]);

/* This function may be set to handle internal errors.  Dirsrv handles them in
   this way, by logging to plog.   It is int instead of void for historical
   reasons: older versions of the PCC (Portable C Compiler) cannot handle
   pointers to void functions. */

extern int (*internal_error_handler)(const char file[], int linenumber, const char mesg[]);

void gl_function_arguments_error(const char *format, ...);


int (*internal_error_handler)(const char file[], int line, const char mesg[]) = 0;


#endif /* OLDGAA_GL_INTERNAL_ERR_H */
