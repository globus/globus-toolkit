#ifndef HAVE_GETLINE
#include <sys/types.h>
#include <limits.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#if !(__STDC_VERSION__ >= 199901L)
#define restrict
#endif

enum { CHUNKSIZE=128 };

ssize_t
seg_getline(char ** restrict linep, size_t * restrict linecapp, FILE * restrict stream)
{
    char * buf;
    size_t bufsize;
    size_t offset=0;
    ssize_t result=0;

    if (linep == NULL || linecapp == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    else if (stream == NULL)
    {
        errno = EBADF;
        return -1;
    }

    buf = *linep;
    bufsize = *linecapp;

    while (!feof(stream))
    {
        int ch;

        if (offset >= SSIZE_MAX)
        {
            errno = EOVERFLOW;
            result = -1;
            break;
        }
        
        ch = fgetc(stream);
        if (ch == EOF)
        {
            result = -1;
            break;
        }

        if ((offset+1) >= bufsize)
        {
            char * tmp = realloc(buf, bufsize + CHUNKSIZE);
            if (tmp == NULL)
            {
                ungetc(ch, stream);
                result = -1;
                break;
            }
            buf = tmp;
            bufsize += CHUNKSIZE;
        }
        buf[offset++] = (char) ((unsigned char) ch);
        if (ch == '\n')
        {
            result = offset;
            buf[offset++] = '\0';
            break;
        }
    }
    *linep = buf;
    *linecapp = bufsize;
    return result;
}
#endif /* HAVE_GETLINE */
