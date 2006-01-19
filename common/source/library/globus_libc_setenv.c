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
 * Copyright (c) 1987, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* based on @(#)setenv.c	8.1 (Berkeley) 6/4/93 */
/* based on @(#)getenv.c	8.1 (Berkeley) 6/4/93 */

#include "globus_common_include.h"
#include "globus_libc.h"

#ifndef	__P
#define __P(x)	()
#endif
static char *globus_l_libc_findenv __P((const char *, globus_size_t *)); 

/**
 * globus_libc_setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
int
globus_libc_setenv(name, value, rewrite)
	register const char *name;
	register const char *value;
	int  rewrite;
{
	extern char **environ;
	static int alloced;			/* if allocated space before */
	register char *c;
	globus_size_t l_value, offset = 0;

	globus_libc_lock();

	if (*value == '=')			/* no `=' in value */
		++value;
	l_value = strlen(value);
	if ((c = globus_l_libc_findenv(name, &offset))) {	/* find if already exists */
		if (!rewrite)
		{
		    globus_libc_unlock();
		    return (0);
		}
		if (strlen(c) >= l_value) /* old larger; copy over */
        {	
            while ((*c++ = *value++));

		    globus_libc_unlock();
		    return (0);
		}
	} 
    else 
    {					/* create new slot */
		register int cnt;
		register char **p;

		for (p = environ, cnt = 0; *p; ++p, ++cnt);
		if (alloced) {			/* just increase size */
		    environ = (char **)realloc((char *)environ,
					       (size_t)(sizeof(char *) * (cnt + 2)));
		    if (!environ)
		    {
			globus_libc_unlock();
			return (-1);
		    }
		}
		else {				/* get new space */
			alloced = 1;		/* copy old entries into it */
			p = (char **)malloc((size_t)(sizeof(char *) * (cnt + 2)));
			if (!p)
			{
			    globus_libc_unlock();
			    return (-1);
			}
			memcpy(p, environ, cnt * sizeof(char *));
			environ = p;
		}
		environ[cnt + 1] = NULL;
		offset = (globus_size_t) cnt;
	}
	for (c = (char *)name; *c && *c != '='; ++c);	/* no `=' in name */
	if (!(environ[offset] =			/* name + `=' + value */
	    malloc((size_t)((int)(c - name) + l_value + 2))))
	{
	    globus_libc_unlock();
	    return (-1);
	}
	for (c = environ[offset]; (*c = *name++) && *c != '='; ++c);
	for (*c++ = '='; (*c++ = *value++););

	globus_libc_unlock();
	return (0);
}

/**
 * unsetenv(name) --
 *	Delete environmental variable "name".
 */
void
globus_libc_unsetenv(name)
	const char *name;
{
	extern char **environ;
	register char **p;
	globus_size_t offset;

	globus_libc_lock();
	
	while (globus_l_libc_findenv(name, &offset))	/* if set multiple times */
		for (p = &environ[offset];; ++p)
			if (!(*p = *(p + 1)))
				break;
	globus_libc_unlock();
}

/**
 * globus_libc_getenv --
 *	Returns ptr to value associated with name, if any, else NULL.
 */
char *
globus_libc_getenv(name)
	const char *name;
{
    globus_size_t offset;
    char          *ptr;

    globus_libc_lock();
    ptr = globus_l_libc_findenv(name, &offset);
    globus_libc_unlock();
    
    return ptr;
}

/**
 * globus_l_libc_findenv --
 *	Returns pointer to value associated with name, if any, else NULL.
 *	Sets offset to be the offset of the name/value combination in the
 *	environmental array, for use by setenv(3) and unsetenv(3).
 *	Explicitly removes '=' in argument name.
 */
static char *
globus_l_libc_findenv(name, offset)
    register const char *  name;
    globus_size_t *        offset;
{
    extern char **environ;
    register int len;
    register const char *np;
    register char **p, *c;
    
    if (name == NULL || environ == NULL)
	return (NULL);
    for (np = name; *np && *np != '='; ++np)
	continue;
    len = np - name;
    for (p = environ; (c = *p) != NULL; ++p)
	if (strncmp(c, name, len) == 0 && c[len] == '=') {
	    *offset = (globus_size_t)(p - environ);
	    return (c + len + 1);
	}
    return (NULL);
}


