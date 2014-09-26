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

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_common_paths.c
 * @brief Install and deploy path discovery functions
 */
#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

#include "globus_i_common_config.h"
#include "globus_common.h"
#include "globus_l_common_paths.h"

#include <string.h>

/******************************************************************************
                           ERROR object declaration

     this API returns ONE type of error object, where instance_data is a
           string with a somewhat descriptive error message.
******************************************************************************/

/* forward declarations */
char *
globus_l_common_path_error_message(globus_object_t *  error);

void
globus_l_common_path_error_copy( void *  source,
				 void ** dest );

void
globus_l_common_path_error_destruct( void * object );

static globus_object_type_t GLOBUS_COMMON_PATH_ERROR_DEFINITION
= globus_error_type_static_initializer( GLOBUS_ERROR_TYPE_BASE,
					globus_l_common_path_error_copy,
					globus_l_common_path_error_destruct,
					globus_l_common_path_error_message );


#define GLOBUS_COMMON_PATH_ERROR (&GLOBUS_COMMON_PATH_ERROR_DEFINITION)

#define GLOBUS_COMMON_PATH_ERROR_INSTANCE(errmsg) \
           globus_error_put(globus_l_common_path_error_instance(errmsg))

globus_object_t *
globus_l_common_path_error_instance(char * errmsg)
{
    globus_object_t  * d = globus_object_construct(GLOBUS_COMMON_PATH_ERROR);
    d->instance_data = globus_libc_strdup(errmsg);
    return d;
}

char *
globus_l_common_path_error_message(globus_object_t *  error)
{
    return globus_libc_strdup((char *) error->instance_data);
}

void
globus_l_common_path_error_copy( void *  source,
				 void ** dest )
{
    *dest = (void *) globus_libc_strdup( (char *) source );
}

void
globus_l_common_path_error_destruct( void * data )
{
    globus_free( data );
}



/******************************************************************************
               for now, install and deploy directories are found
                        using env vars GLOBUS_*_PATH
******************************************************************************/

globus_result_t
globus_l_common_env_path( char** bufp, char* name )
{
    char     errmsg[256];
    char *   p;

    *bufp = GLOBUS_NULL;
    p = getenv(name);
    if (!p || strlen(p)==0)
    {
	globus_libc_sprintf(errmsg,_GCSL("Environment variable %s is not set"), name);
	return GLOBUS_COMMON_PATH_ERROR_INSTANCE(errmsg);
    }

    *bufp = globus_libc_strdup(p);
    if (! *bufp)
    {
	return GLOBUS_COMMON_PATH_ERROR_INSTANCE(_GCSL("malloc error"));
    }
    
    return GLOBUS_SUCCESS;
}


globus_result_t
globus_location( char **   bufp )
{
    globus_result_t result;

    result = globus_l_common_env_path(bufp, "GLOBUS_LOCATION");

    if (result != GLOBUS_SUCCESS)
    {
        *bufp = strdup(globus_l_common_path_lookup_table[0].path);
        if (! *bufp)
        {
            return GLOBUS_COMMON_PATH_ERROR_INSTANCE(_GCSL("malloc error"));
        }
        else
        {
            result = GLOBUS_SUCCESS;
        }
    }
    return result;
}


/**
 * @ingroup globus_common
 * 
 * @param pathstring
 *     A string containing any number of variable path references using the
 *     syntax ${PATH-NAME} Supported path elements are
 *     - prefix
 *     - exec_prefix
 *     - sbindir
 *     - bindir
 *     - libdir
 *     - libexecdir
 *     - includedir
 *     - datarootdir
 *     - datadir
 *     - mandir
 *     - sysconfdir
 *     - sharedstatedir
 *     - localstatedir
 *     - perlmoduledir
 *     These strings are based on the parameters passed to this package
 *     configure script, but modified so that if GLOBUS_LOCATION is
 *     set in the environment, it is used instead of the configured path.
 * @param bufp
 *     Pointer to be set to a newly allocated string that has recursively
 *     resolved all substitution paths.
 */
globus_result_t
globus_eval_path(const char * pathstring, char **bufp)
{
    char * tmp;
    char * newtmp;
    char * location = getenv("GLOBUS_LOCATION");
    int i;

    if (location != NULL)
    {
        globus_l_common_path_lookup_table[0].path = location;
    }

    *bufp = NULL;

    tmp = strdup(pathstring);
    while (tmp != NULL && strchr(tmp, '$') != 0)
    {
        char * end = NULL;
        if ((newtmp = strstr(tmp, "${")) != NULL)
        {
            *newtmp = 0;
            newtmp = newtmp + 2;
            end = strstr(newtmp, "}");

            if (end == NULL)
            {
                free(tmp);
                tmp = NULL;
                break;
            }
            *end = 0;
        }
        for (i = 0; globus_l_common_path_lookup_table[i].name != NULL; i++)
        {
            if (strcmp(newtmp, globus_l_common_path_lookup_table[i].name) == 0)
            {
                newtmp = malloc(strlen(tmp) + strlen(globus_l_common_path_lookup_table[i].path) + (end ? strlen(end+1):0) + 1);
                if (newtmp == NULL)
                {
                    free(tmp);
                    tmp = NULL;
                }
                else
                {
                    sprintf(newtmp, "%s%s%s",
                        tmp, globus_l_common_path_lookup_table[i].path, end?end+1:"");
                    free(tmp);
                    tmp = newtmp;
                }
                break;
            }
        } 
    }
    if (tmp != NULL)
    {
        *bufp = tmp;
        return GLOBUS_SUCCESS;
    }
    else
    {
        return GLOBUS_COMMON_PATH_ERROR_INSTANCE(_GCSL("Can't resolve path"));
    }
}

/*****************************************************************************
                                 help function
  fgets() usually doesn't return the last line correctly if there's no 
  trailing \n. This function returns 1 when information was read and 0 when
  there is no more info left.

*****************************************************************************/
static int   globus_l_common_path_fgets_c = 0;

void
globus_l_common_path_fgets_init()
{
    globus_l_common_path_fgets_c = 0;
}

int
globus_l_common_path_fgets( char* buf, int bufsize, FILE* fp )
{
    int          c;
    int          n;
    
    c = globus_l_common_path_fgets_c;
    if (c==EOF)
	return 0;
    c=0;
    n=0;
    while (n<bufsize && EOF!=(c=fgetc(fp)) && c!='\n')
    {
	buf[n++] = c;
    }

    buf[n] = '\0';
    globus_l_common_path_fgets_c = c;
    
    return 1;
}


/*****************************************************************************
  processes a config file in the deploy dir and retrieves the value of
  a ATTRIBUTE=VALUE line in that file.
*****************************************************************************/

globus_result_t
globus_common_get_attribute_from_config_file( char *   deploy_path,
					      char *   file_location,
					      char *   attribute,
					      char **  value )
{
    globus_result_t   result;
    FILE *            fp;
    char *            p;
    char *            q;
    char *            deploy;
    char *            filename;
    char              attr[200];    /* assumes a name won't be longer... */
    char              buf[2000];    /* assumes a line won't be longer... */
    int               attr_len;
    int               status;

    result = GLOBUS_SUCCESS;
    *value = GLOBUS_NULL;
    deploy = deploy_path;

    if (!deploy && (result=globus_location(&deploy)))
	return result;

    filename = globus_malloc(strlen(deploy) +
			     strlen(file_location) + 1 + 1 );
    if (!filename)
	return GLOBUS_COMMON_PATH_ERROR_INSTANCE(_GCSL("malloc error"));
    
    globus_libc_sprintf(filename,
			"%s/%s",
			deploy,
			file_location);

    if (!deploy_path)
	globus_free(deploy);

    fp = fopen(filename,"r");
    if (!fp)
    {
	globus_libc_sprintf(buf,
			    _GCSL("failed to open %s"),
			    filename);
	return GLOBUS_COMMON_PATH_ERROR_INSTANCE( buf );
    }

    globus_l_common_path_fgets_init();
    p=GLOBUS_NULL;

    globus_libc_sprintf(attr, "%s=", attribute);
    attr_len = strlen(attr);

    while(!p && (status=globus_l_common_path_fgets(buf,sizeof(buf),fp)))
    {
	/* any white space? */
	q = buf;
	while (*q==' ' || *q=='\t')
	    q++;

	if (strncmp(q, attr, attr_len) == 0)
	    p = q + attr_len;
    }

    fclose(fp);
    globus_free(filename);
    if (p)
    {
	/* any enclosing quotes or trailing white space? */
	if (*p == '"')
	    ++p;

	q = p + strlen(p) - 1;  /* last char before \0 */
	while (q > p && (*q==' ' || *q=='\t' || *q=='\n' || *q=='"'))
	{
	    *q = '\0';
	    --q;
	}
    }

    if (!p || strlen(p)==0)
    {
	globus_libc_sprintf(buf,
			    _GCSL("could not resolve %s from config file"),
			    attribute);
	return GLOBUS_COMMON_PATH_ERROR_INSTANCE( buf );
    }

    *value = globus_libc_strdup(p);
    if (! *value)
	return GLOBUS_COMMON_PATH_ERROR_INSTANCE(_GCSL("malloc error"));

    return GLOBUS_SUCCESS;
}

