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

#include "globus_debug.h"
#include "globus_libc.h"
#include "globus_module.h"
#include "globus_common.h"

#ifdef BUILD_DEBUG

#if !defined(strdup)
char * strdup(const char *);
#endif

static
void
globus_l_debug_parse_level_names(
    char *                              my_names,
    char **                             my_levels)
{
    char *                              name;
    int                                 i;
    
    /* check for level names */
    /* prune whitespace */
    name = my_names + strspn(my_names, " \t\n");
    for(i = 0; i < 32; i++)
    {
        if(*name)
        {
            my_levels[i] = name;
            
            /* find end of name */
            name += strcspn(name, " \t\n");
            /* terminate previous name */
            if(*name)
            {
                *(name++) = 0;
                /* prune whitespace */
                name += strspn(name, " \t\n");
            }
        }
        else
        {
            my_levels[i] = GLOBUS_NULL;
        }
    }
}

static
unsigned
globus_l_debug_get_level(
    const char *                        env_name,
    char **                             my_levels,
    char *                              levels  /* gets mangled */)
{
    unsigned                            level;
    
    level = (unsigned) strtoul(levels, NULL, 10);
    if(level == 0)
    {
        char *                          next_name;
        int                             i;
        globus_bool_t                   negate = GLOBUS_FALSE;
        
        if(*levels == '^')
        {
            levels++;
            negate = GLOBUS_TRUE;
        }
        
        /* map all names in levels to my_levels */
        do
        {
            next_name = strchr(levels, '|');
            if(next_name)
            {
                *(next_name++) = 0;
            }
            
            for(i = 0;
                i < 32 && my_levels[i] && strcmp(levels, my_levels[i]) != 0;
                i++);
            
            if(i < 32 && my_levels[i])
            {
                /* matched name */
                level |= 1U << i;
            }
            else if(strcmp(levels, "ALL") == 0)
            {
                level = ~(0U);
            }
            else
            {
                fprintf(stderr,
                    _GCSL("Invalid level name (%s) in %s env variable... ignoring\n"),
                    levels,
                    env_name);
            }
        } while((levels = next_name));
        
        if(negate)
        {
            level = ~level;
        }
    }
    
    return level;
}

void
globus_debug_init(
    const char *                        env_name,
    const char *                        level_names,
    globus_debug_handle_t *             handle)
{
    char *                              tmp;

    if(handle->file)
    {
        return;
    }
    
    handle->levels = 0;
    handle->timestamp_levels = 0;
    handle->file = stderr;
    handle->thread_ids = GLOBUS_FALSE;
    handle->using_file = GLOBUS_FALSE;

    tmp = globus_module_getenv(env_name);
    if(tmp && *tmp)
    {
        char *                          my_names;
        char *                          my_levels[32];
        char *                          levels;
        char *                          filename;
        char *                          show_tid;
        char *                          timestamp_levels;
        
        levels = strdup(tmp);
        if(!levels)
        {
            return;
        }
        my_names = strdup(level_names);
        if(!my_names)
        {
            free(levels);
            return;
        }
        
        globus_l_debug_parse_level_names(my_names, my_levels);
        
        show_tid = GLOBUS_NULL;
        timestamp_levels = GLOBUS_NULL;
        filename = strchr(levels, ',');
        if(filename)
        {
            *(filename++) = 0;
            
            show_tid = strchr(filename, ',');
            if(show_tid)
            {
                *(show_tid++) = 0;
                
                timestamp_levels = strchr(show_tid, ',');
                if(timestamp_levels)
                {
                    *(timestamp_levels++) = 0;
                }
            }
        }
        
        handle->levels = 
            globus_l_debug_get_level(env_name, my_levels, levels);

        if(handle->levels)
        {
            globus_bool_t               append_pid = GLOBUS_FALSE;
            
            if(show_tid && *show_tid)
            {
                int                     flags;
                
                flags = atoi(show_tid);
                if((flags & 0x1))
                {
                    handle->thread_ids = GLOBUS_TRUE;
                }
                
                if((flags & 0x2))
                {
                    append_pid = GLOBUS_TRUE;
                }
            }
            
            if(filename && *filename)
            {
                char                    buf[1024];
                
                if(append_pid)
                {
                    sprintf(buf, "%s.%d", filename, (int) getpid());
                    filename = buf;
                }
                
                if(*filename == '#')
                {
                    filename += 1;
                    truncate(filename, 0);
                }
                
                handle->file = fopen(filename, "a");
                if(handle->file)
                {
                    handle->using_file = GLOBUS_TRUE;
                    setvbuf(handle->file, GLOBUS_NULL, _IONBF, 0);
                    fprintf(
                        handle->file, "### %d: %s ###\n", getpid(), env_name);
                }
                else
                {
                    handle->file = stderr;
                    fprintf(stderr,
                        _GCSL("%s: Could not open %s, "
                        "using stderr for debug messages\n"),
                        env_name,
                        filename);
                }
            }
            
            if(timestamp_levels)
            {
                handle->timestamp_levels = 
                    globus_l_debug_get_level(
                        env_name, my_levels, timestamp_levels);
            }
        }
        
        free(my_names);
        free(levels);
    }
}

#endif
