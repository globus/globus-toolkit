#include "globus_debug.h"
#include "globus_libc.h"
#include "globus_module.h"

#ifdef BUILD_DEBUG

char * strdup(const char *);

static
unsigned
globus_l_debug_get_level(
    const char *                        env_name,
    const char *                        level_names,
    char *                              levels  /* gets mangled */)
{
    unsigned                            level;
    
    level = (unsigned) strtoul(levels, NULL, 10);
    if(level == 0)
    {
        char *                          my_names;
        char *                          name;
        char *                          next_name;
        char *                          my_levels[32];
        int                             i;
        globus_bool_t                   negate = GLOBUS_FALSE;
        
        my_names = strdup(level_names);
        if(!my_names)
        {
            return 0;
        }
        
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
                    "Invalid level name (%s) in %s env variable... ignoring\n",
                    levels,
                    env_name);
            }
        } while((levels = next_name));
        
        if(negate)
        {
            level = ~level;
        }
        
        free(my_names);
    }
    
    return level;
}

void
globus_debug_init(
    const char *                        env_name,
    const char *                        level_names,
    unsigned *                          debug_level,
    FILE **                             out_file,
    globus_bool_t *                     using_file,
    globus_bool_t *                     show_tids)
{
    char *                              tmp;

    if(*out_file)
    {
        return;
    }
    
    *debug_level = 0;
    *out_file = stderr;
    *using_file = GLOBUS_FALSE;
    *show_tids = GLOBUS_FALSE;

    tmp = globus_module_getenv(env_name);
    if(tmp && *tmp)
    {
        char *                          levels;
        char *                          filename;
        char *                          show_tid;
        
        levels = strdup(tmp);
        if(!levels)
        {
            return;
        }
        
        show_tid = GLOBUS_NULL;
        filename = strchr(levels, ',');
        if(filename)
        {
            *(filename++) = 0;
            
            show_tid = strchr(filename, ',');
            if(show_tid)
            {
                *(show_tid++) = 0;
            }
        }
        
        *debug_level = globus_l_debug_get_level(env_name, level_names, levels);

        if(*debug_level)
        {
            if(filename && *filename)
            {
                if(*filename == '#')
                {
                    filename += 1;
                    truncate(filename, 0);
                }
                
                *out_file = fopen(filename, "a");
                if(*out_file)
                {
                    *using_file = GLOBUS_TRUE;
                    setvbuf(*out_file, GLOBUS_NULL, _IONBF, 0);
                    fprintf(*out_file, "### %d: %s ###\n", getpid(), env_name);
                }
                else
                {
                    *out_file = stderr;
                    fprintf(stderr,
                        "%s: Could not open %s, "
                        "using stderr for debug messages\n",
                        env_name,
                        filename);
                }
            }
            
            if(show_tid && *show_tid != '0') /* I DO mean the digit 0 */
            {
                *show_tids = GLOBUS_TRUE;
            }
        }
        
        free(levels);
    }
}

#endif
