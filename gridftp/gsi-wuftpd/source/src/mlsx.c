    /*
      mlst/mlsx come from a draft standard for dealing with file listings
      in a manner that is standard across platforms and therefore parsable
      by clients.
    */
#include "config.h"
#include "proto.h"
#include "mlsx.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "globus_common.h"

char *mapping_getcwd(char *path, size_t size);

static char * options = NULL;

void
mlsx_options(
    const char *                        new_options) 
{
    if(options)
    {
        free(options);
    }
    
    if(new_options)
    {
        options = strdup(new_options);
    }
    else
    {
        options = NULL;
    }
}

static
const char *
get_mlsx_options()
{
    if(!options) 
    {
        return "Type;Size;Modify;Perm;Charset;UNIX.mode;UNIX.slink;Unique;";
    }
    
    return options;
}

static
void
get_abs_path(
    const char *                        path,
    char *                              abs_path,
    int                                 size)
{
    char *                              slash;
    
    if(!path)
    {
        mapping_getcwd(abs_path, size);
    }
    else if(*path == '/')
    {
        strncpy(abs_path, path, size);
    }
    else
    {
        char                            cwd[MAXPATHLEN];
        
        snprintf(
            abs_path,
            size,
            "%s/%s",
            mapping_getcwd(cwd, sizeof(cwd)),
            path);
    }
    
    abs_path[size - 1] = 0;
    
    slash = strrchr(abs_path, '/');
    if(slash && slash != abs_path && *(slash + 1) == '\0')
    {
        *slash = '\0';
    }
}

void 
mlst(
    const char *                        path)
{
    char                                full_path[MAXPATHLEN];
    char                                fact_str[2048];
    
    get_abs_path(path, full_path, sizeof(full_path));
    
    if(get_fact_string(
        fact_str, sizeof(fact_str), full_path, get_mlsx_options())) 
    {
        reply(501, "No such file or insufficient permissions");
    }
    else 
    {
        lreply(250, "Listing %s", full_path);
        lreply(0, " %s", fact_str);
        reply(250, "End of status");
    }
}

void 
mlsd(
    const char *                        path)
{
    char                                abs_path[MAXPATHLEN];
    char *                              gl;
    DIR *                               dir;
    char *                              cmd;
    
    get_abs_path(path, abs_path, sizeof(abs_path));
    
    dir = opendir(abs_path);
    if(!dir)
    {
        reply(501, "Not a directory or insufficient permissions");
    }
    else
    {
        char                                params[2048];
        
        closedir(dir);
        snprintf(
            params, sizeof(params), "%s %s", abs_path, get_mlsx_options());
        params[sizeof(params) - 1] = 0;
        
        globus_location(&gl);
        if(gl)
        {
            snprintf(abs_path, sizeof(abs_path), "%s/bin/ftpmlsd %%s", gl);
            abs_path[sizeof(abs_path) - 1] = 0;
            cmd = abs_path;
            free(gl);
        }
        else
        {
            cmd = "ftpmlsd %s";
        }
        
        retrieve(cmd, params, -1, -1);
    }
}
