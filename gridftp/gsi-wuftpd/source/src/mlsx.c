    /*
      mlst/mlsx come from a draft standard for dealing with file listings
      in a manner that is standard across platforms and therefore parsable
      by clients.
    */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>


/* XXX this is from ftpd.c which has no header and declares it within it's
 * scope.  Should be moved to a header if refactoring is ever done*/
char *mapping_getcwd(char *path, size_t size);

void
add_date(char *work_str, const char *tag, time_t *work_tm)
{
    char *ptr;
    
    ptr = (char *)malloc(15);
    strftime(ptr,15, "%G%m%d%k%M%S", localtime(work_tm));
    sprintf(work_str, "%s%s=%s;", work_str, tag, ptr);
}

/* This is the method that produces a result line about an arbitrary file
   it is used by the parent mlsd and mlst routines to produce their output. */
int
get_fact_list(char *ret_val, int size, const char *file, const char *facts) 
{
    /* XXX what should be done with facts that aren't known? The spec implies
     * skipping, but i haven't seen it explicitely say this.  lang and media
     * type aren't specifed at a file system level and therefore cannot be
     * included in the return set.*/
    
    struct stat s;
    char *ptr;
    char mutable_facts[strlen(facts)];
    struct tm work_tm;
    int writable = 0;
    int executable = 0;
    
    strcpy(mutable_facts, facts);

    if (lstat(file, &s) != 0)	/* File doesn't exist, or is not readable by user */
        return 2;

    for(ptr=mutable_facts;*ptr;ptr++) {
        *ptr=tolower(*ptr);
    }
    
    if(strstr(mutable_facts, "type") )
    {
        if(S_ISREG(s.st_mode))
        {
            sprintf(ret_val, "Type=%s;", "file");
        }
        else if(S_ISDIR(s.st_mode))
        {
            sprintf(ret_val, "Type=%s;", "dir");
        }
        /*XXX the specification refers to IANA assigned numbers but I could
          find no reference to them.  In any case putting them in the generic
          'unix' branch provides some protection from misinterpretaion.*/
        else if(S_ISCHR(s.st_mode))
        {
            sprintf(ret_val, "Type=%s;", "OS.unix=chr");
        }
        else if(S_ISCHR(s.st_mode))
        {
            sprintf(ret_val, "Type=%s;", "OS.unix=chr");
        }
    }
    if( strstr(mutable_facts, "modify")) 
    {
        add_date(ret_val, "Modify", &s.st_mtime);        
    }

    if( strstr(mutable_facts, "charset"))
    {
        /* XXX only utf-8 characters are allowed in the namespace anyway so we
           should be safe here */
        sprintf(ret_val, "%sCharset=%s;", ret_val, "UTF-8");
    }

    /* Create is here and commented out to remind future reviewers
       that create isn't availabe in posix and, specifically, that
       ctime isn't it. 
    if( strstr(mutable_facts, "create")) 
    
        add_date(ret_val, "Create", &s.st_ctime);        
        } */

    if( strstr(mutable_facts, "size")) 
    {
        sprintf(ret_val, "%sSize=%lu;", ret_val, (long)s.st_size);
    }
    
    if( strstr(mutable_facts, "perm")) 
    {
        if( getuid() == s.st_uid ) 
        {
            sprintf(ret_val, "%sPerm=%s", ret_val, s.st_mode & S_IRUSR ? "r" : "");
            sprintf(ret_val, "%s%s", ret_val, s.st_mode & S_IWUSR ? "w" : "");
            sprintf(ret_val, "%s%s", ret_val, s.st_mode & S_IXUSR ? "x" : "");
            if(s.st_mode & S_IWUSR) 
            {
                writable = 1;
            }
            if(s.st_mode & S_IXUSR) 
            {
                executable = 1;
            }
            
        }
        else if( getuid() == s.st_gid ) 
        {
            sprintf(ret_val, "%sPerm=%s", ret_val, s.st_mode & S_IRGRP ? "r" : "");
            sprintf(ret_val, "%s%s", ret_val, s.st_mode & S_IWGRP ? "w" : "");
            sprintf(ret_val, "%s%s", ret_val, s.st_mode & S_IXGRP ? "x" : "");
            if(s.st_mode & S_IWGRP) 
            {
                writable = 1;
            }
            if(s.st_mode & S_IXGRP) 
            {
                executable = 1;
            }
        }
        else 
        {
            sprintf(ret_val, "%sPerm=%s", ret_val, s.st_mode & S_IROTH ? "r" : "");
            sprintf(ret_val, "%s%s", ret_val, s.st_mode & S_IWOTH ? "w" : "");
            sprintf(ret_val, "%s%s", ret_val, s.st_mode & S_IXOTH ? "x" : "");
            if(s.st_mode & S_IWOTH) 
            {
                writable = 1;
            }
            if(s.st_mode & S_IXOTH) 
            {
                executable = 1;
            }

        }
        if(S_ISDIR(s.st_mode) && writable) 
        {
            sprintf(ret_val, "%s%s", ret_val, "c");
        }
        else if(S_ISREG(s.st_mode) && writable)
        {
            sprintf(ret_val, "%s%s", ret_val, "df");
        }
        if(S_ISDIR(s.st_mode) && executable) 
        {
            sprintf(ret_val, "%s%s", ret_val, "elm");
        }
        sprintf(ret_val, "%s;", ret_val);
        
    }

    //printf("%s\n",ret_val);
    return 0;
    
}

char *options=0;

void
mlsx_options(const char *options) 
{
    if(!options) 
    {
        options = (char*)malloc(512);
    }
    strncpy(options, options, 512);
}

const char *
get_mlsx_options()
{
    return options;
}
