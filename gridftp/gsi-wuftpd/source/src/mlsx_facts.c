#include "config.h"
#include "globus_common.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "proto.h"

#define NEEDS_ENCODING(c) \
    (!isgraph(c) || (c) == '%' || (c) == '=' || (c) == ';')

static const char *hex_chars = "0123456789ABCDEF";

/** Encode string using URL encoding from rfc1738 (sec 2.2). */
static
void
url_encode(
    const char *                        in_string,
    char **                             out_string)
{
    int                                 len;
    char *                              in_ptr;
    char *                              out_ptr;
    char                                out_buf[MAXPATHLEN * 3];

    in_ptr = (char *) in_string;
    out_ptr = out_buf;
    len = strlen(in_string);

    while(in_ptr < in_string + len)
    {
        if(NEEDS_ENCODING(*in_ptr))
        {
            *out_ptr++ = '%';
            *out_ptr++ = hex_chars[(*in_ptr >> 4) & 0xF];
            *out_ptr++ = hex_chars[*in_ptr & 0xF];
        } 
        else
        {
            *out_ptr++ = *in_ptr;
        }
        in_ptr++;
    }
    *out_ptr = '\0';
    *out_string = strdup(out_buf);    
}

static
void
make_date(
    char *                              work_str,
    int                                 size,
    const char *                        tag,
    time_t *                            work_tm)
{
    char                                buf[64];
    
    strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", gmtime(work_tm));
    snprintf(work_str, size, "%s=%s;", tag, buf);
    work_str[size - 1] = '\0';
}

/* This is the method that produces a result line about an arbitrary file
   it is used by the parent mlsd and mlst routines to produce their output. */
int
get_fact_string(
    char *                              ret_val,
    int                                 size,
    const char *                        path,
    const char *                        facts) 
{
    struct stat                         stat_buf;
    char *                              ptr;
    char *                              mutable_facts;
    const char *                        unqualified_path;
    char                                type_buf[100];
    char                                modify_buf[100];
    char                                charset_buf[100];
    char                                size_buf[100];
    char                                perm_buf[100];
    char                                mode_buf[100];
    char                                unique_buf[100];
    char                                slink_buf[MAXPATHLEN * 4];
    char                                target[MAXPATHLEN];
    char *                              encoded_target;
    
    mutable_facts = strdup(facts);
    if(!mutable_facts)
    {
        return 1;
    }

    if(lstat(path, &stat_buf) != 0)
    {
        /* File doesn't exist, or is not readable by user */
        free(mutable_facts);
        return 2;
    }

    for(ptr = mutable_facts; *ptr; ptr++)
    {
        *ptr = tolower(*ptr);
    }
    
    ptr = slink_buf;
    if(strstr(mutable_facts, "unix.slink"))
    {        
        if(S_ISLNK(stat_buf.st_mode))
        {
            if(stat(path, &stat_buf) != 0)
            {
                /* File doesn't exist, or is not readable by user */
                free(mutable_facts);
                return 2;
            }
            /* Get target of symlink. */
            if(wu_realpath(path, target, NULL) == NULL)
            {
                free(mutable_facts);
                return 3;         /* problem reading link */
            }
            url_encode(target, &encoded_target);

            strcpy(ptr, "UNIX.slink=");
            ptr += 11;
            strcpy(ptr, encoded_target);
            ptr += strlen(encoded_target);
            *(ptr++) = ';';
            
            free(encoded_target);
        }
    }
    *ptr = '\0';
    
    
    unqualified_path = strrchr(path, '/');
    if(unqualified_path)
    {
        unqualified_path += 1;
    }
    else
    {
        unqualified_path = path;
    }
    
    ptr = type_buf;
    if(strstr(mutable_facts, "type"))
    {
        strcpy(ptr, "Type=");
        ptr += 5;
        
        if(S_ISREG(stat_buf.st_mode))
        {
            strcpy(ptr, "file");
            ptr += 4;
        }
        else if(S_ISDIR(stat_buf.st_mode))
        {
            char *                      type = "dir";
            int                         len = 3;
            
            if(*unqualified_path == '.')
            {
                if(*(unqualified_path + 1) == '\0')
                {
                    type = "cdir";
                    len = 4;
                }
                else if(*(unqualified_path + 1) == '.' && 
                    *(unqualified_path + 2) == '\0')
                {
                    type = "pdir";
                    len = 4;
                }
            }
            
            strcpy(ptr, type);
            ptr += len;
        }
        else if(S_ISCHR(stat_buf.st_mode))
        {
            strcpy(ptr, "OS.unix=chr");
            ptr += 11;
        }
        else if(S_ISBLK(stat_buf.st_mode))
        {
            strcpy(ptr, "OS.unix=blk");
            ptr += 11;
        }        
        *(ptr++) = ';';
    }
    *ptr = '\0';
    
    *modify_buf = '\0';
    if(strstr(mutable_facts, "modify")) 
    {
        make_date(
            modify_buf, sizeof(modify_buf), "Modify", &stat_buf.st_mtime);
    }
    
    *charset_buf = '\0';
    if(strstr(mutable_facts, "charset"))
    {
        strcpy(charset_buf, "Charset=UTF-8;");
    }
    
    *size_buf = '\0';
    if(strstr(mutable_facts, "size")) 
    {
        sprintf(size_buf, "Size=%llu;", (unsigned long long) stat_buf.st_size);
    }
    
    ptr = perm_buf;
    if(strstr(mutable_facts, "perm")) 
    {
        int                             is_readable = 0;
        int                             is_writable = 0;
        int                             is_executable = 0;
        
        strcpy(ptr, "Perm=");
        ptr += 5;
        
        if(getuid() == stat_buf.st_uid)
        {
            if(stat_buf.st_mode & S_IRUSR)
            {
                is_readable = 1;
            }
            if(stat_buf.st_mode & S_IWUSR)
            {
                is_writable = 1;
            }
            if(stat_buf.st_mode & S_IXUSR)
            {
                is_executable = 1;
            }
        }
        
        /* XXX should check stat_buf.st_gid against all groups user is in */
        if(getuid() == stat_buf.st_gid)
        {
            if(stat_buf.st_mode & S_IRGRP)
            {
                is_readable = 1;
            }
            if(stat_buf.st_mode & S_IWGRP)
            {
                is_writable = 1;
            }
            if(stat_buf.st_mode & S_IXGRP)
            {
                is_executable = 1;
            }
        }
        
        if(stat_buf.st_mode & S_IROTH)
        {
            is_readable = 1;
        }
        if(stat_buf.st_mode & S_IWOTH)
        {
            is_writable = 1;
        }
        if(stat_buf.st_mode & S_IXOTH)
        {
            is_executable = 1;
        }
        
        /*
            The "a" permission applies to objects of type=file, and indicates
            that the APPE (append) command may be applied to the file named.
         */
        /*
           The "w" permission applies to type=file objects, and for some
           systems, perhaps to other types of objects, and indicates that the
           STOR command may be applied to the object named.
         */
        if(is_writable && S_ISREG(stat_buf.st_mode))
        {
            *(ptr++) = 'a';
            *(ptr++) = 'w';
        }

        /*
           The "c" permission applies to objects of type=dir (and type=pdir,
           type=cdir).  It indicates that files may be created in the directory
           named.  That is, that a STOU command is likely to succeed, and that
           STOR and APPE commands might succeed if the file named did not
           previously exist, but is to be created in the directory object that
           has the "c" permission.  It also indicates that the RNTO command is
           likely to succeed for names in the directory.
         */
        /*
           The "f" permission for objects indicates that the object named may be
           renamed - that is, may be the object of an RNFR command.
         */
        /*
           The "m" permission applies to directory types, and indicates that the
           MKD command may be used to create a new directory within the
           directory under consideration.
         */
        /*
           The "p" permission applies to directory types, and indicates that
           objects in the directory may be deleted, or (stretching naming a
           little) that the directory may be purged.  Note: it does not indicate
           that the RMD command may be used to remove the directory named
           itself, the "d" permission indicator indicates that.
         */
        if(is_writable && is_executable && S_ISDIR(stat_buf.st_mode))
        {
            *(ptr++) = 'c';
            *(ptr++) = 'f';
            *(ptr++) = 'm';
            *(ptr++) = 'p';
        }
        
        /*
           The "d" permission applies to all types.  It indicates that the
           object named may be deleted, that is, that the RMD command may be
           applied to it if it is a directory, and otherwise that the DELE
           command may be applied to it.
         
           XXX can't answer this without looking at parent directory
         */
        
        /*
           The "e" permission applies to the directory types.  When set on an
           object of type=dir, type=cdir, or type=pdir it indicates that a CWD
           command naming the object should succeed, and the user should be able
           to enter the directory named.  For type=pdir it also indicates that
           the CDUP command may succeed (if this particular pathname is the one
           to which a CDUP would apply.)
         */
        if(is_executable && S_ISDIR(stat_buf.st_mode))
        {
            *(ptr++) = 'e';
        }
        
        /*
           The "l" permission applies to the directory file types, and indicates
           that the listing commands, LIST, NLST, and MLSD may be applied to the
           directory in question.
         */
        if(is_readable && is_executable && S_ISDIR(stat_buf.st_mode))
        {
            *(ptr++) = 'l';
        }
        
        /*
           The "r" permission applies to type=file objects, and for some
           systems, perhaps to other types of objects, and indicates that the
           RETR command may be applied to that object.
         */
        if(is_readable && S_ISREG(stat_buf.st_mode))
        {
            *(ptr++) = 'r';
        }
        
        *(ptr++) = ';';
    }
    *ptr = '\0';
    
    *mode_buf = '\0';
    if(strstr(mutable_facts, "unix.mode")) 
    {
        sprintf(
            mode_buf,
            "UNIX.mode=%04o;",
            (unsigned) (stat_buf.st_mode & 07777));
    }
    
    *unique_buf = '\0';
    if(strstr(mutable_facts, "unique")) 
    {
        sprintf(
            unique_buf,
            "Unique=%lx-%lx;",
            (unsigned long) stat_buf.st_dev, (unsigned long) stat_buf.st_ino);
    }
    snprintf(
        ret_val,
        size,
        "%s%s%s%s%s%s%s%s %s",
        type_buf,
        size_buf,
        modify_buf,
        perm_buf,
        charset_buf,
        mode_buf,
        slink_buf,
        unique_buf,
        unqualified_path);
        
    ret_val[size - 1] = '\0';

    free(mutable_facts);
    return 0;

}
