#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/md5.h>
#include "cksmcmd.h"

#define CKSM_BUFSIZE 1024*1024

void 
cksmcmd(
    char *                              filename,
    char *                              algorithm,
    globus_off_t                        offset,
    globus_off_t                        length)
{
    MD5_CTX                             mdctx;
    char *                              md5ptr;
    unsigned char                                md[MD5_DIGEST_LENGTH];
    char                                md5sum[MD5_DIGEST_LENGTH * 2 + 1];
    char                                buf[CKSM_BUFSIZE];

    int                                 i;
    int                                 fd;
    int                                 n;
    globus_off_t                        count;
    globus_off_t                        read_left;
    

    if(offset < 0)
    {
        goto param_error;
    }
       
    if(length >= 0)
    {
        read_left = length;
        count = (read_left > CKSM_BUFSIZE) ? CKSM_BUFSIZE : read_left;
    }
    else
    {
        count = CKSM_BUFSIZE;
    }
    
    fd = open(filename, O_RDONLY);        
    if(fd < 0)
    {
        goto fd_error;
    }

    if (lseek(fd, offset, SEEK_SET) == -1)
    {
        goto seek_error;
    }

    
    MD5_Init(&mdctx);        

    while((n = read(fd, buf, count)) > 0)
    {
        if(length >= 0)
        {
            read_left -= n;
            count = (read_left > CKSM_BUFSIZE) ? CKSM_BUFSIZE : read_left;
        }

        MD5_Update(&mdctx, buf, n);
    }

    MD5_Final(md, &mdctx);
    
    close(fd);
        
    md5ptr = md5sum;
    for(i = 0; i < MD5_DIGEST_LENGTH; i++)
    {
       sprintf(md5ptr, "%02x", md[i]);
       md5ptr++;
       md5ptr++;
    }
    md5ptr = '\0';
    
    reply(213, "%s", md5sum);
    
    return;
    
seek_error:
    close(fd);
fd_error:
param_error:
    reply(501, "Error calculating checksum");

    return;
}

