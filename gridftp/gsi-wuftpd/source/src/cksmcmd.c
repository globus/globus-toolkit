#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/md5.h>
#include "cksmcmd.h"

void cksmcmd(char *filename,
	     char *algorithm,
	     globus_off_t offset,
	     globus_off_t length)
{
      MD5_CTX mdctx;
      /*int mdctx;*/
      unsigned char *md;
      int i;
      int fd, n;
      int count = 0;
      char buf[SSIZE_MAX];
      char md5sum[MD5_DIGEST_LENGTH];
      char * md5ptr;

      md=malloc(MD5_DIGEST_LENGTH);

      fd=open(filename, O_RDONLY);

      MD5_Init(&mdctx);

      if (fd >=0 )
      {
           if (lseek(fd, offset, SEEK_SET) ==-1)
	   {
           /*     printf("seek failed\n");*/
	   }
           else
                while ((n = read(fd, buf, length)) >0)
                {
                      MD5_Update(&mdctx, buf, n);
                   /*   printf ("this is n=%d \nthis is a read: %s",n,buf);*/
                }
           close(fd);

           if (n<0)
           {
              /*   printf ("read error\n");*/
           }
       }


       MD5_Final(md, &mdctx);
       md5ptr=md5sum;
       for(i = 0; i < MD5_DIGEST_LENGTH; i++)
       {
	       sprintf(md5ptr,"%02x", md[i]);
	       md5ptr++;
	       md5ptr++;
       }
       reply(213, "%s", md5sum);
     /*  printf("\n");*/

}

