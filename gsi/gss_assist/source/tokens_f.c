
/******************************************************************************
token_f.c

Description:
	globus_gss_assist get/send token routines using fread and fwrite

	Additional code has been added to detect tokens which 
	are sent without a length field. These can currently be
	only SSL tokens. This does require some knowledge of the 
	underlying GSSAPI, by the application, but is within the 
	guidelines of the GSSAPI specifications. 

	The get routine will automaticly attempt this test,
	while a new send routine will check a flag. The old send
	routine will work as before, sending a 4-byte length.

CVS Information:

    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/

/******************************************************************************
                             Include header files
******************************************************************************/
#include "globus_gss_assist.h"
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
/******************************************************************************
                               Type definitions
******************************************************************************/
/******************************************************************************
                          Module specific prototypes
******************************************************************************/
/******************************************************************************
                       Define module specific variables
******************************************************************************/

/******************************************************************************
Function:	globus_gss_assist_token_get_fd()

Description:
	Use a open file discriptor to get a token

Parameters:

Returns:
	return 0 on success
		> 0 is internal return
		< 0 is the -errno 

******************************************************************************/
int
globus_gss_assist_token_get_fd(void *arg, void **bufp, size_t *sizep)
{
	unsigned char int_buf[5];
	unsigned char *pp;
	unsigned char *bp = NULL;
	int  bsize;
	int  dsize;
	int  size;
	void *cp;
	FILE * fd;
	int bytesread;

	fd = (FILE *) arg;
	if ((bytesread=fread(int_buf, 1, 4, fd)) != 4)
	{
		fprintf(stderr,"Failed reading length %d\n",bytesread);
		return GLOBUS_GSS_ASSIST_TOKEN_EOF;
	}

#ifdef DEBUG
	fprintf(stderr,"token read:%2.2x%2.2x%2.2x%2.2x\n",
   	int_buf[0],int_buf[1],int_buf[2],int_buf[3]);
#endif
	/*
	 * check if the length is missing, and we are receiving 
	 * a SSL token directly. 
	 * SSLv3 will start with a flag byte in the twenties
	 * followed by major version 3 minor version 0  
	 * Will also accept a SSLv2 hello 2 0 
	 * or a TLS  3 1
	 */
	 
	if (int_buf[0]  >= 20 && int_buf[0] <= 26 
		&& (((int_buf[1] == 3 && (int_buf[2] == 0) || int_buf[2] == 1))
			|| (int_buf[1] == 2 && int_buf[2] == 0))
		|| ((int_buf[0] & 0x80) && int_buf[2] == 1))
	{
		/* looks like a SSL token read rest of length */

		if (fread(&int_buf[4], 1, 1, fd) != 1)
		{
#ifdef DEBUG
			fprintf(stderr,"FAILED READING EXTRA BYTE\n");
#endif
			return GLOBUS_GSS_ASSIST_TOKEN_EOF;
		}

#ifdef DEBUG
        fprintf(stderr,"reading SSL token %.2x%.2x%.2x%.2x%.2x\n",
            int_buf[0],int_buf[1],int_buf[2],int_buf[3],int_buf[4]);
#endif

		if ((int_buf[0] & 0x80)) {
			/* looks like a sslv2 hello 
			 * length is of following bytes in header. 
			 * we read in 5, 2 length and 3 extra, 
			 * so only need next dsize -3
			 */
			dsize = ( ((unsigned int) int_buf[0] & 0x7f)<<8 
					| (unsigned int) int_buf[1]) - 3;
		} else {
			dsize = (  ( ((unsigned int) int_buf[3]) << 8)
					 |   ((unsigned int) int_buf[4]) );
		}

		/* If we are using the globus_ssleay, with 
		 * international version, we may be using the 
		 * "26" type, where the length is really the hash 
		 * length, and there is a hash, 8 byte seq andi
		 * 4 byte data length following. We need to get
		 * these as well. 
		 */

		if (int_buf[0] == 26 ) 
		{
			bsize = dsize + 12;  /* MD, seq, data-length */
			bp = (void *)malloc(bsize);
			if (!bp)
			{
				return GLOBUS_GSS_ASSIST_TOKEN_ERR_MALLOC;
			}
			if (fread(bp, 1, bsize, fd) != bsize)
			{
				return GLOBUS_GSS_ASSIST_TOKEN_EOF;
			}
			dsize = (  ( ((unsigned int) bp[bsize-4]) << 24)
					 | ( ((unsigned int) bp[bsize-3]) << 16)
					 | ( ((unsigned int) bp[bsize-2]) << 8)
					 |   ((unsigned int) bp[bsize-1]) );
		
			size = bsize + dsize + 5;
		}
		else
		{
			size = dsize + 5; 
		}
		cp = (void *)malloc(size);				
		if (!cp)
		{
			return GLOBUS_GSS_ASSIST_TOKEN_ERR_MALLOC;
		}

		/* reassemble token header from in_buf and bp */

		pp = cp;
		memcpy(pp,int_buf,5);
		pp += 5;
		if (bp)
		{
			memcpy(pp,bp,bsize);
			pp += bsize;
			free(bp);
			bp = NULL;
		}
		if ((bytesread=fread(pp, 1, dsize, fd)) != dsize)
		{
#ifdef DEBUG
			fprintf(stderr,"READ SHORT: %d, %d\n",dsize,bytesread);
#endif
	    	return GLOBUS_GSS_ASSIST_TOKEN_EOF;
		}
	}
	else
	{
		size = (  ( ((unsigned int) int_buf[0]) << 24)
				| ( ((unsigned int) int_buf[1]) << 16)
				| ( ((unsigned int) int_buf[2]) << 8)
				|   ((unsigned int) int_buf[3]) );

		if (size > 1<<24)  /* size may be garbage */
		{
	  		return GLOBUS_GSS_ASSIST_TOKEN_ERR_BAD_SIZE; 
		}

		cp = (void *)malloc(size);
		if (!cp)
		{
			return GLOBUS_GSS_ASSIST_TOKEN_ERR_MALLOC;
		}
		if ((bytesread=fread(cp, 1, size, fd)) != size)
		{
#ifdef DEBUG
			fprintf(stderr,"read short: %d, %d\n",size,bytesread);
#endif
	    	return GLOBUS_GSS_ASSIST_TOKEN_EOF;
		}
	}
	*bufp = cp;
	*sizep = size;
	return(0);
}

/******************************************************************************
Function:	globus_gss_assist_token_send_fd()

Description:
	Write a token to the open file descripter. 
	Will write it with a 4 byte length. 
	
Parameters:
Returns:
******************************************************************************/
int
globus_gss_assist_token_send_fd(void *arg,  void *buf, size_t size)
{
	globus_gss_assist_ex ex; 

	ex.arg = arg;
	ex.flags = 0;

	return(globus_gss_assist_token_send_fd_ex((void *)&ex, buf, size));
}

/******************************************************************************
Function:	globus_gss_assist_token_send_fd_without_length()

Description:
	Write a token to the open file descripter. 
	Will write it without a length. so as to 
	
Parameters:
Returns:
******************************************************************************/
int
globus_gss_assist_token_send_fd_without_length(void *arg,  void *buf, size_t size)
{
	globus_gss_assist_ex ex;
	
	ex.arg  = arg;
	ex.flags = GLOBUS_GSS_ASSIST_EX_SEND_WITHOUT_LENGTH;

	return(globus_gss_assist_token_send_fd_ex((void *)&ex, buf, size));
}

/******************************************************************************
Function:	globus_gss_assist_token_send_fd_flag_ex()

Description:
	Write a token to the open file descripter. 
	will look at the flag to determine if the length field need
	to be written.
	
Parameters:
Returns:
******************************************************************************/
int
globus_gss_assist_token_send_fd_ex(void *exp,  void *buf, size_t size)
{
	unsigned char int_buf[4];
	char *header = (char *)buf;
	FILE * fd;
	globus_gss_assist_ex *ex;
	
	ex = (globus_gss_assist_ex *) exp;
	fd = (FILE *) ex->arg;

	/*
	 * Will always send SSL type tokens without a length
	 */

#ifdef DEBUG
	fprintf(stderr,"send_token:flags:%d length:%d ",
				ex->flags, size);
#endif
	if (!(size > 5 && header[0] <= 26 && header[0] >= 20
             && ((header[1] == 3 && (header[2] == 0 || header[2] == 1))
                 || (header[1] == 2 && header[2] == 0))))
	{

		if (!(ex->flags & GLOBUS_GSS_ASSIST_EX_SEND_WITHOUT_LENGTH)) 
		{
			int_buf[0] =  size >> 24;
			int_buf[1] =  size >> 16;
			int_buf[2] =  size >>  8;
			int_buf[3] =  size;
	
#ifdef DEBUG
	fprintf(stderr,"with 4 byte length");
#endif
			if (fwrite(int_buf ,1 ,4 , fd) != 4)
			{
				return GLOBUS_GSS_ASSIST_TOKEN_EOF;
			}
		}
	}
#ifdef DEBUG
	fprintf(stderr,"\n");
#endif
	if (fwrite(buf, 1, size, fd) != size)
	{
	    return GLOBUS_GSS_ASSIST_TOKEN_EOF;
	}
	return(0);
}
