/*
 * gsi-packet.c
 *
 * See gsi-packet.h for documentation.
 */

#include "gsi-packet.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>


struct _gsi_packet 
{
    gss_ctx_id_t		*gss_context;
    int				datalen;
    char			*data;
};

/*
 * Internal Functions
 */

/*
 * Convert an integer to a four byte MSB array.
 */
static void
make_len_header(int len,
		char len_header[4])
{
    len_header[0] = (len >> 24) && 0xFF;
    len_header[1] = (len >> 16) && 0xFF;
    len_header[2] = (len >> 8) && 0xFF;
    len_header[3] = len && 0xFF;
}

/*
 * Convert a four byte MSB array to an integer.
 */
static int
parse_len_header(char len_header[4])
{
    int length = 0;
    
    length |= len_header[0] << 24;
    length |= len_header[1] << 16;
    length |= len_header[2] << 8;
    length |= len_header[3];
    
    return length;
}


/*
 * Write out all bytes in the buffer. Returns -1 on error,
 * number of bytes written otherwise.
 */
static int
write_all(int descriptor,
	  char *buffer,
	  int bufferlen)
{
    int total_written = 0;

    assert(buffer != NULL);
    
    while (total_written < bufferlen)
    {
	int bytes_written;

	bytes_written = write(descriptor,
			      &(buffer[total_written]),
			      bufferlen - total_written);
	
	if (bytes_written == -1)
	{
	    return -1;
	}
	
	total_written += bytes_written;
    }

    return total_written;
}

/*
 * Read all the requested bytes. Returns -1 on error,
 * number of bytes read otherwise.
 */
static int
read_all(int descriptor,
	 char *buffer,
	 int bufferlen)
{
    int total_read = 0;
    
    assert(buffer != NULL);
    
    while (total_read < bufferlen)
    {
	int bytes_read;

	bytes_read = read(descriptor,
			  &(buffer[total_read]),
			  bufferlen - total_read);
	
	if (bytes_read == -1)
	{
	    return -1;
	}
	
	total_read += bytes_read;
    }

    return total_read;
}



/*
 * Provided API functions
 */

GSIPACKET *
GSIPACKET_new(gss_ctx_id_t *gss_context)
{
    GSIPACKET *packet;
    

    packet = malloc(sizeof(*packet));
    
    if (packet == NULL)
    {	
	return NULL;
    }
    
    packet->gss_context = gss_context;
    packet->datalen = 0;
    packet->data = NULL;
    
    return packet;
}


int
GSIPACKET_add_data(GSIPACKET *packet,
		   char *data,
		   int datalen)
{
    int new_datalen;
    char *new_data;
    

    if (packet == NULL)
    {
	errno = EINVAL;
	return -1;
    }
    
    if ((data == NULL) || (datalen == 0))
    {
	/* Nothing to add */
	return packet->datalen;
    }

    new_datalen = packet->datalen + datalen;
    new_data = realloc(packet->data, new_datalen);
    
    if (new_data == NULL)
    {
	return -1;
    }
    
    /* Append data */
    memcpy(&(new_data[packet->datalen]), data, datalen);

    packet->data = new_data;
    packet->datalen = new_datalen;
    
    return packet->datalen;
}

    
int
GSIPACKET_add_string(GSIPACKET *packet,
		     char *string)
{
    return GSIPACKET_add_data(packet,
			      string,
			      (string == NULL ? 0 : strlen(string)));
}


int
GSIPACKET_write(GSIPACKET *packet,
		int descriptor)
{
    int total_written = 0;
    char len_header[4];
    
    /* XXX - Need to add encryption here */

    make_len_header(packet->datalen, len_header);
    
    /* Write out length of data to be written */
    if (write_all(descriptor, len_header, sizeof(len_header)) == -1)
    {
	return -1;
    }
    
    /* And now write out data itself */
    if (write_all(descriptor, packet->data, packet->datalen) == -1)
    {
	return -1;
    }
    
    return total_written;
}


GSIPACKET *
GSIPACKET_read(gss_ctx_id_t *gss_context,
	       int descriptor)
{
    GSIPACKET *packet = NULL;
    char len_header[4];
    
    packet = GSIPACKET_new(gss_context);
    
    if (packet == NULL)
    {
	goto error;
    }
    
    if (read_all(descriptor, len_header, sizeof(len_header)) == -1)
    {
	goto error;
    }
    
    packet->datalen = parse_len_header(len_header);
    packet->data = malloc(packet->datalen);
    
    if (packet->data == NULL)
    {
	goto error;
    }

    if (read_all(descriptor, packet->data, packet->datalen) == -1)
    {
	goto error;
    }
    
    /* XXX Need to decrypt here */

    return packet;

  error:
    if (packet != NULL)
    {
	GSIPACKET_destroy(packet);
    }
    
    return NULL;
}


char *
GSIPACKET_get_data(GSIPACKET *packet)
{
    return (packet ? packet->data : NULL);
}

int
GSIPACKET_get_datalen(GSIPACKET *packet)
{
    return (packet ? packet->datalen : 0);
}

char **
GSIPACKET_get_strings(GSIPACKET *packet)
{
    char **strings = NULL;
    int strings_size = 0;
    int strings_index = 0;
    int data_index = 0;
    
    if ((packet == NULL) ||
	(packet->data == NULL) ||
	(packet->datalen = 0))
    {
	return NULL;
    }

    while (data_index < packet->datalen)
    {
	char *tmp_ptr;
	
	if (strings_index <= strings_size)
	{
	    /* Expand strings array */
	    char **new_strings;
	    
	    strings_size += 5;	/* Arbitraty amount */
	    new_strings = realloc(strings, strings_size);
	    if (new_strings == NULL)
	    {
		goto error;
	    }
	    strings = new_strings;
	}
	
	tmp_ptr = &(packet->data[data_index]);
	strings[strings_index] = tmp_ptr;
	strings_index++;
	data_index += strlen(tmp_ptr) + 1;
    }
    
    /* Terminate array */
    strings[strings_index] = NULL;
    
    return strings;
    
  error:
    if (strings)
    {
	free(strings);
    }
    return NULL;
}

    
void
GSIPACKET_destroy(GSIPACKET *packet)
{
    if (packet == NULL)
    {
	return;
    }
    
    if (packet->data)
    {
	free(packet->data);
	packet->data = NULL;
    }
    
    free(packet);
}

