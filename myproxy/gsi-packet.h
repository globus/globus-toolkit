/*
 * gsi-packet.h
 *
 * Interface for sending GSI protected packets over a socket connection.
 *
 * Kudos to ssh and ssleay, from both of which I've borrowed ideas for
 * this.
 */

#ifndef __GSI_PACKET_H
#define __GSI_PACKET_H

#include <gssapi.h>

/*
 * Definition for the PACKET object.
 */
struct _gsi_packet;

typedef struct _gsi_packet GSIPACKET;

/*
 * GSIPACKET_new()
 *
 * Create a new GSIPACKET for later sending. Returns NULL on error.
 * gss_context is the context to be used for protecting the
 * packet.
 */
GSIPACKET *GSIPACKET_new(gss_ctx_id_t *gss_context);

/*
 * GSIPACKET_add_data()
 *
 * Add data to packet for later sending. Returns total bytes in packet
 * or -1 on error.
 */
int GSIPACKET_add_data(GSIPACKET *packet,
		       char *data,
		       int datalen);

/*
 * GSIPACKET_add_string()
 *
 * Add a NUL-terminated string to the packet for later sending. Returns
 * total bytes in packet or -1 on error.
 */
int GSIPACKET_add_string(GSIPACKET *packet,
			 char *string);

/*
 * GSIPACKET_write()
 *
 * Write the packet to the given descriptor. Returns total data bytes written
 * or -1 on error.
 */
int GSIPACKET_write(GSIPACKET *packet,
		    int descriptor);

/*
 * GSIPACKET_read()
 *
 * Read a GSIPACKET from the given descriptor. Returns NULL on error.
 */
GSIPACKET *GSIPACKET_read(gss_ctx_id_t *gss_context,
			  int descriptor);

/*
 * GSIPACKET_get_data()
 *
 * Return a pointer to the data contained in a packet. Note that this 
 * buffer will be freed if GSIPACKET_destroy() is called. It should be
 * duplicated before it is modified. Returns NULL if the packet has
 * no data associated with it.
 */
char *GSIPACKET_get_data(GSIPACKET *packet);

/*
 * GSIPACKET_get_datalen()
 *
 * Return the number of bytes of data contained in the packet.
 */
int GSIPACKET_get_datalen();

/*
 * GSIPACKET_get_strings()
 *
 * Returns a NULL-terminated array of pointers to NUL-terminated
 * strings as contained in the pasted packet. Note that these
 * strings will be freed if GSIPACKET_destroy() is called, so
 * they should be copied before they are modified. Note that
 * if the packet doesn't contain strings, bad things are liable
 * to happen if this function is called. The array returned by
 * this function should be freed by the caller.
 */
char **GSIPACKET_get_strings(GSIPACKET *packet);

/*
 * GSIPACKET_destroy()
 *
 * Deallocate all memory associated with a GSIPACKET.
 */
void GSIPACKET_destroy(GSIPACKET *);

#endif /* __GSIPACKET_H */
