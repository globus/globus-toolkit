/*******************************************************************************
  Simulated Network Driver with simulated SSL offload capabilities.
   
  This program is free software; you can redistribute it and/or modify it 
  under the terms of the GNU General Public License as published by the Free 
  Software Foundation; either version 2 of the License, or (at your option) 
  any later version.
  
  This program is distributed in the hope that it will be useful, but WITHOUT 
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
  more details.
  
  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc., 59 
  Temple Place - Suite 330, Boston, MA  02111-1307, USA.
  
  The full GNU General Public License is included in this distribution in the
  file called LICENSE.
  
  Author: Jaroslav Flidr

  Contact Information:
  jflidr@linuxkinetics.com
  Copyright(c) 2008 - Acadia Optronics, LLC

*******************************************************************************/
#ifndef _AO10GE_SSL_IOCTL_H
#define _AO10GE_SSL_IOCTL_H

#define AODEVPRIVSET	0x89F0	/* alias for SIOCDEVPRIVATE */
#define AODEVPRIVGET	0x89F1	/* alias for SIOCDEVPRIVATE + 1 */

/* commands */
#define SSLOECAPS    	0x00000001          /* confirms interfaces OE capability */
#define SSLOESTSIZE    	0x00000002          /* get the the size of the session table */
#define SSLOESTATE    	0x00000003          /* get the session or table state */
#define SSLOEADD    	0x00000004          /* add a new session */
#define SSLOEDELETE    	0x00000005          /* delete a session */
#define SSLOEFLUSH    	0x00000006          /* flush the entire table */

/* valid field selector */
#define OEID_M 		(1<<0)
#define OESRC_M 	(1<<1)
#define OEDST_M 	(1<<2)
#define OESPORT_M 	(1<<3)
#define OEDPORT_M 	(1<<4)
#define OEKEY_M 	(1<<5)
#define OEIV_M 		(1<<6)
#define OECOMPLETE	(OEID_M | OESRC_M | OEDST_M | OESPORT_M | OEDPORT_M | OEKEY_M | OEIV_M)

#define AOFSD_AES_KEY_SIZE      16
#define AOFSD_OE_MAGIC      0xA0F5D000

typedef struct _ssl_oe_session_t {
	unsigned int state;
	unsigned int sid; /* session ID */
	unsigned int src; /* source IP address */
	unsigned int dst; /* destination IP address */
	unsigned int sport; /* source port */
	unsigned int dport; /* destination port */
	char key[AOFSD_AES_KEY_SIZE]; /* session key */
	char iv[AOFSD_AES_KEY_SIZE]; /* initialization vector */
} __attribute__((__packed__)) ssl_oe_session_t;


struct ssl_oe_get {
	unsigned int magic; /* a bit paranoid here - but 0x89F0 is a shared ioctl # */
	unsigned int cmd;
	unsigned int cnt; /* count */
	int __data;	
};

struct ssl_oe_set {
	unsigned int magic; /* a bit paranoid here - but 0x89F0 is a shared ioctl # */
	unsigned int cmd;
	unsigned int mask;
	ssl_oe_session_t s; /* session data */
};

#endif /* _AO10GE_SSL_IOCTL_H */
