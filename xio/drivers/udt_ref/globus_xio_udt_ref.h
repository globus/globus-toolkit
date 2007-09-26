/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#ifndef GLOBUS_XIO_UDT_REF_H
#define GLOBUS_XIO_UDT_REF_H

enum
{
    GLOBUS_XIO_UDT_MSS = 1,
    GLOBUS_XIO_UDT_SNDSYN,
    GLOBUS_XIO_UDT_RCVSYN,
    GLOBUS_XIO_UDT_FC,  
    GLOBUS_XIO_UDT_SNDBUF,  
    GLOBUS_XIO_UDT_RCVBUF, 
    GLOBUS_XIO_UDT_UDP_SNDBUF,  
    GLOBUS_XIO_UDT_UDP_RCVBUF, 
    GLOBUS_XIO_UDT_LINGER,  
    GLOBUS_XIO_UDT_RENDEZVOUS, 
    GLOBUS_XIO_UDT_SNDTIMEO,  
    GLOBUS_XIO_UDT_RCVTIMEO, 
    GLOBUS_XIO_UDT_REUSEADDR,
    GLOBUS_XIO_UDT_SET_LOCAL_PORT,
    GLOBUS_XIO_UDT_GET_LOCAL_PORT,
};

#endif
