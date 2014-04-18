/*
 * Copyright 1999-2014 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
    GLOBUS_XIO_UDT_SET_FD,
    GLOBUS_XIO_UDT_GET_LOCAL_CANDIDATES,
    GLOBUS_XIO_UDT_SET_REMOTE_CANDIDATES
};

#endif
