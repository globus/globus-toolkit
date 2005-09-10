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

#include "globus_i_xio_udt.h"

/* default attr */
globus_l_attr_t                         globus_l_xio_udt_attr_default =
{
    GLOBUS_XIO_UDT_INVALID_HANDLE,    /* handle   */

    GLOBUS_NULL,                        /* listener_serv */
    0,                                  /* listener_port */
    -1,                                 /* listener_backlog (SOMAXCONN) */
    0,                                  /* listener_min_port */
    0,                                  /* listener_max_port */

    GLOBUS_NULL,                        /* bind_address */
    GLOBUS_TRUE,                        /* restrict_port */
    GLOBUS_FALSE,                       /* reuseaddr */

    GLOBUS_FALSE,                       /* keepalive */
    GLOBUS_FALSE,                       /* linger */
    0,                                  /* linger_time */
    GLOBUS_FALSE,                       /* oobinline */
    8388608,                            /* sndbuf */
    8388608,                            /* rcvbuf */
    GLOBUS_FALSE,                       /* nodelay */
    0,                                  /* connector_min_port */
    0,                                  /* connector_max_port */

    0,                                   /* send_flags */

    8388608,                            /* protocolbuf */
    1500,                               /* mss */
    25600                               /* window size */
};

      /*
       *  Functionality:                
       *     initialize driver attribute
       *  Parameters:                   
       *     1) [out] out_attr: udt driver attribute
       *  Returned value:               
       *     GLOBUS_SUCCESS if initialization is successful,
       *     otherwise a result object with an error
       */
    
globus_result_t
globus_l_xio_udt_attr_init(
    void **                             out_attr)
{      
    globus_l_attr_t *                   attr;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_udt_attr_init);
        
    GlobusXIOUdtDebugEnter();

    /*
     *  create a udt attr structure and intialize its values
     */ 
    attr = (globus_l_attr_t *) globus_malloc(sizeof(globus_l_attr_t));
    if(!attr)
    {
        result = GlobusXIOErrorMemory("attr");
        goto error_attr;
    }  
      
    memcpy(attr, &globus_l_xio_udt_attr_default, sizeof(globus_l_attr_t));
    *out_attr = attr;
        
    GlobusXIOUdtDebugExit();    
    return GLOBUS_SUCCESS;

error_attr:
    GlobusXIOUdtDebugExitWithError();
    return result;
}           
            
            
                
      /*        
       *  Functionality:
       *     modify/read driver attribute structure
       *  Parameters:
       *     1) [in] driver_attr: udt driver attribute
       *     2) [in] cmd: specifies what to do
       *     3) [in/out] depends on the value of cmd
       *  Returned value:
       *     GLOBUS_SUCCESS if there is no error, otherwise a result
       *     object with an error
       */
            
globus_result_t
globus_l_xio_udt_attr_cntl(
    void *                              driver_attr,
    int                                 cmd,
    va_list                             ap)
{       
    globus_l_attr_t *                   attr;
    globus_xio_system_socket_t *        out_handle;
    char **                             out_string;
    int *                               out_int;
    globus_bool_t *                     out_bool;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_udt_attr_cntl);

    GlobusXIOUdtDebugEnter();
    attr = (globus_l_attr_t *) driver_attr;
    switch(cmd)
    {

      /**
       *  server attrs
       */
      /* char *                         service_name */
      case GLOBUS_XIO_UDT_SET_SERVICE:
        if(attr->listener_serv)
        {
            globus_free(attr->listener_serv);
        }

        attr->listener_serv = va_arg(ap, char *);
        if(attr->listener_serv)
        {
            attr->listener_serv = globus_libc_strdup(attr->listener_serv);
            if(!attr->listener_serv)
            {
                result = GlobusXIOErrorMemory("listener_serv");
                goto error_memory;
            }
        }
        break;


      /* char **                        service_name_out */
      case GLOBUS_XIO_UDT_GET_SERVICE:
        out_string = va_arg(ap, char **);
        if(attr->listener_serv)
        {
            *out_string = globus_libc_strdup(attr->listener_serv);
            if(!*out_string)
            {
                result = GlobusXIOErrorMemory("listener_serv_out");
                goto error_memory;
            }
        }
        else
        {
            *out_string = GLOBUS_NULL;  
        }
        break;                          
      
      /* int                            listener_port */
      case GLOBUS_XIO_UDT_SET_PORT:
        attr->listener_port = va_arg(ap, int);
        break;
      
      /* int *                          listener_port_out */
      case GLOBUS_XIO_UDT_GET_PORT:
        out_int = va_arg(ap, int *);
        *out_int = attr->listener_port;
        break;
      
      /* int                            listener_backlog */
      case GLOBUS_XIO_UDT_SET_BACKLOG:
        attr->listener_backlog = va_arg(ap, int);
        break;
      
      /* int *                          listener_backlog_out */
      case GLOBUS_XIO_UDT_GET_BACKLOG:
        out_int = va_arg(ap, int *);
        *out_int = attr->listener_backlog;
        break;
      
      /* int                            listener_min_port */
      /* int                            listener_max_port */
      case GLOBUS_XIO_UDT_SET_LISTEN_RANGE:
        attr->listener_min_port = va_arg(ap, int);
        attr->listener_max_port = va_arg(ap, int);
        break;
            
      /* int *                          listener_min_port_out */
      /* int *                          listener_max_port_out */
      case GLOBUS_XIO_UDT_GET_LISTEN_RANGE:
        out_int = va_arg(ap, int *);
        *out_int = attr->listener_min_port;
        out_int = va_arg(ap, int *);
        *out_int = attr->listener_max_port;
        break;
                
      /**
       *  handle/server attrs
       */
      /* globus_xio_system_socket_t *   handle_out */
      case GLOBUS_XIO_UDT_GET_HANDLE:
        out_handle = va_arg(ap, globus_xio_system_socket_t *);
        *out_handle = attr->handle;
        break;
                
      /* globus_xio_system_socket_t     handle */
      case GLOBUS_XIO_UDT_SET_HANDLE:
        attr->handle = va_arg(ap, globus_xio_system_socket_t);
        break;

      /**   
       *  handle/server attrs
       */
      /* char *                         interface */
      case GLOBUS_XIO_UDT_SET_INTERFACE:
        if(attr->bind_address)          
        {
            globus_free(attr->bind_address);
        }
        
        attr->bind_address = va_arg(ap, char *);
        if(attr->bind_address)
        {   
            attr->bind_address = globus_libc_strdup(attr->bind_address);
            if(!attr->bind_address)
            {
                result = GlobusXIOErrorMemory("bind_address");
                goto error_memory;
            }
        }
        break;

      /* char **                        interface_out */
      case GLOBUS_XIO_UDT_GET_INTERFACE:
        out_string = va_arg(ap, char **);
        if(attr->bind_address)
        {
            *out_string = globus_libc_strdup(attr->bind_address);
            if(!*out_string)
            {
                result = GlobusXIOErrorMemory("bind_address_out");
                goto error_memory;
            }
        }
        else
        {
            *out_string = GLOBUS_NULL;
        }
        break;

      /* globus_bool_t                  restrict_port */
      case GLOBUS_XIO_UDT_SET_RESTRICT_PORT:
        attr->restrict_port = va_arg(ap, globus_bool_t);
        break;

      /* globus_bool_t *                restrict_port_out */
      case GLOBUS_XIO_UDT_GET_RESTRICT_PORT:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = attr->restrict_port;
        break;

      /* globus_bool_t                  resuseaddr */
      case GLOBUS_XIO_UDT_SET_REUSEADDR:
        attr->resuseaddr = va_arg(ap, globus_bool_t);
        break;


      /* globus_bool_t *                resuseaddr_out */
      case GLOBUS_XIO_UDT_GET_REUSEADDR:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = attr->resuseaddr;
        break;

      /**
       *  handle attrs
       */
      /* globus_bool_t                  keepalive */
      case GLOBUS_XIO_UDT_SET_KEEPALIVE:
        attr->keepalive = va_arg(ap, globus_bool_t);
        break;

      /* globus_bool_t *                keepalive_out */
      case GLOBUS_XIO_UDT_GET_KEEPALIVE:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = attr->keepalive;
        break;

      /* globus_bool_t                  linger */
      /* int                            linger_time */
      case GLOBUS_XIO_UDT_SET_LINGER:
        attr->linger = va_arg(ap, globus_bool_t);
        attr->linger_time = va_arg(ap, int);
        break;

      /* globus_bool_t *                linger_out */ 
      /* int *                          linger_time_out */
      case GLOBUS_XIO_UDT_GET_LINGER:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = attr->linger;
        out_int = va_arg(ap, int *);
        *out_int = attr->linger_time;
        break;
                
      /* globus_bool_t                  oobinline */
      case GLOBUS_XIO_UDT_SET_OOBINLINE:
        attr->oobinline = va_arg(ap, globus_bool_t);
        break;
        
      /* globus_bool_t *                oobinline_out */
      case GLOBUS_XIO_UDT_GET_OOBINLINE:
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = attr->oobinline;
        break;
         
      /* int                            sndbuf */
      case GLOBUS_XIO_UDT_SET_SNDBUF:
        attr->sndbuf = va_arg(ap, int);
        break;
      
      /* int *                          sndbuf_out */
      case GLOBUS_XIO_UDT_GET_SNDBUF:
        out_int = va_arg(ap, int *);
        *out_int = attr->sndbuf;
        break;
      
        
      /* int                            rcvbuf */
      case GLOBUS_XIO_UDT_SET_RCVBUF:
        attr->rcvbuf = va_arg(ap, int);
        break;
      
      /* int *                          rcvbuf_out */
      case GLOBUS_XIO_UDT_GET_RCVBUF:
        out_int = va_arg(ap, int *);
        *out_int = attr->rcvbuf;
        break;
       
      /* globus_bool_t                  nodelay */
      case GLOBUS_XIO_UDT_SET_NODELAY:  
        attr->nodelay = va_arg(ap, globus_bool_t);
        break;
        
      /* globus_bool_t *                nodelay_out */
      case GLOBUS_XIO_UDT_GET_NODELAY:  
        out_bool = va_arg(ap, globus_bool_t *);
        *out_bool = attr->nodelay;
        break;
        
      /* int                            connector_min_port */
      /* int                            connector_max_port */
      case GLOBUS_XIO_UDT_SET_CONNECT_RANGE:
        attr->connector_min_port = va_arg(ap, int);
        attr->connector_max_port = va_arg(ap, int);
        break;

      /* int *                          connector_min_port_out */
      /* int *                          connector_max_port_out */
      case GLOBUS_XIO_UDT_GET_CONNECT_RANGE:
        out_int = va_arg(ap, int *);
        *out_int = attr->connector_min_port;
        out_int = va_arg(ap, int *);
        *out_int = attr->connector_max_port;
        break;

      /**
       * data descriptors
       */
      /* int                            send_flags */
      case GLOBUS_XIO_UDT_SET_SEND_FLAGS:
        attr->send_flags = va_arg(ap, int);
        break;

      /* int *                          send_flags_out */
      case GLOBUS_XIO_UDT_GET_SEND_FLAGS:
        out_int = va_arg(ap, int *);
        *out_int = attr->send_flags;
        break;

      /* int                              udt buf */
      case GLOBUS_XIO_UDT_SET_PROTOCOL_BUF:
        attr->protocolbuf = va_arg(ap, int);
        break;

      /* int *                            udt buf_out */
      case GLOBUS_XIO_UDT_GET_PROTOCOL_BUF:
        out_int = va_arg(ap, int*);
        *out_int = attr->protocolbuf;
        break;

      /* int                              max_segment_size */
      case GLOBUS_XIO_UDT_SET_MSS:
        attr->mss = va_arg(ap, int);
        break;

      /* int *                            max_segment_size_out */
      case GLOBUS_XIO_UDT_GET_MSS:
        out_int = va_arg(ap, int*);
        *out_int = attr->mss;
        break;

      /* int                              window_size */
      case GLOBUS_XIO_UDT_SET_WND_SIZE:
        attr->max_flow_wnd_size = va_arg(ap, int);
        break;

      /* int *                            window_size_out */
      case GLOBUS_XIO_UDT_GET_WND_SIZE:
        out_int = va_arg(ap, int*);
        *out_int = attr->max_flow_wnd_size;
        break;

      case GLOBUS_XIO_UDT_SET_NO_IPV6:
      case GLOBUS_XIO_UDT_GET_NO_IPV6:
        break;
        
      default:
        result = GlobusXIOErrorInvalidCommand(cmd);
        goto error_invalid;             
        break;                          
    } 
        
    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;
        
error_memory:
error_invalid:
    GlobusXIOUdtDebugExitWithError();
    return result;
}      
      
      
        
      /*
       *  Functionality:
       *     copy attribute structure   
       *  Parameters:
       *     1) [out] dst: target attribute structure
       *     2) [in] src: source attribute structure
       *  Returned value:
       *     GLOBUS_SUCCESS if there is no error, otherwise a result object
       *     with an error                
       */
        
globus_result_t
globus_l_xio_udt_attr_copy(               
    void **                             dst,
    void *                              src)
{       
    globus_l_attr_t *                   attr;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_udt_attr_copy);
      
    GlobusXIOUdtDebugEnter();
        
    attr = (globus_l_attr_t *) globus_malloc(sizeof(globus_l_attr_t));
    if(!attr)
    { 
        result = GlobusXIOErrorMemory("attr");
        goto error_attr;
    }   

    memcpy(attr, src, sizeof(globus_l_attr_t));
      
    /*  
     * if there is any ptr in the attr structure do attr->xptr =
     * globus_libc_strdup(attr->xptr) and do if (!attr->xptr) { result =
     * GlobusXIOErrorMemory("xptr"); goto error_xptr; }   
     */
        
    *dst = attr; 
        
    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;
      
error_attr:
    GlobusXIOUdtDebugExitWithError();
    return result;
}       
        
        
    
      /*
       *  Functionality:
       *     destroy driver attribute structure
       *  Parameters:
       *     1) [in] driver_attr: udt driver attribute
       *  Returned value:
       *     GLOBUS_SUCCESS
       */

globus_result_t
globus_l_xio_udt_attr_destroy(
    void *                              driver_attr)
{      
    globus_l_attr_t *                   attr;
    GlobusXIOName(globus_l_xio_udt_attr_destroy);
       
    GlobusXIOUdtDebugEnter();
       
    attr = (globus_l_attr_t *) driver_attr;
    globus_free(attr);
       
    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;
}
