#ifdef GLOBUS_SEPARATE_DOCS
/**
 * @file globus_ftp_control.c
 *
 * FTP Control API Activation/Deactivation and Global State
 *
 */
#endif

#include "globus_ftp_control.h"
#include "globus_i_ftp_control.h"
#ifndef TARGET_ARCH_WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include "version.h"

#undef GLOBUS_FAILURE
#define GLOBUS_FAILURE globus_error_put(GLOBUS_ERROR_NO_INFO)

static int globus_l_ftp_control_activate(void);
static int globus_l_ftp_control_deactivate(void);

globus_module_descriptor_t globus_i_ftp_control_module =
{
    "globus_ftp_control",
    globus_l_ftp_control_activate,
    globus_l_ftp_control_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/**
 * Debugging level
 *
 * 1 thru 3 enable debug output for control channel
 * 4 thru 6 enable debug output for control and data channel
 */
int globus_i_ftp_control_debug_level = 0;

static
int
globus_l_ftp_control_activate(void)
{
    int                                rc;
    char *                              tmp_string;

    rc = globus_module_activate(GLOBUS_IO_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
        return rc;
    }
    
    tmp_string = globus_module_getenv("GLOBUS_FTP_CONTROL_DEBUG_LEVEL");
    if(tmp_string != GLOBUS_NULL)
    {
	globus_i_ftp_control_debug_level = atoi(tmp_string);

	if(globus_i_ftp_control_debug_level < 0)
	{
	    globus_i_ftp_control_debug_level = 0;
	}
    }
    
    globus_i_ftp_control_debug_printf(1,
        (stderr, "globus_l_ftp_control_activate() entering\n"));
        
    rc = globus_module_activate(GLOBUS_THREAD_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
        goto exit;
    }
    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
        goto exit;
    }
    rc = globus_module_activate(GLOBUS_GSI_GSSAPI_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
        goto exit;
    }
    rc = (int)globus_i_ftp_control_server_activate();
    if(rc != GLOBUS_SUCCESS)
    {
        goto exit;
    }
    rc = (int)globus_i_ftp_control_client_activate();
    if(rc != GLOBUS_SUCCESS)
    {
        goto exit;
    }
    rc = (int)globus_i_ftp_control_data_activate();

exit:
    globus_i_ftp_control_debug_printf(1,
        (stderr, "globus_l_ftp_control_activate() exiting\n"));
    return rc;
}

static
int
globus_l_ftp_control_deactivate(void)
{
    int                             rc;
    
    globus_i_ftp_control_debug_printf(1,
        (stderr, "globus_l_ftp_control_deactivate() entering\n"));
        
    rc = (int)globus_i_ftp_control_data_deactivate();
    if(rc != GLOBUS_SUCCESS)
    {
        goto exit;
    }
    rc = (int)globus_i_ftp_control_client_deactivate();
    if(rc != GLOBUS_SUCCESS)
    {
        goto exit;
    }
    rc = (int)globus_i_ftp_control_server_deactivate();
    if(rc != GLOBUS_SUCCESS)
    {
        goto exit;
    }
    rc = globus_module_deactivate(GLOBUS_IO_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
        goto exit;
    }
    rc = globus_module_deactivate(GLOBUS_GSI_GSSAPI_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
        goto exit;
    }
    rc = globus_module_deactivate(GLOBUS_THREAD_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
        goto exit;
    }
    rc = globus_module_deactivate(GLOBUS_COMMON_MODULE);

exit:    
    globus_i_ftp_control_debug_printf(1,
        (stderr, "globus_l_ftp_control_deactivate() exiting\n"));
    return rc;
}

/*
 *  access functions for globus_ftp_control_parallelism_t
 */
globus_result_t
globus_i_ftp_parallelism_copy(
    globus_ftp_control_parallelism_t *             dest_parallelism,
    globus_ftp_control_parallelism_t *             src_parallelism)
{
    /*
     *  for now there are no pointers in any of the sub classes of
     *  globus_i_ftp_parallelism_base_t so we can just do a mem
     *  copy.
     */

    memcpy(
        dest_parallelism, 
        src_parallelism, 
        sizeof(globus_ftp_control_parallelism_t));

    if(dest_parallelism->mode == GLOBUS_FTP_CONTROL_PARALLELISM_NONE)
    {
        dest_parallelism->base.size = 1;
    }

    /* TODO check src_parallelism for vaid members */
    return GLOBUS_SUCCESS;
}

globus_result_t
globus_ftp_control_set_netlogger(
    globus_ftp_control_handle_t *               handle,
    globus_netlogger_handle_t *                 nl_handle,
    globus_bool_t                               nl_ftp_control,
    globus_bool_t                               nl_globus_io)
{
    globus_result_t                             res;

    res = globus_i_ftp_control_client_set_netlogger(handle, nl_handle);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }
    res = globus_i_ftp_control_data_set_netlogger(
              handle, nl_handle, nl_ftp_control, nl_globus_io);

    return res;
}

int
globus_i_ftp_parallelism_get_size(
    globus_ftp_control_parallelism_t *             parallelism)
{
    return parallelism->base.size;
}

int
globus_i_ftp_parallelism_get_max_size(
    globus_ftp_control_parallelism_t *             parallelism)
{
    if(parallelism->mode == GLOBUS_FTP_CONTROL_PARALLELISM_NONE)
    {
        return 1;
    }
/*    else if(parallelism->mode == GLOBUS_FTP_CONTROL_PARALLELISM_FIXED)
    {
        return parallelism->fixed.size;
    }
    else if(parallelism->mode == GLOBUS_FTP_CONTROL_PARALLELISM_AUTOMATIC)
    {
        return parallelism->automatic.max_size;
    }
*/
    return -1;
}

int
globus_i_ftp_parallelism_get_min_size(
    globus_ftp_control_parallelism_t *             parallelism)
{
    if(parallelism->mode == GLOBUS_FTP_CONTROL_PARALLELISM_NONE)
    {
        return 1;
    }
/*    else if(parallelism->mode == GLOBUS_FTP_CONTROL_PARALLELISM_FIXED)
    {
        return parallelism->fixed.size;
    }
    else if(parallelism->mode == GLOBUS_FTP_CONTROL_PARALLELISM_AUTOMATIC)
    {
        return parallelism->automatic.min_size;
    }
*/
    return -1;
}

/*
 *  access functions for globus_ftp_host_port_t
 */
void 
globus_ftp_control_host_port_init(
    globus_ftp_control_host_port_t *              host_port,
    char *                                        host,
    unsigned short                                port)
{
    struct hostent                                hostent;
    globus_byte_t                                 bs_buf[8192];
    int                                           err_no;
    char                                          hostip[30];
    char                                          l_hostname[512];

    host_port->host[0] = 0;
    host_port->host[1] = 0;
    host_port->host[2] = 0;
    host_port->host[3] = 0;

    if(host != GLOBUS_NULL)
    {
	struct in_addr tmp_addr;

        globus_libc_gethostbyname_r(
            host,
            &hostent,
            bs_buf,
            8192,
            &err_no);

	memcpy(&tmp_addr, hostent.h_addr_list[0], sizeof(struct in_addr));
        strcpy(
            hostip, 
            inet_ntoa(tmp_addr));
        sscanf(
            hostip, 
            "%d.%d.%d.%d", 
            &host_port->host[0],
            &host_port->host[1],
            &host_port->host[2],
            &host_port->host[3]);
    }
    host_port->port = port;
}

void 
globus_ftp_control_host_port_destroy(
    globus_ftp_control_host_port_t *                   host_port)
{
}

void
globus_ftp_control_host_port_get_host(
    globus_ftp_control_host_port_t *                   host_port,
    char *                                             host)
{
    sprintf(host, "%d.%d.%d.%d",
            host_port->host[0],
            host_port->host[1],
            host_port->host[2],
            host_port->host[3]);
}

unsigned short
globus_ftp_control_host_port_get_port(
    globus_ftp_control_host_port_t *                   host_port)
{
    return host_port->port;
}

void
globus_ftp_control_host_port_copy(
    globus_ftp_control_host_port_t *                   dest,
    globus_ftp_control_host_port_t *                   src)
{
    dest->host[0] = src->host[0];
    dest->host[1] = src->host[1];
    dest->host[2] = src->host[2];
    dest->host[3] = src->host[3];

    dest->port = src->port;
}

globus_result_t
globus_ftp_control_layout_copy(
    globus_ftp_control_layout_t *                       dest,
    globus_ftp_control_layout_t *                       src)
{
    if(dest == GLOBUS_NULL)
    {
        return GLOBUS_FAILURE;
    }
    if(src == GLOBUS_NULL)
    {
        return GLOBUS_FAILURE;
    }

    memcpy(
        (void *)dest, 
        (void *)src, 
        sizeof(globus_ftp_control_layout_t)); 

    return GLOBUS_SUCCESS;
}

