/******************************************************************************
globus_gass_transfer.c
 
Description:
    This module implements the GASS transfer module descriptor
 
CVS Information:
 
    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/

#include "globus_i_gass_transfer.h"

globus_hashtable_t globus_i_gass_transfer_protocols;
globus_handle_table_t globus_i_gass_transfer_requests;
globus_handle_table_t globus_i_gass_transfer_listeners;
globus_mutex_t globus_i_gass_transfer_mutex;

static
int
globus_l_gass_transfer_activate(void);

static
int
globus_l_gass_transfer_deactivate(void);

globus_module_descriptor_t globus_i_gass_transfer_module =
{
    "globus_gass_transfer",
    globus_l_gass_transfer_activate,
    globus_l_gass_transfer_deactivate,
    GLOBUS_NULL
};


static int
globus_l_gass_transfer_activate(void)
{
    globus_module_activate(GLOBUS_COMMON_MODULE);
    globus_module_activate(GLOBUS_IO_MODULE);

    globus_hashtable_init(&globus_i_gass_transfer_protocols,
			  16,
			  globus_hashtable_string_hash,
			  globus_hashtable_string_keyeq);

    globus_handle_table_init(&globus_i_gass_transfer_requests);
    globus_handle_table_init(&globus_i_gass_transfer_listeners);

    globus_module_activate(GLOBUS_I_GASS_TRANSFER_HTTP_MODULE);

    globus_gass_transfer_proto_register_protocol(
	&globus_i_gass_transfer_http_descriptor);
    globus_gass_transfer_proto_register_protocol(
	&globus_i_gass_transfer_https_descriptor);

    globus_mutex_init(&globus_i_gass_transfer_mutex,
                      GLOBUS_NULL);
    return GLOBUS_SUCCESS;
}
/* globus_l_gass_transfer_activate() */

static int
globus_l_gass_transfer_deactivate(void)
{
    globus_hashtable_destroy(&globus_i_gass_transfer_protocols);
    globus_handle_table_destroy(&globus_i_gass_transfer_requests);
    globus_handle_table_destroy(&globus_i_gass_transfer_listeners);
    globus_mutex_destroy(&globus_i_gass_transfer_mutex);

    globus_module_deactivate(GLOBUS_I_GASS_TRANSFER_HTTP_MODULE);

    globus_module_deactivate(GLOBUS_IO_MODULE);
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
    return GLOBUS_SUCCESS;
}
/* globus_l_gass_transfer_deactivate() */
