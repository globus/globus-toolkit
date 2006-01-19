/*
 * Copyright 1999-2006 University of Chicago
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

#include "globus_i_xio_udt.h"
#include "version.h"

GlobusDebugDefine(GLOBUS_XIO_UDT);

globus_xio_stack_t globus_l_xio_udt_server_stack;
globus_xio_driver_t globus_l_xio_udt_udp_driver;
globus_xio_driver_t globus_l_xio_udt_server_udp_driver;

static
int
globus_l_xio_udt_activate(void);

static
int
globus_l_xio_udt_deactivate(void);


GlobusXIODefineModule(udt) =
{
    "globus_xio_udt",
    globus_l_xio_udt_activate,
    globus_l_xio_udt_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

static
globus_result_t
globus_l_xio_udt_push_driver(
    globus_xio_driver_t                 driver,
    globus_xio_stack_t                  stack)
{
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_udt_push_driver);

    GlobusXIOUdtDebugEnter();

    result = globus_xio_stack_push_driver(stack, globus_l_xio_udt_udp_driver);
    if (result == GLOBUS_SUCCESS)
    {
        result = globus_xio_stack_push_driver(stack, driver);
    }

    GlobusXIOUdtDebugExit();
    return result;
}

static  
globus_result_t
globus_l_xio_udt_init(
    globus_xio_driver_t *               out_driver)
{       
    globus_xio_driver_t                 driver;
    globus_result_t                     result;
    GlobusXIOName(globus_l_xio_udt_init);
            
    GlobusXIOUdtDebugEnter();
            
    /* I dont support any driver options, so I'll ignore the ap */
        
    result = globus_xio_driver_init(&driver, "udt", GLOBUS_NULL);
    if(result != GLOBUS_SUCCESS)
    {   
        result = GlobusXIOErrorWrapFailed(
            "globus_l_xio_driver_init", result);
        goto error_init;
    } 
        
    globus_xio_driver_set_transform(
        driver,
        globus_l_xio_udt_open,
        globus_l_xio_udt_close,
        globus_l_xio_udt_read,
        globus_l_xio_udt_write,
        globus_l_xio_udt_cntl,
        globus_l_xio_udt_push_driver);
    
    globus_xio_driver_set_server(
        driver,
        globus_l_xio_udt_server_init,
        globus_l_xio_udt_server_accept,
        globus_l_xio_udt_server_destroy,
        globus_l_xio_udt_server_cntl,
        globus_l_xio_udt_link_cntl,
        globus_l_xio_udt_link_destroy);

    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_udt_attr_init,
        globus_l_xio_udt_attr_copy,
        globus_l_xio_udt_attr_cntl,
        globus_l_xio_udt_attr_destroy);
    
    *out_driver = driver;
    
    GlobusXIOUdtDebugExit();
    return GLOBUS_SUCCESS;
    
error_init:
    GlobusXIOUdtDebugExitWithError();
    return result;
}    

static
void
globus_l_xio_udt_destroy(
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_destroy(driver);
}

GlobusXIODefineDriver(
    udt,
    globus_l_xio_udt_init,
    globus_l_xio_udt_destroy);

static
int                                     
globus_l_xio_udt_activate(void)                 
{                                       
    globus_result_t result;                     
    GlobusXIOName(globus_l_xio_udt_activate);
    
    GlobusDebugInit(GLOBUS_XIO_UDT, TRACE);
    
    GlobusXIOUdtDebugEnter();           
    
    result = globus_module_activate(GLOBUS_XIO_SYSTEM_MODULE);
    if (result != GLOBUS_SUCCESS)               
    {
        goto error_activate;                    
    }
    result = globus_xio_driver_load("udp", &globus_l_xio_udt_udp_driver); 
    if (result != GLOBUS_SUCCESS)               
    {
        goto error_load_udp_driver;
    }
    result = globus_xio_driver_load("udp",      
        &globus_l_xio_udt_server_udp_driver);   
    if (result != GLOBUS_SUCCESS)
    {
        goto error_load_server_udp_driver;
    }
    result = globus_xio_stack_init(&globus_l_xio_udt_server_stack, NULL);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_stack_init;
    }
    result = globus_xio_stack_push_driver(globus_l_xio_udt_server_stack,                globus_l_xio_udt_server_udp_driver);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_push_driver;
    }
    
    GlobusXIORegisterDriver(udt);
    GlobusXIOUdtDebugExit();
    return result;

error_push_driver:
   globus_xio_stack_destroy(globus_l_xio_udt_server_stack);

error_stack_init:
    globus_xio_driver_unload(globus_l_xio_udt_server_udp_driver);

error_load_server_udp_driver:
    globus_xio_driver_unload(globus_l_xio_udt_udp_driver);

error_load_udp_driver:
    globus_module_deactivate(GLOBUS_XIO_SYSTEM_MODULE);

error_activate:
    GlobusXIOUdtDebugExitWithError();
    GlobusDebugDestroy(GLOBUS_XIO_UDT);
    return result;
}

static
int
globus_l_xio_udt_deactivate(void)
{
    globus_result_t result;
    GlobusXIOName(globus_l_xio_udt_deactivate);

    GlobusXIOUdtDebugEnter();
    
    GlobusXIOUnRegisterDriver(udt);
    
/*    result = globus_xio_stack_destroy(globus_l_xio_udt_server_stack);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_deactivate;
    }
    result = globus_xio_driver_unload(globus_l_xio_udt_server_udp_driver);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_deactivate;
    }
*/
    result = globus_xio_driver_unload(globus_l_xio_udt_udp_driver);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_deactivate;
    }
    result = globus_module_deactivate(GLOBUS_XIO_SYSTEM_MODULE);
    if (result != GLOBUS_SUCCESS)
    {
        goto error_deactivate;
    }

    GlobusXIOUdtDebugExit();
    GlobusDebugDestroy(GLOBUS_XIO_UDT);
    return result;

error_deactivate:
    GlobusXIOUdtDebugExitWithError();
    GlobusDebugDestroy(GLOBUS_XIO_UDT);
    return result;
}
