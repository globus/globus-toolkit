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


#include "globus_xio_load.h"
#include "globus_i_xio_test_drivers.h"

GlobusDebugDefine(GLOBUS_XIO_TEST);

GlobusXIODeclareModule(bounce);
GlobusXIODeclareModule(debug);
GlobusXIODeclareModule(null);
GlobusXIODeclareModule(null_pass);
GlobusXIODeclareModule(op);
GlobusXIODeclareModule(smtp);
GlobusXIODeclareModule(stack);
GlobusXIODeclareModule(test);
GlobusXIODeclareModule(verify);

static
int
globus_l_test_drivers_activate(void)
{
    GlobusDebugInit(GLOBUS_XIO_TEST, TRACE INTERNAL_TRACE VERBOSE_INFO STATE);
    
    globus_extension_register_builtin(
        GlobusXIOExtensionName(bounce), GlobusXIOMyModule(bounce));
    globus_extension_register_builtin(
        GlobusXIOExtensionName(debug), GlobusXIOMyModule(debug));
    globus_extension_register_builtin(
        GlobusXIOExtensionName(null), GlobusXIOMyModule(null));
    globus_extension_register_builtin(
        GlobusXIOExtensionName(null_pass), GlobusXIOMyModule(null_pass));
    globus_extension_register_builtin(
        GlobusXIOExtensionName(op), GlobusXIOMyModule(op));
    globus_extension_register_builtin(
        GlobusXIOExtensionName(smtp), GlobusXIOMyModule(smtp));
    globus_extension_register_builtin(
        GlobusXIOExtensionName(stack), GlobusXIOMyModule(stack));
    globus_extension_register_builtin(
        GlobusXIOExtensionName(test), GlobusXIOMyModule(test));
    globus_extension_register_builtin(
        GlobusXIOExtensionName(verify), GlobusXIOMyModule(verify));
        
    return GLOBUS_SUCCESS;
}

static
int
globus_l_test_drivers_deactivate(void)
{
    globus_extension_unregister_builtin(GlobusXIOExtensionName(bounce));
    globus_extension_unregister_builtin(GlobusXIOExtensionName(debug));
    globus_extension_unregister_builtin(GlobusXIOExtensionName(null));
    globus_extension_unregister_builtin(GlobusXIOExtensionName(null_pass));
    globus_extension_unregister_builtin(GlobusXIOExtensionName(op));
    globus_extension_unregister_builtin(GlobusXIOExtensionName(smtp));
    globus_extension_unregister_builtin(GlobusXIOExtensionName(stack));
    globus_extension_unregister_builtin(GlobusXIOExtensionName(test));
    globus_extension_unregister_builtin(GlobusXIOExtensionName(verify));
    
    GlobusDebugDestroy(GLOBUS_XIO_TEST);
    return GLOBUS_SUCCESS;
}

/* dont need to use extension module macro since i will ONLY be a shared lib */
globus_module_descriptor_t globus_extension_module =
{
    "test_drivers",
    globus_l_test_drivers_activate,
    globus_l_test_drivers_deactivate,
    NULL,
    NULL,
    NULL
};
