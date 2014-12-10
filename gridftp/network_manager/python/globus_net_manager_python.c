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

#include "globus_common.h"
#include "globus_net_manager.h"
#include "version.h"

#include <Python.h>


typedef struct
{
    char                               *key;
    PyObject                           *module;
    PyObject                           *pre_listen;
    PyObject                           *post_listen;
    PyObject                           *pre_accept;
    PyObject                           *post_accept;
    PyObject                           *pre_connect;
    PyObject                           *post_connect;
    PyObject                           *pre_close;
    PyObject                           *post_close;
}
globus_l_python_modref_t;

static globus_hashtable_t               globus_l_python_modules;
static globus_mutex_t                   globus_l_python_modules_lock;

/**
 * @brief Resolve a python function name
 * @details
 * Check for a symbol named by funcname in the given module. If it is
 * a callable object, return it. Otherwise return NULL.
 *
 * @param module
 * @param funcname
 */
static
PyObject *
globus_l_python_resolve_func(
    PyObject                           *module,
    const char                         *funcname)
{
    PyObject                           *pyfunc = NULL;
    pyfunc = PyObject_GetAttrString(module, funcname);
    if (pyfunc && !PyCallable_Check(pyfunc))
    {
        Py_DECREF(pyfunc);
        pyfunc = NULL;
    }
    return pyfunc;
}

static
globus_result_t
globus_l_python_module(
    const globus_net_manager_attr_t    *attrs,
    globus_l_python_modref_t          **pymod)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    int                                 rc = 0;
    globus_l_python_modref_t           *modref = NULL;
    PyObject                           *pymodname = NULL;

    for (int i = 0; attrs != NULL && attrs[i].scope != NULL; i++)
    {
        if (strcmp(attrs[i].scope, "python") == 0)
        {
            if (strcmp(attrs[i].name, "pymod") == 0)
            {
                modref = globus_hashtable_lookup(
                    &globus_l_python_modules, attrs[i].value);
                if (!modref)
                {
                    modref = malloc(sizeof(globus_l_python_modref_t));
                    if (!modref)
                    {
                        result = GLOBUS_FAILURE;
                        goto modref_malloc_fail;
                    }
                    modref->key = strdup(attrs[i].value);
                    if (!modref->key)
                    {
                        result = GLOBUS_FAILURE;
                        goto strdup_modref_key_fail;
                    }
                    pymodname = PyString_FromString(modref->key);
                    if (!pymodname)
                    {
                        result = GLOBUS_FAILURE;
                        goto modref_key_to_pystring_fail;
                    }
                    modref->module = PyImport_Import(pymodname);
                    if (!modref->module)
                    {
                        result = GLOBUS_FAILURE;
                        goto module_import_fail;
                    }
                    modref->pre_listen = globus_l_python_resolve_func(
                            modref->module, "pre_listen");
                    modref->post_listen = globus_l_python_resolve_func(
                            modref->module, "post_listen"); 
                    modref->pre_accept = globus_l_python_resolve_func(
                            modref->module, "pre_accept"); 
                    modref->post_accept = globus_l_python_resolve_func(
                            modref->module, "post_accept"); 
                    modref->pre_connect = globus_l_python_resolve_func(
                            modref->module, "pre_connect"); 
                    modref->post_connect = globus_l_python_resolve_func(
                            modref->module, "post_connect"); 
                    modref->pre_close = globus_l_python_resolve_func(
                            modref->module, "pre_close"); 
                    modref->post_close = globus_l_python_resolve_func(
                            modref->module, "post_close"); 

                    rc = globus_hashtable_insert(
                            &globus_l_python_modules,
                            modref->key,
                            modref);
                    if (rc != GLOBUS_SUCCESS)
                    {
                        result = GLOBUS_FAILURE;
                        goto hashtable_insert_fail;
                    }
                }
                Py_XDECREF(pymodname);
                break;
            }
        }
    }
hashtable_insert_fail:
    if (result != GLOBUS_SUCCESS)
    {
        Py_XDECREF(modref->pre_listen);
        Py_XDECREF(modref->post_listen);
        Py_XDECREF(modref->pre_accept);
        Py_XDECREF(modref->post_accept);
        Py_XDECREF(modref->pre_connect);
        Py_XDECREF(modref->post_connect);
        Py_XDECREF(modref->pre_close);
        Py_XDECREF(modref->post_close);
        Py_XDECREF(modref->module);
    }
module_import_fail:
modref_key_to_pystring_fail:
    if (result != GLOBUS_SUCCESS)
    {
        free(modref->key);
strdup_modref_key_fail:
        free(modref);
        modref = NULL;
    }
modref_malloc_fail:
    *pymod = modref;
    return result;
}
/* globus_l_python_module() */

static
globus_result_t
globus_l_python_attr_array_to_pylist(
    const globus_net_manager_attr_t    *attr_array,
    PyObject                          **attr_list)
{
    ssize_t                             num_attrs = 0;
    PyObject                           *pylist = NULL;

    for (int i = 0; attr_array != NULL && attr_array[i].scope != NULL; i++)
    {
        num_attrs++;
    }
    pylist = PyList_New(num_attrs);

    for (int i = 0; attr_array != NULL && attr_array[i].scope != NULL; i++)
    {
        PyObject                       *tuple, *pyscope, *pyname, *pyvalue;

        tuple = PyTuple_New(3);
        pyscope = PyString_FromString(attr_array[i].scope);
        pyname = PyString_FromString(attr_array[i].name);
        pyvalue = PyString_FromString(attr_array[i].value);

        PyTuple_SetItem(tuple, 0, pyscope);
        PyTuple_SetItem(tuple, 1, pyname);
        PyTuple_SetItem(tuple, 2, pyvalue);

        PyList_SetItem(pylist, i, tuple);
    }
    *attr_list = pylist;
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_python_pylist_to_attr_array(
    PyObject                           *pylist,
    globus_net_manager_attr_t          **attr_array_out)
{
    ssize_t                             list_size;

    list_size = PyList_Size(pylist);
    *attr_array_out = malloc((list_size+1) * sizeof(globus_net_manager_attr_t));
    for (ssize_t i = 0; i < list_size; i++)
    {
        PyObject                       *pyattr_tuple;
        PyObject                       *pyscope, *pyname, *pyvalue;

        pyattr_tuple = PyList_GetItem(pylist, i);
        if (!PyTuple_Check(pyattr_tuple))
        {
            return GLOBUS_FAILURE;
        }
        if (PyTuple_Size(pyattr_tuple) != 3)
        {
            return GLOBUS_FAILURE;
        }
        pyscope = PyTuple_GetItem(pyattr_tuple, 0);
        pyname = PyTuple_GetItem(pyattr_tuple, 1);
        pyvalue = PyTuple_GetItem(pyattr_tuple, 2);
        if (!
                (PyString_Check(pyscope) &&
                 PyString_Check(pyname) &&
                 PyString_Check(pyvalue)))
        {
            return GLOBUS_FAILURE;
        }
        (*attr_array_out)[i].scope = strdup(PyString_AsString(pyscope));
        (*attr_array_out)[i].name = strdup(PyString_AsString(pyname));
        (*attr_array_out)[i].value = strdup(PyString_AsString(pyvalue));
    }
    (*attr_array_out)[list_size] = globus_net_manager_null_attr;
    return GLOBUS_SUCCESS;
}
/* globus_l_python_pylist_to_attr_array() */

static
globus_result_t
globus_l_python_pre_listen(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const globus_net_manager_attr_t    *attr_array,
    globus_net_manager_attr_t         **attr_array_out)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_l_python_modref_t           *pymod = NULL;

    result = globus_l_python_module(attr_array, &pymod);

    if (result)
    {
        goto lookup_module_fail;
    }
    assert(pymod != NULL);

    if (pymod->pre_listen)
    {
        PyObject                       *pyargs = PyTuple_New(3);
        PyObject                       *pytaskid, *pytransport, *pylist;
        PyObject                       *pyresult;

        pytaskid = PyString_FromString(task_id);
        pytransport = PyString_FromString(transport);
        globus_l_python_attr_array_to_pylist(attr_array, &pylist);
        PyTuple_SetItem(pyargs, 0, pytaskid);
        PyTuple_SetItem(pyargs, 1, pytransport);
        PyTuple_SetItem(pyargs, 2, pylist);

        pyresult = PyObject_CallObject(pymod->pre_listen, pyargs);
        Py_DECREF(pyargs);
        if (pyresult != Py_None && PyList_Check(pyresult))
        {
            globus_l_python_pylist_to_attr_array(pyresult, attr_array_out);
        }
        Py_DECREF(pyresult);
    }
lookup_module_fail:
    return result;
}

static int globus_l_net_manager_python_activate(void);
static int globus_l_net_manager_python_deactivate(void);

static globus_net_manager_t globus_l_net_manager_python = {
    "python",
    globus_l_python_pre_listen,
    NULL/*globus_l_python_post_listen*/,
    NULL/*globus_l_python_pre_accept*/,
    NULL/*globus_l_python_post_accept*/,
    NULL/*globus_l_python_pre_connect*/,
    NULL/*globus_l_python_post_connect*/,
    NULL/*globus_l_python_pre_close*/,
    NULL/*globus_l_python_post_close*/
};

GlobusExtensionDefineModule(globus_net_manager_python) =
{
    "globus_net_manager_python",
    globus_l_net_manager_python_activate,
    globus_l_net_manager_python_deactivate,
    NULL,
    NULL,
    &local_version
};
static
int
globus_l_net_manager_python_activate(void)
{
    Py_Initialize();
    globus_mutex_init(&globus_l_python_modules_lock, NULL);
    globus_hashtable_init(
            &globus_l_python_modules,
            7,
            globus_hashtable_string_hash, 
            globus_hashtable_string_keyeq); 
    globus_module_activate(GLOBUS_NET_MANAGER_MODULE);
    return globus_net_manager_register(&globus_l_net_manager_python);
}

static
int
globus_l_net_manager_python_deactivate(void)
{
    globus_net_manager_unregister(&globus_l_net_manager_python);
    Py_Finalize();
    return globus_module_deactivate(GLOBUS_NET_MANAGER_MODULE);
}
