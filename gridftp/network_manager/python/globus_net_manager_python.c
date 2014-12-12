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
#include "globus_error_string.h"
#include "globus_net_manager.h"
#include "globus_net_manager_python.h"
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
    globus_result_t                     result = GLOBUS_SUCCESS;
    ssize_t                             num_attrs = 0;
    PyObject                           *pylist = NULL;

    for (int i = 0; attr_array != NULL && attr_array[i].scope != NULL; i++)
    {
        num_attrs++;
    }
    pylist = PyList_New(num_attrs);
    if (!pylist)
    {
        result = GLOBUS_FAILURE;
        goto pylist_new_fail;
    }

    for (int i = 0; attr_array != NULL && attr_array[i].scope != NULL; i++)
    {
        PyObject                       *tuple, *pyscope, *pyname, *pyvalue;

        tuple = PyTuple_New(3);
        if (!tuple)
        {
            result = GLOBUS_FAILURE;
            goto pytuple_new_fail;
        }
        PyList_SetItem(pylist, i, tuple);

        pyscope = PyString_FromString(attr_array[i].scope);
        if (!pyscope)
        {
            result = GLOBUS_FAILURE;
            goto pyscope_new_fail;
        }
        PyTuple_SetItem(tuple, 0, pyscope);

        pyname = PyString_FromString(attr_array[i].name);
        if (!pyname)
        {
            result = GLOBUS_FAILURE;
            goto pyname_new_fail;
        }
        PyTuple_SetItem(tuple, 1, pyname);

        pyvalue = PyString_FromString(attr_array[i].value);
        if (!pyvalue)
        {
            result = GLOBUS_FAILURE;
            goto pyvalue_new_fail;
        }
        PyTuple_SetItem(tuple, 2, pyvalue);
    }
    if (result)
    {
pyvalue_new_fail:
pyname_new_fail:
pyscope_new_fail:
pytuple_new_fail:
        Py_DECREF(pylist);
        pylist = NULL;
    }
pylist_new_fail:
    *attr_list = pylist;
    return result;
}
/* globus_l_python_attr_array_to_pylist() */

static
globus_result_t
globus_l_python_pylist_to_attr_array(
    PyObject                           *pylist,
    globus_net_manager_attr_t          **attr_array_out)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    ssize_t                             list_size = 0, i = 0;
    globus_net_manager_attr_t          *attr_array = NULL;

    list_size = PyList_Size(pylist);
    attr_array = malloc((list_size+1) * sizeof(globus_net_manager_attr_t));
    if (!attr_array)
    {
        result = GLOBUS_FAILURE;
        goto attr_array_malloc_fail;
    }
    for (i = 0; i < list_size; i++)
    {
        PyObject                       *pyattr_tuple = NULL;
        PyObject                       *pyscope = NULL,
                                       *pyname = NULL,
                                       *pyvalue = NULL;

        pyattr_tuple = PyList_GetItem(pylist, i);
        if (pyattr_tuple == NULL || !PyTuple_Check(pyattr_tuple))
        {
            result = GLOBUS_FAILURE;
            goto bad_tuple_item;
        }
        if (PyTuple_Size(pyattr_tuple) != 3)
        {
            result = GLOBUS_FAILURE;
            goto bad_tuple_size;
        }
        pyscope = PyTuple_GetItem(pyattr_tuple, 0);
        if (pyscope == NULL || !PyString_Check(pyscope))
        {
            result = GLOBUS_FAILURE;
            goto bad_tuple_scope;
        }
        pyname = PyTuple_GetItem(pyattr_tuple, 1);
        if (pyname == NULL || !PyString_Check(pyname))
        {
            result = GLOBUS_FAILURE;
            goto bad_tuple_name;
        }
        pyvalue = PyTuple_GetItem(pyattr_tuple, 2);
        if (pyvalue == NULL || !PyString_Check(pyvalue))
        {
            result = GLOBUS_FAILURE;
            goto bad_tuple_value;
        }
        attr_array[i].scope = strdup(PyString_AsString(pyscope));
        if (attr_array[i].scope == NULL)
        {
            result = GLOBUS_FAILURE;
            goto strdup_scope_fail;
        }
        attr_array[i].name = strdup(PyString_AsString(pyname));
        if (attr_array[i].name == NULL)
        {
            result = GLOBUS_FAILURE;
            goto strdup_name_fail;
        }
        attr_array[i].value = strdup(PyString_AsString(pyvalue));
        if (attr_array[i].value == NULL)
        {
            result = GLOBUS_FAILURE;
            goto strdup_value_fail;
        }
    }
    attr_array[list_size] = globus_net_manager_null_attr;
    if (result != GLOBUS_SUCCESS)
    {
        for (; i >= 0 ; i--)
        {
            free(attr_array[i].value);
strdup_value_fail:
            free(attr_array[i].name);
strdup_name_fail:
            free(attr_array[i].scope);
strdup_scope_fail:
bad_tuple_value:
bad_tuple_name:
bad_tuple_scope:
bad_tuple_size:
bad_tuple_item:
            ;
        }
        free(attr_array);
        attr_array = NULL;
    }
attr_array_malloc_fail:
    *attr_array_out = attr_array;
    return GLOBUS_SUCCESS;
}
/* globus_l_python_pylist_to_attr_array() */

static
globus_result_t
globus_l_net_manager_python_handle_exception(
    const char                         *func_name)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    PyObject                           *exception = NULL,
                                       *exception_string = NULL;
    const char                         *exception_cstr = NULL;

    exception = PyErr_Occurred();
    if (exception != NULL)
    {
        result = GLOBUS_FAILURE;

        exception_string = PyObject_Str(exception);
        if (exception_string)
        {
            exception_cstr = PyString_AsString(exception_string);
            if (exception_cstr)
            {
                result = globus_error_put(
                        globus_error_construct_string(
                            &globus_net_manager_python_module,
                            NULL,
                            "Python Exception in %s: %s",
                            func_name,
                            exception_cstr));
            }
            Py_DECREF(exception_string);
        }
    }
    return result;
}
/* globus_l_net_manager_python_handle_exception() */

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
        PyObject                       *pyargs = NULL;
        PyObject                       *pytaskid, *pytransport, *pylist;
        PyObject                       *pyresult;

        pyargs = PyTuple_New(3);
        if (pyargs == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pyargs_new_fail;
        }
        pytaskid = PyString_FromString(task_id);
        if (pytaskid == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_taskid_fail;
        }
        PyTuple_SetItem(pyargs, 0, pytaskid);

        pytransport = PyString_FromString(transport);
        if (pytransport == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_transport_fail;
        }
        PyTuple_SetItem(pyargs, 1, pytransport);

        result = globus_l_python_attr_array_to_pylist(attr_array, &pylist);
        if (result)
        {
            goto attr_to_pylist_fail;
        }
        PyTuple_SetItem(pyargs, 2, pylist);

        PyErr_Clear();
        pyresult = PyObject_CallObject(pymod->pre_listen, pyargs);
        if (pyresult && pyresult != Py_None)
        {
            if (PyList_Check(pyresult))
            {
                result = globus_l_python_pylist_to_attr_array(
                    pyresult, attr_array_out);
            }
            else
            {
                result = GLOBUS_FAILURE;
            }
            Py_DECREF(pyresult);
        }
        if (result == GLOBUS_SUCCESS)
        {
            result = globus_l_net_manager_python_handle_exception("pre_listen");
        }
attr_to_pylist_fail:
pystring_transport_fail:
pystring_taskid_fail:
        Py_DECREF(pyargs);
        pyargs = NULL;
    }
pyargs_new_fail:
lookup_module_fail:
    return result;
}
/* globus_l_python_pre_listen() */

static
globus_result_t
globus_l_python_post_listen(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const char                         *local_contact,
    const globus_net_manager_attr_t    *attr_array,
    char                              **local_contact_out,
    globus_net_manager_attr_t         **attr_array_out)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_l_python_modref_t           *pymod = NULL;

    if (local_contact_out == NULL)
    {
        result = GLOBUS_FAILURE;
        goto local_contact_null;
    }
    *local_contact_out = NULL;

    if (attr_array_out == NULL)
    {
        result = GLOBUS_FAILURE;
        goto attr_array_out_null;
    }
    *attr_array_out = NULL;

    result = globus_l_python_module(attr_array, &pymod);
    if (result)
    {
        goto lookup_module_fail;
    }
    assert(pymod != NULL);

    if (pymod->post_listen)
    {
        PyObject                       *pyargs = NULL,
                                       *pytaskid = NULL,
                                       *pytransport = NULL,
                                       *pylocal_contact = NULL,
                                       *pylist = NULL,
                                       *pyresult = NULL;

        pyargs = PyTuple_New(4);
        if (pyargs == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pyargs_new_fail;
        }
        pytaskid = PyString_FromString(task_id);
        if (pytaskid == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_taskid_fail;
        }
        PyTuple_SetItem(pyargs, 0, pytaskid);

        pytransport = PyString_FromString(transport);
        if (pytransport == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_transport_fail;
        }
        PyTuple_SetItem(pyargs, 1, pytransport);

        pylocal_contact = PyString_FromString(local_contact);
        if (pylocal_contact == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_local_contact_fail;
        }
        PyTuple_SetItem(pyargs, 2, pylocal_contact);

        result = globus_l_python_attr_array_to_pylist(attr_array, &pylist);
        if (result)
        {
            goto attr_to_pylist_fail;
        }
        PyTuple_SetItem(pyargs, 3, pylist);

        PyErr_Clear();
        pyresult = PyObject_CallObject(pymod->post_listen, pyargs);
        if (pyresult && pyresult != Py_None)
        {
            if (PyTuple_Check(pyresult) && PyTuple_Size(pyresult) == 2)
            {
                PyObject                *py_localcontact_out = NULL,
                                        *py_attr_array_out = NULL;

                py_localcontact_out = PyTuple_GetItem(pyresult, 0);
                if (!py_localcontact_out)
                {
                    result = GLOBUS_FAILURE;
                    goto get_localcontactitem_fail;
                }
                if (PyString_Check(py_localcontact_out))
                {
                    const char * tmpstr = PyString_AsString(py_localcontact_out);
                    if (tmpstr)
                    {
                        *local_contact_out = strdup(tmpstr);

                        if (*local_contact_out == NULL)
                        {
                            goto strdup_local_contact_out_fail;
                        }
                    }
                }
                py_attr_array_out = PyTuple_GetItem(pyresult, 1);
                if (!py_attr_array_out)
                {
                    result = GLOBUS_FAILURE;
                    goto get_attr_array_out_fail;
                }
                if (py_attr_array_out == Py_None)
                {
                    *attr_array_out = NULL;
                }
                else if (PyList_Check(py_attr_array_out))
                {
                    result = globus_l_python_pylist_to_attr_array(
                        py_attr_array_out, attr_array_out);
                }
                else
                {
                    result = GLOBUS_FAILURE;
                    goto py_attr_array_not_list;
                }
            }
            else
            {
                result = GLOBUS_FAILURE;
                goto py_result_wrong_size;
            }
            if (result != GLOBUS_SUCCESS)
            {
py_result_wrong_size:
py_attr_array_not_list:
get_attr_array_out_fail:
                free(*local_contact_out);
                *local_contact_out = NULL;
            }
strdup_local_contact_out_fail:
get_localcontactitem_fail:
            Py_DECREF(pyresult);
        }
        if (result == GLOBUS_SUCCESS)
        {
            result = globus_l_net_manager_python_handle_exception(
                    "post_listen");
        }
attr_to_pylist_fail:
pystring_local_contact_fail:
pystring_transport_fail:
pystring_taskid_fail:
        Py_DECREF(pyargs);
        pyargs = NULL;
    }
pyargs_new_fail:
lookup_module_fail:
attr_array_out_null:
local_contact_null:
    return result;
}
/* globus_l_python_post_listen() */

static
globus_result_t
globus_l_python_pre_accept(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const char                         *local_contact,
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

    if (pymod->pre_accept)
    {
        PyObject                       *pyargs = NULL,
                                       *pytaskid = NULL,
                                       *pytransport = NULL,
                                       *pylocal_contact = NULL,
                                       *pylist = NULL,
                                       *pyresult = NULL;

        pyargs = PyTuple_New(4);
        if (pyargs == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pyargs_new_fail;
        }
        pytaskid = PyString_FromString(task_id);
        if (pytaskid == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_taskid_fail;
        }
        PyTuple_SetItem(pyargs, 0, pytaskid);

        pytransport = PyString_FromString(transport);
        if (pytransport == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_transport_fail;
        }
        PyTuple_SetItem(pyargs, 1, pytransport);

        pylocal_contact = PyString_FromString(local_contact);
        if (pylocal_contact == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_local_contact_fail;
        }
        PyTuple_SetItem(pyargs, 2, pylocal_contact);

        result = globus_l_python_attr_array_to_pylist(attr_array, &pylist);
        if (result)
        {
            goto attr_to_pylist_fail;
        }
        PyTuple_SetItem(pyargs, 3, pylist);

        PyErr_Clear();
        pyresult = PyObject_CallObject(pymod->pre_accept, pyargs);
        if (pyresult != NULL && pyresult != Py_None)
        {
            if (PyList_Check(pyresult))
            {
                result = globus_l_python_pylist_to_attr_array(
                    pyresult, attr_array_out);
            }
            else
            {
                result = GLOBUS_FAILURE;
            }
            Py_DECREF(pyresult);
        }
        if (result == GLOBUS_SUCCESS)
        {
            result = globus_l_net_manager_python_handle_exception(
                    "pre_accept");
        }
attr_to_pylist_fail:
pystring_local_contact_fail:
pystring_transport_fail:
pystring_taskid_fail:
        Py_DECREF(pyargs);
        pyargs = NULL;
    }
pyargs_new_fail:
lookup_module_fail:
    return result;
}
/* globus_l_python_pre_accept() */

static
globus_result_t
globus_l_python_post_accept(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const char                         *local_contact,
    const char                         *remote_contact,
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

    if (pymod->post_accept)
    {
        PyObject                       *pyargs = NULL,
                                       *pytaskid = NULL,
                                       *pytransport = NULL,
                                       *pylocal_contact = NULL,
                                       *pyremote_contact = NULL,
                                       *pylist = NULL,
                                       *pyresult = NULL;

        pyargs = PyTuple_New(5);
        if (pyargs == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pyargs_new_fail;
        }
        pytaskid = PyString_FromString(task_id);
        if (pytaskid == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_taskid_fail;
        }
        PyTuple_SetItem(pyargs, 0, pytaskid);

        pytransport = PyString_FromString(transport);
        if (pytransport == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_transport_fail;
        }
        PyTuple_SetItem(pyargs, 1, pytransport);

        pylocal_contact = PyString_FromString(local_contact);
        if (pylocal_contact == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_local_contact_fail;
        }
        PyTuple_SetItem(pyargs, 2, pylocal_contact);

        pyremote_contact = PyString_FromString(remote_contact);
        if (pyremote_contact == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_remote_contact_fail;
        }
        PyTuple_SetItem(pyargs, 3, pyremote_contact);

        result = globus_l_python_attr_array_to_pylist(attr_array, &pylist);
        if (result)
        {
            goto attr_to_pylist_fail;
        }
        PyTuple_SetItem(pyargs, 4, pylist);

        PyErr_Clear();
        pyresult = PyObject_CallObject(pymod->post_accept, pyargs);
        if (pyresult && pyresult != Py_None)
        {
            if (PyList_Check(pyresult))
            {
                result = globus_l_python_pylist_to_attr_array(
                    pyresult, attr_array_out);
            }
            else
            {
                result = GLOBUS_FAILURE;
            }
            Py_DECREF(pyresult);
        }
        if (result == GLOBUS_SUCCESS)
        {
            result = globus_l_net_manager_python_handle_exception(
                    "post_accept");
        }
attr_to_pylist_fail:
pystring_remote_contact_fail:
pystring_local_contact_fail:
pystring_transport_fail:
pystring_taskid_fail:
        Py_DECREF(pyargs);
        pyargs = NULL;
    }
pyargs_new_fail:
lookup_module_fail:
    return result;
}
/* globus_l_python_post_accept() */

static
globus_result_t
globus_l_python_pre_connect(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const char                         *remote_contact,
    const globus_net_manager_attr_t    *attr_array,
    char                              **remote_contact_out,
    globus_net_manager_attr_t         **attr_array_out)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_l_python_modref_t           *pymod = NULL;

    if (remote_contact_out == NULL)
    {
        result = GLOBUS_FAILURE;
        goto remote_contact_null;
    }
    *remote_contact_out = NULL;

    if (attr_array_out == NULL)
    {
        result = GLOBUS_FAILURE;
        goto attr_array_out_null;
    }
    *attr_array_out = NULL;

    result = globus_l_python_module(attr_array, &pymod);
    if (result)
    {
        goto lookup_module_fail;
    }
    assert(pymod != NULL);

    if (pymod->pre_connect)
    {
        PyObject                       *pyargs = NULL,
                                       *pytaskid = NULL,
                                       *pytransport = NULL,
                                       *pyremote_contact = NULL,
                                       *pylist = NULL,
                                       *pyresult = NULL;

        pyargs = PyTuple_New(4);
        if (pyargs == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pyargs_new_fail;
        }
        pytaskid = PyString_FromString(task_id);
        if (pytaskid == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_taskid_fail;
        }
        PyTuple_SetItem(pyargs, 0, pytaskid);

        pytransport = PyString_FromString(transport);
        if (pytransport == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_transport_fail;
        }
        PyTuple_SetItem(pyargs, 1, pytransport);

        pyremote_contact = PyString_FromString(remote_contact);
        if (pyremote_contact == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_remote_contact_fail;
        }
        PyTuple_SetItem(pyargs, 2, pyremote_contact);

        result = globus_l_python_attr_array_to_pylist(attr_array, &pylist);
        if (result)
        {
            goto attr_to_pylist_fail;
        }
        PyTuple_SetItem(pyargs, 3, pylist);

        PyErr_Clear();
        pyresult = PyObject_CallObject(pymod->pre_connect, pyargs);
        if (pyresult && pyresult != Py_None)
        {
            if (PyTuple_Check(pyresult) && PyTuple_Size(pyresult) == 2)
            {
                PyObject                *py_localcontact_out = NULL,
                                        *py_attr_array_out = NULL;

                py_localcontact_out = PyTuple_GetItem(pyresult, 0);
                if (!py_localcontact_out)
                {
                    result = GLOBUS_FAILURE;
                    goto get_localcontactitem_fail;
                }
                if (PyString_Check(py_localcontact_out))
                {
                    const char * tmpstr = PyString_AsString(py_localcontact_out);
                    if (tmpstr)
                    {
                        *remote_contact_out = strdup(tmpstr);

                        if (*remote_contact_out == NULL)
                        {
                            goto strdup_remote_contact_out_fail;
                        }
                    }
                }
                py_attr_array_out = PyTuple_GetItem(pyresult, 1);
                if (!py_attr_array_out)
                {
                    result = GLOBUS_FAILURE;
                    goto get_attr_array_out_fail;
                }
                if (py_attr_array_out == Py_None)
                {
                    *attr_array_out = NULL;
                }
                else if (PyList_Check(py_attr_array_out))
                {
                    result = globus_l_python_pylist_to_attr_array(
                        py_attr_array_out, attr_array_out);
                }
                else
                {
                    result = GLOBUS_FAILURE;
                    goto py_attr_array_not_list;
                }
            }
            else
            {
                result = GLOBUS_FAILURE;
            }
py_attr_array_not_list:
get_attr_array_out_fail:
            if (result)
            {
                free(*remote_contact_out);
                *remote_contact_out = NULL;
            }
strdup_remote_contact_out_fail:
get_localcontactitem_fail:
            Py_DECREF(pyresult);
        }
        if (result == GLOBUS_SUCCESS)
        {
            result = globus_l_net_manager_python_handle_exception(
                    "pre_connect");
        }
attr_to_pylist_fail:
pystring_remote_contact_fail:
pystring_transport_fail:
pystring_taskid_fail:
        Py_DECREF(pyargs);
        pyargs = NULL;
    }
pyargs_new_fail:
lookup_module_fail:
attr_array_out_null:
remote_contact_null:
    return result;
}
/* globus_l_python_pre_connect() */

static
globus_result_t
globus_l_python_post_connect(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const char                         *local_contact,
    const char                         *remote_contact,
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

    if (pymod->post_connect)
    {
        PyObject                       *pyargs = NULL,
                                       *pytaskid = NULL,
                                       *pytransport = NULL,
                                       *pylocal_contact = NULL,
                                       *pyremote_contact = NULL,
                                       *pylist = NULL,
                                       *pyresult = NULL;

        pyargs = PyTuple_New(5);
        if (pyargs == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pyargs_new_fail;
        }
        pytaskid = PyString_FromString(task_id);
        if (pytaskid == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_taskid_fail;
        }
        PyTuple_SetItem(pyargs, 0, pytaskid);

        pytransport = PyString_FromString(transport);
        if (pytransport == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_transport_fail;
        }
        PyTuple_SetItem(pyargs, 1, pytransport);

        pylocal_contact = PyString_FromString(local_contact);
        if (pylocal_contact == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_local_contact_fail;
        }
        PyTuple_SetItem(pyargs, 2, pylocal_contact);

        pyremote_contact = PyString_FromString(remote_contact);
        if (pyremote_contact == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_remote_contact_fail;
        }
        PyTuple_SetItem(pyargs, 3, pyremote_contact);

        result = globus_l_python_attr_array_to_pylist(attr_array, &pylist);
        if (result)
        {
            goto attr_to_pylist_fail;
        }
        PyTuple_SetItem(pyargs, 4, pylist);

        PyErr_Clear();
        pyresult = PyObject_CallObject(pymod->post_connect, pyargs);
        if (pyresult && pyresult != Py_None)
        {
            if (PyList_Check(pyresult))
            {
                result = globus_l_python_pylist_to_attr_array(
                    pyresult, attr_array_out);
            }
            else
            {
                result = GLOBUS_FAILURE;
            }
            Py_DECREF(pyresult);
        }
        if (result == GLOBUS_SUCCESS)
        {
            result = globus_l_net_manager_python_handle_exception(
                    "post_connect");
        }
attr_to_pylist_fail:
pystring_remote_contact_fail:
pystring_local_contact_fail:
pystring_transport_fail:
pystring_taskid_fail:
        Py_DECREF(pyargs);
        pyargs = NULL;
    }
pyargs_new_fail:
lookup_module_fail:
    return result;
}
/* globus_l_python_post_connect() */

static
globus_result_t
globus_l_python_pre_close(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const char                         *local_contact,
    const char                         *remote_contact,
    const globus_net_manager_attr_t    *attr_array)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_l_python_modref_t           *pymod = NULL;

    result = globus_l_python_module(attr_array, &pymod);

    if (result)
    {
        goto lookup_module_fail;
    }
    assert(pymod != NULL);

    if (pymod->pre_close)
    {
        PyObject                       *pyargs = NULL,
                                       *pytaskid = NULL,
                                       *pytransport = NULL,
                                       *pylocal_contact = NULL,
                                       *pyremote_contact = NULL,
                                       *pylist = NULL,
                                       *pyresult = NULL;

        pyargs = PyTuple_New(5);
        if (pyargs == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pyargs_new_fail;
        }
        pytaskid = PyString_FromString(task_id);
        if (pytaskid == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_taskid_fail;
        }
        PyTuple_SetItem(pyargs, 0, pytaskid);

        pytransport = PyString_FromString(transport);
        if (pytransport == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_transport_fail;
        }
        PyTuple_SetItem(pyargs, 1, pytransport);

        pylocal_contact = PyString_FromString(local_contact);
        if (pylocal_contact == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_local_contact_fail;
        }
        PyTuple_SetItem(pyargs, 2, pylocal_contact);

        pyremote_contact = PyString_FromString(remote_contact);
        if (pyremote_contact == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_remote_contact_fail;
        }
        PyTuple_SetItem(pyargs, 3, pyremote_contact);

        result = globus_l_python_attr_array_to_pylist(attr_array, &pylist);
        if (result)
        {
            goto attr_to_pylist_fail;
        }
        PyTuple_SetItem(pyargs, 4, pylist);

        PyErr_Clear();
        pyresult = PyObject_CallObject(pymod->pre_close, pyargs);
        if (pyresult && pyresult != Py_None)
        {
            result = GLOBUS_FAILURE;
            Py_DECREF(pyresult);
        }
        if (result == GLOBUS_SUCCESS)
        {
            result = globus_l_net_manager_python_handle_exception(
                    "pre_close");
        }
attr_to_pylist_fail:
pystring_remote_contact_fail:
pystring_local_contact_fail:
pystring_transport_fail:
pystring_taskid_fail:
        Py_DECREF(pyargs);
        pyargs = NULL;
    }
pyargs_new_fail:
lookup_module_fail:
    return result;
}
/* globus_l_python_pre_close() */

static
globus_result_t
globus_l_python_post_close(
    struct globus_net_manager_s        *manager,
    const char                         *task_id,
    const char                         *transport,
    const char                         *local_contact,
    const char                         *remote_contact,
    const globus_net_manager_attr_t    *attr_array)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_l_python_modref_t           *pymod = NULL;

    result = globus_l_python_module(attr_array, &pymod);

    if (result)
    {
        goto lookup_module_fail;
    }
    assert(pymod != NULL);

    if (pymod->post_close)
    {
        PyObject                       *pyargs = NULL,
                                       *pytaskid = NULL,
                                       *pytransport = NULL,
                                       *pylocal_contact = NULL,
                                       *pyremote_contact = NULL,
                                       *pylist = NULL,
                                       *pyresult = NULL;

        pyargs = PyTuple_New(5);
        if (pyargs == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pyargs_new_fail;
        }
        pytaskid = PyString_FromString(task_id);
        if (pytaskid == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_taskid_fail;
        }
        PyTuple_SetItem(pyargs, 0, pytaskid);

        pytransport = PyString_FromString(transport);
        if (pytransport == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_transport_fail;
        }
        PyTuple_SetItem(pyargs, 1, pytransport);

        pylocal_contact = PyString_FromString(local_contact);
        if (pylocal_contact == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_local_contact_fail;
        }
        PyTuple_SetItem(pyargs, 2, pylocal_contact);

        pyremote_contact = PyString_FromString(local_contact);
        if (pyremote_contact == NULL)
        {
            result = GLOBUS_FAILURE;
            goto pystring_remote_contact_fail;
        }
        PyTuple_SetItem(pyargs, 3, pyremote_contact);

        result = globus_l_python_attr_array_to_pylist(attr_array, &pylist);
        if (result)
        {
            goto attr_to_pylist_fail;
        }
        PyTuple_SetItem(pyargs, 4, pylist);

        PyErr_Clear();
        pyresult = PyObject_CallObject(pymod->post_close, pyargs);
        if (pyresult && pyresult != Py_None)
        {
            result = GLOBUS_FAILURE;
            Py_DECREF(pyresult);
        }
        if (result == GLOBUS_SUCCESS)
        {
            result = globus_l_net_manager_python_handle_exception(
                    "post_close");
        }
attr_to_pylist_fail:
pystring_remote_contact_fail:
pystring_local_contact_fail:
pystring_transport_fail:
pystring_taskid_fail:
        Py_DECREF(pyargs);
        pyargs = NULL;
    }
pyargs_new_fail:
lookup_module_fail:
    return result;
}
/* globus_l_python_post_close() */

static int globus_l_net_manager_python_activate(void);
static int globus_l_net_manager_python_deactivate(void);

static globus_net_manager_t globus_l_net_manager_python = {
    "python",
    globus_l_python_pre_listen,
    globus_l_python_post_listen,
    globus_l_python_pre_accept,
    globus_l_python_post_accept,
    globus_l_python_pre_connect,
    globus_l_python_post_connect,
    globus_l_python_pre_close,
    globus_l_python_post_close
};

static
void *
globus_l_net_manager_python_get_pointer(void)
{
    return &globus_l_net_manager_python;
}

GlobusExtensionDefineModule(globus_net_manager_python) =
{
    "globus_net_manager_python",
    globus_l_net_manager_python_activate,
    globus_l_net_manager_python_deactivate,
    NULL,
    globus_l_net_manager_python_get_pointer,
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
