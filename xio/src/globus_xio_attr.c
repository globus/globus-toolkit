#include "globus_common.h"
#include "globus_i_xio.h"

/*******************************************************************
 *                     internal functions
 ******************************************************************/

#define GlobusIXIOAttrGetDS(ds, attr, driver)                               \
do                                                                          \
{                                                                           \
    int                                         _ctr;                       \
    globus_i_xio_attr_t *                       _attr;                      \
    globus_xio_driver_t                         _driver;                    \
    globus_i_xio_attr_ent_t *                   _entry;                     \
    void *                                      _ds = NULL;                 \
                                                                            \
    _attr = (attr);                                                         \
    _driver = (driver);                                                     \
                                                                            \
    _entry = _attr->entry;                                                  \
    for(_ctr = 0; _ctr < _attr->ndx && _ds == NULL; _ctr++)                 \
    {                                                                       \
        if(_entry[_ctr].driver == driver)                                   \
        {                                                                   \
            _ds = entry[ctr].driver_data;                                   \
        }                                                                   \
    }                                                                       \
    ds = _ds;                                                               \
} while(0)

#define GlobusIXIODDGetDS(ds, dd, driver)                                   \
do                                                                          \
{                                                                           \
    int                                         _ctr;                       \
    globus_i_xio_dd_t *                         _dd;                        \
    globus_xio_driver_t                         _driver;                    \
    globus_i_xio_attr_ent_t *                   _entry;                     \
    void *                                      _ds = NULL;                 \
                                                                            \
    _dd = (dd);                                                             \
    _driver = (driver);                                                     \
                                                                            \
    _entry = _dd->entry;                                                    \
    for(_ctr = 0; _ctr < _dd->stack_size && _ds == NULL; _ctr++)            \
    {                                                                       \
        if(_entry[_ctr].driver == driver)                                   \
        {                                                                   \
            _ds = entry[ctr].driver_data;                                   \
        }                                                                   \
    }                                                                       \
    ds = _ds;                                                               \
} while(0)


/*******************************************************************
 *                         api functions
 *                         -------------
 *
 *  In these we just check parameters, allocate memory and call the
 *  internal functions.
 ******************************************************************/
/*
 *
 */
globus_result_t
globus_xio_attr_init(
    globus_xio_attr_t *                         attr)
{
    globus_i_xio_attr_t *                       xio_attr;

    if(attr == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_attr_init");
    }
   
    /* allocate the attr */ 
    xio_attr = (globus_i_xio_attr_t *)
                globus_malloc(sizeof(globus_i_xio_attr_t));
    if(xio_attr == NULL)
    {
        return GlobusXIOErrorMemoryAlloc("globus_xio_attr_init");
    }
    xio_attr->entry = (globus_i_xio_attr_ent_t *)
        globus_malloc(sizeof(globus_i_xio_attr_ent_t) *
            GLOBUS_XIO_ATTR_ARRAY_BASE_SIZE);

    if(xio_attr->entry == NULL)
    {
        globus_free(xio_attr);
        return GlobusXIOErrorMemoryAlloc("globus_xio_attr_init");
    }

    /* zero it out */
    memset(xio_attr, 0, sizeof(globus_i_xio_attr_t));
    memset(xio_attr->entry, 0, sizeof(globus_i_xio_attr_ent_t) *
        GLOBUS_XIO_ATTR_ARRAY_BASE_SIZE);
    xio_attr->max = GLOBUS_XIO_ATTR_ARRAY_BASE_SIZE;
    
    *attr = xio_attr;

    return GLOBUS_SUCCESS;
}

/*
 *
 */
globus_result_t
globus_xio_attr_cntl(
    globus_xio_attr_t                           attr,
    globus_xio_driver_t                         driver,
    int                                         cmd,
    ...)
{
    va_list                                     ap;
    globus_result_t                             res;
    void *                                      ds;

    if(attr == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_attr_cntl");
    }


    if(driver != NULL)
    {
        GlobusIXIOAttrGetDS(ds, attr, driver);
        if(ds == NULL)
        {
            res = driver->attr_init_func(&ds);
            if(res != GLOBUS_SUCCESS)
            {
                return res;
            }
            if(attr->ndx >= attr->max)
            {
                attr->max *= 2;
                attr->entry = (globus_i_xio_attr_ent_t *)
                    globus_realloc(attr->entry, attr->max *
                            sizeof(globus_i_xio_attr_ent_t));
            }
            attr->entry[attr->ndx].driver = driver;
            attr->entry[attr->ndx].driver_data = ds;
            attr->ndx++;
        }
#       ifdef HAVE_STDARG_H
        {
            va_start(ap, cmd);
        }
#       else
        {
            va_start(ap);
        }
#       endif
        res = driver->attr_cntl_func(ds, cmd, ap);
        if(res != GLOBUS_SUCCESS)
        {
            return res;
        }
        va_end(ap);
    }
    else
    {
        /* set non driver specific attributes.  none defined yet */
    }

    return GLOBUS_SUCCESS;
}

/*
 *
 */
globus_result_t
globus_xio_attr_destroy(
    globus_xio_attr_t                           attr)
{
    int                                         ctr;
    globus_result_t                             res = GLOBUS_SUCCESS;
    globus_result_t                             tmp_res;

    if(attr == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_attr_destroy");
    }
    
    for(ctr = 0; ctr < attr->max; ctr++)
    {
        /* report the last seen error but be sure to attempt to clean 
            them all */
        tmp_res = attr->entry[ctr].driver->attr_destroy_func(
                attr->entry[ctr].driver_data);
        if(tmp_res != GLOBUS_SUCCESS)
        {
            res = tmp_res;
        }
    }

    globus_free(attr->entry);
    globus_free(attr);

    return res;
}

globus_result_t
globus_xio_attr_copy(
    globus_xio_attr_t *                         dst,
    globus_xio_attr_t                           src)
{
    globus_i_xio_attr_t *                       xio_attr_src;
    globus_i_xio_attr_t *                       xio_attr_dst;
    globus_result_t                             res;
    int                                         ctr;
    int                                         ctr2;

    if(dst == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_attr_copy");
    }

    if(src == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_attr_copy");
    }

    xio_attr_src = src;

    xio_attr_dst = (globus_i_xio_attr_t *)
            globus_malloc(sizeof(globus_i_xio_attr_t));

    /* check for memory alloc failure */
    if(xio_attr_dst == NULL)
    {
        return GlobusXIOErrorMemoryAlloc("globus_xio_attr_copy");
    }

    xio_attr_dst->entry = (globus_i_xio_attr_ent_t *)
        globus_malloc(sizeof(globus_i_xio_attr_ent_t) *
            GLOBUS_XIO_ATTR_ARRAY_BASE_SIZE);
    if(xio_attr_dst->entry == NULL)
    {
        globus_free(xio_attr_dst);
        return GlobusXIOErrorMemoryAlloc("globus_xio_attr_copy");
    }

    memset(xio_attri_dst, 0, sizeof(globus_i_xio_attr_t));
    memset(xio_attri_dst->entry, 0, 
        sizeof(globus_i_xio_attr_ent_t) * GLOBUS_XIO_ATTR_ARRAY_BASE_SIZE);

    /* copy all general attrs */
    xio_attr_dst->max = xio_attr_src->max;
    xio_attr_dst->ndx = xio_attr_src->ndx;
 
    for(ctr = 0; ctr < xio_attr_dst->ndx; ctr++)
    {
        xio_attr_dst->entry[ctr].driver = xio_attr_src->entry[ctr].driver;

        res = xio_attr_dst->entry[ctr].driver->attr_copy_func(
                &xio_attr_dst->entry[ctr].drivers_data,
                xio_attr_src->entry[ctr].drivers_data);
        if(res != GLOBUS_SUCCESS)
        {
            globus_result_t                     res2;

            for(ctr2 = 0; ctr2 < ctr; ctr2++)
            {
                /* ignore result here */
                xio_attr_dst->entry[ctr].driver->attr_destroy_func(
                    xio_attr_dst->entry[ctr].driver_data);
            }
            globus_free(xio_attr_dst->entry);
            globus_free(xio_attr_dst);

            return res;
        }
    }

    *dst = xio_attr_dst;

    return GLOBUS_SUCCESS;
}
/*******************************************************************
 *                       data descriptor stuff
 ******************************************************************/
/* 
 *  the main difference between a dd and an attr is that the DD
 *  has the driver specific data in order of the drivers in the handle 
 *
 *  the same internal data structures are used.  the only difference
 *  in accessing these data structures is the assumptoin of order.
 */

/*
 *
 */
globus_result_t
globus_xio_data_descriptor_init( 
    globus_xio_data_descriptor_t *              data_desc,
    globus_xio_handle_t                         handle)
{
    globus_i_xio_dd_t *                         xio_dd;

    if(data_desc == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_data_descriptor_init");
    }
    if(handle == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_data_descriptor_init");
    }

    xio_dd = (globus_i_xio_dd_t *) globus_malloc(
                sizeof(globus_i_xio_dd_t) + (sizeof(globus_i_xio_attr_ent_t) *
                    (handle->stack_size - 1)));
    /* check for memory alloc failure */
    if(xio_dd == NULL)
    {
        return GlobusXIOErrorMemoryAlloc("globus_xio_data_descriptor_init");
    }

    xio_dd->stack_size = handle->stack_size;

    for(ctr = 0; ctr < xio_dd->stack_size; ctr++)
    {
        xio_dd->entry[ctr].driver = handle->context->entry[ctr].driver;
        xio_dd->entry[ctr].driver_data = NULL;
    }

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_data_descriptor_destroy(
    globus_xio_data_descriptor_t                data_desc)
{
    int                                         ctr;
    globus_result_t                             res = GLOBUS_SUCCESS;
    globus_result_t                             tmp_res;

    if(data_desc == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_data_descriptor_init");
    }

    for(ctr = 0; ctr < data_desc->stack_size; ctr++)
    {
        if(l_dd->drivers_data[ctr] != NULL)
        {
            tmp_res = data_desc->entry[ctr].attr_destroy_func(
                        data_desc->entry[ctr].driver_data);
            if(tmp_res != GLOBUS_SUCCESS)
            {
                res = tmp_res;
            }
        }
    }

    globus_free(data_desc);

    return res;
}

globus_result_t
globus_xio_data_descriptor_cntl(
    globus_xio_data_descriptor_t                data_desc,
    globus_xio_driver_t                         driver,
    int                                         cmd,
    ...)
{
    globus_result_t                             res;
    int                                         ndx;

    if(data_desc == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_data_descriptor_cntl");
    }

    if(driver != NULL)
    {
        ndx = -1;
        for(ctr = 0; ctr < data_desc->stack_size && ndx == -1; ctr++)
        {
            if(driver == data_desc->entry[ctr].driver)
            {
                if(data_desc->entry[ctr].driver_data == NULL)
                {
                    res = data_desc->entry[ctr].driver->attr_init_func(
                            &data_desc->entry[ctr].driver_data);
                    if(res != GLOBUS_SUCCESS)
                    {
                        return res;
                    }
                }
                ndx = ctr;
            }
        }
        if(ndx == -1)
        {
            /* throw error */
            return GlobusXIOErrorDriverNotFound(
                        "globus_xio_data_descriptor_cntl");
        }
#       ifdef HAVE_STDARG_H
        {
            va_start(ap, cmd);
        }
#       else
        {
            va_start(ap);
        }
#       endif

        res = data_desc->entry[ndx].driver->attr_cntl_func(
                data_desc->entry[ndx].driver_data,
                cmd,
                ap);
        if(res != GLOBUS_SUCCESS)
        {
            return res;
        }
        va_end(ap);
    }
    else
    {
        /* TODO: add code for general dd attributes */
    }

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_data_descriptor_copy(
    globus_xio_data_descriptor_t *              dst,
    globus_xio_data_descriptor_t                src)
{
    globus_i_xio_dd_t *                         xio_dd_src;
    globus_i_xio_dd_t *                         xio_dd_dst;
    globus_result_t                             res;
    int                                         ctr;
    int                                         ctr2;
    int                                         tmp_size;

    if(dst == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_attr_copy");
    }

    if(src == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_attr_copy");
    }

    xio_dd_src = src;

    tmp_size = sizeof(globus_i_xio_dd_t) + 
        (sizeof(globus_i_xio_attr_ent_t) * (xio_dd_src->stack_size - 1));
    xio_dd_dst = (globus_i_xio_dd_t *)globus_malloc(tmp_size);
    /* check for memory alloc failure */
    if(xio_dd_dst == NULL)
    {
        return GlobusXIOErrorMemoryAlloc("globus_xio_attr_copy");
    }

    memset(xio_dd_dst, 0, tmp_size);

    /* copy all general attrs */
    xio_dd_dst->stack_size = xio_dd_src->stack_size;
 
    for(ctr = 0; ctr < xio_attr_dst->stack_size; ctr++)
    {
        xio_dd_dst->entry[ctr].driver = xio_dd_src->entry[ctr].driver;

        res = xio_dd_dst->entry[ctr].driver->attr_copy_func(
                &xio_dd_dst->entry[ctr].drivers_data,
                xio_dd_src->entry[ctr].drivers_data);
        if(res != GLOBUS_SUCCESS)
        {
            for(ctr2 = 0; ctr2 < ctr; ctr2++)
            {
                /* ignore result here */
                xio_dd_dst->entry[ctr].driver->attr_destroy_func(
                    xio_dd_dst->entry[ctr].driver_data);
            }
            globus_free(xio_dd_dst);

            return res;
        }
    }

    *dst = xio_dd_dst;

    return GLOBUS_SUCCESS;
}
