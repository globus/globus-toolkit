#include "globus_common.h"
#include "globus_xio.h"

/*******************************************************************
 *                     internal structures
 ******************************************************************/
struct globus_l_xio_dd_s
{

    /* matching length arrays */
    void **                                     drivers;
    void **                                     drivers_data;

    /* contains the length of the above 2 arrays */
    int                                         stack_size;
};

/*******************************************************************
 *                         api functions
 ******************************************************************/
/*
 *
 */
globus_result_t
globus_xio_data_descriptor_init( 
    globus_xio_data_descriptor_t *              data_desc,
    globus_xio_handle_t                         handle)
{
    struct globus_l_xio_dd_s *                  l_dd;
    int                                         stack_size;
    void **                                     drivers;

    if(data_desc == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_data_descriptor_init");
    }

    l_dd = (struct globus_l_xio_dd_s *) globus_malloc(
                                            sizeof(struct globus_l_xio_dd_s));
    /* check for memory alloc failure */
    if(l_dd == NULL)
    {
        return GlobusXIOErrorMemoryAlloc("globus_xio_data_descriptor_init");
    }

    GlobusXIOHandleGetStackSize(handle, stack_size);    
    GlobusXIOHandleGetDriverArray(handle, drivers);

    l_dd->stack_size = stack_size;
    l_dd->drivers = globus_malloc(sizeof(void *) * stack_size);
    l_dd->drivers_data = globus_malloc(sizeof(void *) * stack_size);

    for(ctr = 0; ctr < stack_size; ctr++)
    {
        l_dd->drivers[ctr] = drivers[ctr];
        l_dd->drivers_data[ctr] = NULL;
    }

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_data_descriptor_destroy(
    globus_xio_data_descriptor_t                data_desc)
{
    struct globus_l_xio_dd_s *                  l_dd;
    int                                         ctr;
    globus_result_t                             res;

    if(data_desc == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_data_descriptor_init");
    }

    l_dd = data_desc;
    for(ctr = 0; ctr < l_dd->stack_size; ctr++)
    {
        if(l_dd->drivers_data[ctr] != NULL)
        {
            GlobusXIODriverDDDestroy(
                res,
                l_dd->drivers[ctr], 
                l_dd->drivers_data[ctr]);
            if(res != GLOBUS_SUCCESS)
            {
                return res;
            }
        }
    }

    globus_free(l_dd->drivers);
    globus_free(l_dd->drivers_data);
    globus_free(l_dd);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_data_descriptor_cntl(
    globus_xio_data_descriptor_t                data_desc,
    globus_xio_driver_t                         driver,
    int                                         cmd,
    ...)
{
    void *                                      ds;
    globus_result_t                             res;
    int                                         ndx;

    if(data_desc == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_data_descriptor_cntl");
    }

#   ifdef HAVE_STDARG_H
    {
        va_start(ap, cmd);
    }
#   else
    {
        va_start(ap);
    }
#   endif

    if(driver != NULL)
    {
        ndx = -1;
        for(ctr = 0; ctr < l_dd->stack_size && !found; ctr++)
        {
            if(driver == l_dd->drivers[ctr])
            {
                if(l_dd->drivers_data[ctr] == NULL)
                {
                    GlobusXIODriverDDInit(
                        res,
                        l_dd->drivers[ctr],
                        &l_dd->drivers_data[ctr]);
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
        GlobusXIODriverDDCntl(
            res,
            l_dd->drivers[ndx],
            l_dd->drivers_data[ndx],
            cmd,
            ap);
        if(res != GLOBUS_SUCCESS)
        {
            return res;
        }
    }
    else
    {
        /* TODO: add code for general dd attributes */
    }
    va_end(ap);

    return GLOBUS_SUCCESS;
}

