#include "globus_common.h"
#include "globus_xio.h"

#define GLOBUS_XIO_ATTR_ARRAY_BASE_SIZE         16

/*******************************************************************
 *                     internal structures
 ******************************************************************/
struct globus_l_xio_attr_ds_s
{
    void *                                      driver;
    void *                                      driver_attr;
}

struct globus_l_xio_attr_s
{
    struct globus_l_xio_attr_ds_s *             ds_array;
    int                                         max;
    int                                         ndx;
};

/*******************************************************************
 *                     internal functions
 ******************************************************************/
void *
globus_l_xio_attr_find_driver(
    struct globus_l_xio_attr_ds_s *             array,
    void *                                      driver)
{
    int                                         ctr;

    for(ctr = 0; array[ctr].driver != NULL; ctr++)
    {
        if(array[ctr].driver == driver)
        {
            return array[ctr].driver_attr;
        }
    }

    return NULL;
}

/*******************************************************************
 *                         api functions
 ******************************************************************/
/*
 *
 */
globus_result_t
globus_xio_attr_init(
    globus_xio_attr_t *                         attr)
{
    struct globus_l_xio_attr_s *                l_attr;
    int                                         tmp_size;

    if(attr == NULL)
    {
        return globus_error_put(globus_error_wrap_errno_error(
                            GLOBUS_XIO_MODULE,
                            EINVAL,
                            GLOBUS_XIO_INVALID_PARAMETER,
                            "NULL Parameter"));
    }
    
    l_attr = (struct globus_l_xio_attr_s *)
                globus_malloc(sizeof(struct globus_l_xio_attr_s));

    /* check for memory alloc failure */
    if(l_attr == NULL)
    {
        return globus_error_put(globus_error_wrap_errno_error(
                            GLOBUS_XIO_MODULE,
                            ENOMEM,
                            GLOBUS_XIO_MALLOC_FAILURE,
                            "globus_malloc() failed."));
    }

    /* intialize the attr structure */
    memset(l_attr, 0, sizeof(struct globus_l_xio_attr_s));
    tmp_size = sizeof(struct globus_l_xio_attr_ds_s) *
                    GLOBUS_XIO_ATTR_ARRAY_BASE_SIZE;
    l_attr->driver_attr = (struct globus_l_xio_attr_ds_s *)
            globus_malloc(tmp_size);
    memset(l_attr->driver_attr, 0, tmp_size);
    l_attr->max = GLOBUS_XIO_ATTR_ARRAY_BASE_SIZE;
    l_attr->ndx = 0;
    
    attr = l_attr;

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
    struct globus_l_xio_attr_s *                l_attr;
    va_list                                     ap;
    globus_result_t                             res;
    void *                                      ds_ptr;

    if(attr == NULL)
    {
        return globus_error_put(globus_error_wrap_errno_error(
                            GLOBUS_XIO_MODULE,
                            EINVAL,
                            GLOBUS_XIO_INVALID_PARAMETER,
                            "NULL Parameter"));
    }

    l_attr = (struct globus_l_xio_attr_s *) attr;

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
        ds = globus_l_xio_attr_find_driver(&l_attr->driver_hash, driver);
        if(ds == NULL)
        {
            GlobusXIODriverAttrInit(
                res,
                driver, 
                &ds_ptr);
            if(res != GLOBUS_SUCCESS)
            {
                return res;
            }
            l_attr->ndx++;
            if(l_attr->ndx >= l_attr->max)
            {
                l_attr->max *= 2;
                l_attr->ds_array = (struct globus_l_xio_attr_ds_s *)
                    globus_realloc(l_attr->ds_array, l_attr->max *
                            sizeof(struct globus_l_xio_attr_ds_s));
            }
            l_attr->ds_array[l_attr->ndx].driver = driver;
            l_attr->ds_array[l_attr->ndx].driver_attr = ds_ptr;
            l_attr->ds_array[l_attr->ndx + 1].driver = NULL;
        }
        GlobusXIODriverAttrCntl(
            res,
            l_attr->ds_array[l_attr->ndx].driver, 
            l_attr->ds_array[l_attr->ndx].driver_attr,
            cmd, 
            ap);
        if(res != GLOBUS_SUCCESS)
        {
            return res;
        }
    }
    else
    {
        /* set non driver specific attributes.  none defined yet */
    }
    va_end(ap);

    return GLOBUS_SUCCESS;
}

/*
 *
 */
globus_result_t
globus_xio_attr_destroy(
    globus_xio_attr_t                           attr)
{
    struct globus_l_xio_attr_ds_s *             array;
    struct globus_l_xio_attr_s *                l_attr;

    if(attr == NULL)
    {
        return globus_error_put(globus_error_wrap_errno_error(
                            GLOBUS_XIO_MODULE,
                            EINVAL,
                            GLOBUS_XIO_INVALID_PARAMETER,
                            "NULL Parameter"));
    }
    
    l_attr = (struct globus_l_xio_attr_s *) attr;
    array = l_attr->ds_array;
    for(ctr = 0; array[ctr].driver != NULL; ctr++)
    {
        GlobusXIODriverAttrDestroy(
            res, 
            array[ctr].driver, 
            array[ctr].driver_attr);
        if(res != GLOBUS_SUCCESS)
        {
            return res;
        }
    }
    
    globus_free(array);
    globus_free(l_attr);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_attr_copy(
    globus_xio_attr_t *                         dst,
    globus_xio_attr_t                           src)
{
    struct globus_l_xio_attr_s *                l_attr_src;
    struct globus_l_xio_attr_s *                l_attr_dst;
    int                                         tmp_size;
    int                                         ctr;
    globus_result_t                             res;

    if(dst == NULL)
    {
    }

    if(src == NULL)
    {
    }

    l_attr_dst = (struct globus_l_xio_attr_s *)
                globus_malloc(sizeof(struct globus_l_xio_attr_s));

    /* check for memory alloc failure */
    if(l_attr_dst == NULL)
    {
        return globus_error_put(globus_error_wrap_errno_error(
                            GLOBUS_XIO_MODULE,
                            ENOMEM,
                            GLOBUS_XIO_MALLOC_FAILURE,
                            "globus_malloc() failed."));
    }

    l_attr_src = (struct globus_l_xio_attr_s *) src;
    /* intialize the attr structure */
    memset(l_attr_dst, 0, sizeof(struct globus_l_xio_attr_s));

    tmp_size = sizeof(struct globus_l_xio_attr_ds_s) * l_attr_src->_max;
    l_attr_dst->ds_array = (struct globus_l_xio_attr_ds_s *)
            globus_malloc(tmp_size);
    memset(l_attr->driver_attr, 0, tmp_size);
    l_attr_dst->max = l_attr_src->max;
    l_attr_dst->ndx = l_attr_src->ndx;
    
    for(ctr = 0; ctr < l_attr_dst->max; ctr++)
    {
        if(l_attr_src->ds_array[ctr].driver != NULL)
        {
            GlobusXIODriverAttrCopy(
                res, 
                l_attr_src->ds_array[ctr].driver,
                &l_attr_dst->ds_array[ctr].driver_attr,
                l_attr_src->ds_array[ctr].driver_attr);
            if(res != GLOBUS_SUCCESS)
            {
                globus_result_t                     res2;

                for(ctr2 = 0; ctr2 < ctr; ctr2++)
                {
                    /* ignore result here */
                    GlobusXIODriverAttrDestroy(
                        res2,
                        l_attr_dst->ds_array[ctr2].driver,
                        l_attr_dst->ds_array[ctr2].driver_attr);
                }
                globus_free(l_attr_dst->ds_array);
                globus_free(l_attr_dst);

                return res;
            }
        }
        else
        {
            l_attr_dst->ds_array[ctr].driver = NULL;
        }
    }

    return GLOBUS_SUCCESS;
}
