#include "globus_common.h"
#include "globus_i_xio.h"

#define GLOBUS_XIO_ATTR_ARRAY_BASE_SIZE         16

#define GlobusIXIOAttrDriverFuncCallStart(__attr, __res, __driver, __driver_attr)  \
{                                                                   \
    int                                         __ctr;              \
    struct globus_l_xio_attr_ds_s *             __array;            \
                                                                    \
    res = GLOBUS_SUCCESS;                                           \
    __array = __attr->ds_array;                                     \
    for(__ctr = 0; __ctr < __attr->ndx && res == GLOBUS_SUCCESS;    \
        __ctr++)                                                    \
    {                                                               \
        __driver = __array[ctr].driver;                             \
        __driver_attr = __array[ctr].driver_attr;                   \

#define GlobusIXIOAttrDriverFuncCallEnd()                           \
    }                                                               \
}
/*******************************************************************
 *                     internal functions
 ******************************************************************/
void *
globus_l_xio_attr_find_driver(
    struct globus_l_xio_attr_s *                l_attr,
    void *                                      driver)
{
    int                                         ctr;
    struct globus_l_xio_attr_ds_s *             array;

    array = l_attr->ds_array;
    for(ctr = 0; ctr < l_attr->ndx; ctr++)
    {
        if(array[ctr].driver == driver)
        {
            return array[ctr].driver_attr;
        }
    }

    return NULL;
}

globus_result_t
globus_i_xio_attr_driver_call(
    struct globus_l_xio_attr_s *                l_attr,
    globus_xio_driver_t                         driver,
    func)
{
    int                                         ctr;
    struct globus_l_xio_attr_ds_s *             array;

    array = l_attr->ds_array;
    for(ctr = 0; ctr < l_attr->ndx; ctr++)
    {
        if(array[ctr].driver == driver)
        {
            return func();
        }
    }

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_i_xio_attr_init(
    struct globus_l_xio_attr_s *                l_attr)
{
    int                                         tmp_size;

    /* intialize the attr structure */
    memset(l_attr, 0, sizeof(struct globus_l_xio_attr_s));
    tmp_size = sizeof(struct globus_l_xio_attr_ds_s) *
                    GLOBUS_XIO_ATTR_ARRAY_BASE_SIZE;
    l_attr->driver_attr = (struct globus_l_xio_attr_ds_s *)
            globus_malloc(tmp_size);
    if(l_attr->driver_attr == NULL)
    {
        return GlobusXIOErrorMemoryAlloc("globus_xio_attr_init");
    }
    
    memset(l_attr->driver_attr, 0, tmp_size);
    l_attr->max = GLOBUS_XIO_ATTR_ARRAY_BASE_SIZE;
    l_attr->ndx = 0;
    
    attr = l_attr;

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_i_xio_attr_cntl(
    struct globus_l_xio_attr_s *                l_attr,
    globus_xio_driver_t                         driver,
    int                                         cmd,
    va_list                                     ap)
{
    if(driver != NULL)
    {
        ds = globus_l_xio_attr_find_driver(&l_attr->driver_hash, driver);
        if(ds == NULL)
        {
            GlobusXIODriverAttrInit(
                res,
                driver, 
                &ds);
            if(res != GLOBUS_SUCCESS)
            {
                return res;
            }
            if(l_attr->ndx >= l_attr->max)
            {
                l_attr->max *= 2;
                l_attr->ds_array = (struct globus_l_xio_attr_ds_s *)
                    globus_realloc(l_attr->ds_array, l_attr->max *
                            sizeof(struct globus_l_xio_attr_ds_s));
            }
            l_attr->ds_array[l_attr->ndx].driver = driver;
            l_attr->ds_array[l_attr->ndx].driver_attr = ds;
            l_attr->ndx++;
        }
        GlobusXIODriverAttrCntl(
            res,
            driver, 
            ds,
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

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_i_xio_attr_destroy(
    struct globus_l_xio_attr_s *                l_attr)
{
    struct globus_l_xio_attr_ds_s *             array;

    array = l_attr->ds_array;
    for(ctr = 0; ctr < l_attr->ndx; ctr++)
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
globus_i_xio_attr_copy(
    struct globus_l_xio_attr_s *                l_attr_dst,
    struct globus_l_xio_attr_s *                l_attr_src)
{
    int                                         tmp_size;
    int                                         ctr;
    int                                         ctr2;
    globus_result_t                             res;

    /* intialize the attr structure */
    memset(l_attr_dst, 0, sizeof(struct globus_l_xio_attr_s));

    tmp_size = sizeof(struct globus_l_xio_attr_ds_s) * l_attr_src->_max;
    l_attr_dst->ds_array = (struct globus_l_xio_attr_ds_s *)
            globus_malloc(tmp_size);
    memset(l_attr->driver_attr, 0, tmp_size);
    l_attr_dst->max = l_attr_src->max;
    l_attr_dst->ndx = l_attr_src->ndx;
    
    for(ctr = 0; ctr < l_attr_dst->ndx; ctr++)
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

    return GLOBUS_SUCCESS;
}
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
    struct globus_l_xio_attr_s *                l_attr;

    if(attr == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_attr_init");
    }
    
    l_attr = (struct globus_l_xio_attr_s *)
                globus_malloc(sizeof(struct globus_l_xio_attr_s));

    /* check for memory alloc failure */
    if(l_attr == NULL)
    {
        return GlobusXIOErrorMemoryAlloc("globus_xio_attr_init");
    }

    res = globus_i_xio_attr_init(l_attr);

    *attr = l_attr;

    return res;
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
    void *                                      ds;

    if(attr == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_attr_cntl");
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

    res = globus_i_xio_attr_cntl(
            l_attr,
            driver,
            cmd,
            ap);

    va_end(ap);

    return res;
}

/*
 *
 */
globus_result_t
globus_xio_attr_destroy(
    globus_xio_attr_t                           attr)
{
    struct globus_l_xio_attr_s *                l_attr;

    if(attr == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_attr_destroy");
    }
    
    l_attr = (struct globus_l_xio_attr_s *) attr;

    return globus_i_xio_attr_destroy(l_attr);
}

globus_result_t
globus_xio_attr_copy(
    globus_xio_attr_t *                         dst,
    globus_xio_attr_t                           src)
{
    struct globus_l_xio_attr_s *                l_attr_src;
    struct globus_l_xio_attr_s *                l_attr_dst;
    globus_result_t                             res;

    if(dst == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_attr_copy");
    }

    if(src == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_attr_copy");
    }

    l_attr_dst = (struct globus_l_xio_attr_s *)
                globus_malloc(sizeof(struct globus_l_xio_attr_s));

    /* check for memory alloc failure */
    if(l_attr_dst == NULL)
    {
        return GlobusXIOErrorMemoryAlloc("globus_xio_attr_copy");
    }

    l_attr_src = (struct globus_l_xio_attr_s *) src;

    return globus_i_xio_attr_copy(l_attr_dst, l_attr_src);
}
