#include "globus_i_xio.h"

/************************************************************************
 *                  internal functions
 ***********************************************************************/

/*
 *
 *  create the target structure.
 *
 *  create an array of target_stack entries from the passed in stack
 *  then loop through the drivers and call TargetInit on each.
 */
globus_result_t
globus_i_xio_target_init(
    struct globus_i_xio_target_s *              l_target,
    struct globus_xio_attr_s *                  l_target_attr,
    const char *                                contact_string,
    struct globus_xio_stack_s *                 l_stack)
{
    struct globus_i_xio_driver_target_stack_s * traget_stack = NULL;
    globus_list_t                               driver_list;
    int                                         ndx;
    int                                         ctr;
    void *                                      driver_attr;
    int                                         stack_size;
    globus_result_t                             res;

    GlobusXIOStackGetDrivers(l_stack, driver_list);
    stack_size = globus_list_size(driver_list);
    if(stack_size == 0)
    {
        res = GlobusXIOErrorInvalidStack("globus_xio_target_init");
        goto err;
    }


    target_stack = (struct globus_i_xio_target_stack_s *)
                        globus_malloc(
                            sizeof(struct globus_i_xio_target_stack_s) * 
                                stack_size);
    if(target_stack == NULL)
    {
        res = GlobusXIOErrorMemoryAlloc("globus_xio_target_init");
        goto err;
    }

    ndx = 0;
    for(list = driver_list; 
    !globus_list_empty(list); 
        list = globus_list_rest(list))
    {
        target_stack[ndx].driver = globus_list_first(list);

        /* pull driver specific info out of target attr */
        driver_attr = globus_l_xio_attr_find_driver(
                        l_target_attr, 
                        target_stack[ndx].driver);

        GlobusXIODriverTargetInit(
            res, 
            target_stack[ndx].driver,
            &target_stack[ndx].target,
            driver_attr, 
            contact_string);
        if(res != GLOBUS_SUCCESS)
        {
            globus_result_t                             res2;

            /* loop back through and destroy all inited targets */
            for(ctr = 0; ctr < ndx; ctr++)
            {
                /* ignore the result, but it must be passed */
                GlobusXIODriverTargetDestroy(
                    res2,
                    target_stack[ndx].driver,
                    target_stack[ndx].target);
            }
            goto err;
        }

        ndx++;
    }
    /* hell has broken loose if these are not equal */
    globus_assert(ndx == stack_size);

    l_target->target_stack = target_stack;
    l_target->stack_size = stack_size;
    *target = l_target;

    return GLOBUS_SUCCESS;

    /* 
     *  ERROR handling code.
     *
     *  all non NULL alloced variables are freed
     */
    err:

    if(driver_stack != NULL)
    {
        globus_free(driver_stack);
    }

    return res;
}

/*
 *  verify the driver is in this stack.
 *  call target control on the driver
 *
 *  if not driver specific there is nothing to do (yet)
 */
globus_result_t
globus_i_xio_target_cntl(
    struct globus_i_xio_target_s *              target,
    struct globus_i_xio_driver_s *              driver,
    int                                         cmd,
    va_list                                     ap)
{
    int                                         ctr;
    globus_result_t                             res;

    if(driver != NULL)
    {
        for(ctr = 0; ctr < l_target->stack_size; ctr++)
        {
            if(l_target->target_stack[ctr].driver == driver)
            {
                GlobusXIODriverTargetCntl(
                    res,
                    driver, 
                    l_target->target_stack[ctr].target,
                    cmd,
                    ap);

                return res;
            }
        }
        return GlobusXIOErrorDriverNotFound("globus_i_xio_target_cntl");
    }
    else
    {
        /* do general target modifications */
    }

    return GLOBUS_SUCCESS;
}

/*
 *  loop through all the drivers to call target destroy, then clean up 
 *  the memory devoted to the array.
 */
globus_result_t
globus_i_xio_target_destroy(
    struct globus_xio_target_s *                target)
{
    int                                         ctr;
    globus_result_t                             res = GLOBUS_SUCCESS;

    for(ctr = 0; ctr < l_target->stack_size && res == GLOBUS_SUCCESS; ctr++)
    {
        GlobusXIODriverTargetDestroy(
            res,
            l_target->target_stack[ctr].driver,
            l_target->target_stack[ctr].target);
    }

    globus_free(l_target->target_stack);

    return res;
}

/************************************************************************
 *                  external API
 ***********************************************************************/
globus_result_t
globus_xio_target_init(
    globus_xio_target_t *                       target,
    globus_xio_attr_t                           target_attr,
    const char *                                contact_string,
    globus_xio_stack_t                          stack)
{
    struct globus_i_xio_target_s *              l_target;

    /*
     *  parameter checking 
     */
    if(target == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_target_init");
    }
    if(contact_string == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_target_init");
    }
    if(stack == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_target_init");
    }

    l_target = (struct globus_i_xio_target_s *)
                    globus_malloc(sizeof(struct globus_i_xio_target_s));
    if(l_target == NULL)
    {
        return GlobusXIOErrorMemoryAlloc("globus_xio_target_init");
    }

    res = globus_i_xio_target_init(
              l_target,
              target_attr,
              contact_string,
              stack);
    if(res != GLOBUS_SUCCESS)
    {
        globus_free(l_target);
        return res;
    }

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_target_cntl(
    globus_xio_target_t                         target,
    globus_xio_driver_t                         driver,
    int                                         cmd,
    ...)
{
    struct globus_i_xio_target_s *              l_target;
    globus_result_t                             res;
    va_list                                     ap;

    /*
     *  parameter checking 
     */
    if(target == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_target_cntl");
    }
    if(cmd < 0)
    {
        return GlobusXIOErrorBadParameter("globus_xio_target_cntl");
    }

    l_target = (struct globus_i_xio_target_s *) target;

#   ifdef HAVE_STDARG_H
    {
        va_start(ap, cmd);
    }
#   else
    {
        va_start(ap);
    }
#   endif

    res = globus_i_xio_target_cntl(l_target, l_driver, cmd, ap);

    va_end(ap);

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_xio_target_destroy(
    globus_xio_target_t                         target)
{
    struct globus_i_xio_target_s *              l_target;

    /*
     *  parameter checking 
     */
    if(target == NULL)
    {
        return GlobusXIOErrorBadParameter("globus_xio_target_cntl");
    }

    l_target = (struct globus_i_xio_target_s *) target;

    res = globus_i_xio_target_destroy(l_target);

    globus_free(l_target);

    return res;
}
