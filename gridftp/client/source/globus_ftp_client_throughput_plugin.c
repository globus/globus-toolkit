#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_ftp_client_throughput_plugin.c GridFTP Throughput Performance Plugin Implementation
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 * $Author$
 */

#include "globus_ftp_client_throughput_plugin.h"
#include "globus_ftp_client_perf_plugin.h"
#include <time.h>
#include <sys/timeb.h>

#define GLOBUS_L_FTP_CLIENT_THROUGHPUT_PLUGIN_NAME "globus_ftp_client_throughput_plugin"

static globus_bool_t globus_l_ftp_client_throughput_plugin_activate(void);
static globus_bool_t globus_l_ftp_client_throughput_plugin_deactivate(void);

globus_module_descriptor_t globus_i_ftp_client_throughput_plugin_module =
{
    GLOBUS_L_FTP_CLIENT_THROUGHPUT_PLUGIN_NAME,
    globus_l_ftp_client_throughput_plugin_activate,
    globus_l_ftp_client_throughput_plugin_deactivate,
    GLOBUS_NULL
};

static
int
globus_l_ftp_client_throughput_plugin_activate(void)
{
    int rc;

    rc = globus_module_activate(GLOBUS_FTP_CLIENT_PERF_PLUGIN_MODULE);
    return rc;
}

static
int
globus_l_ftp_client_throughput_plugin_deactivate(void)
{
    return globus_module_deactivate(GLOBUS_FTP_CLIENT_PERF_PLUGIN_MODULE);
}

typedef struct throughput_plugin_info_s
{
    globus_ftp_client_throughput_plugin_begin_cb_t      begin_cb;
    globus_ftp_client_throughput_plugin_stripe_cb_t     per_stripe_cb;
    globus_ftp_client_throughput_plugin_total_cb_t      total_cb;
    globus_ftp_client_throughput_plugin_complete_cb_t   complete_cb;

    void *                                              user_arg;

    double *                                    prev_times;
    double *                                    cur_times;
    globus_off_t *                              prev_bytes;
    globus_off_t *                              cur_bytes;

    double                                      start_time;
    globus_bool_t                               start_marker_used;

    int                                         num_stripes;

} throughput_plugin_info_t;

/**
 * Perf plugin begin callback
 * @ingroup globus_ftp_client_throughput_plugin
 *
 * This callback is called by the perf_plugin when a transfer, either a
 * get, put, or 3pt, has been started.  This will call the user's 'begin'
 * callback.
 */

static
void
throughput_plugin_begin_cb(
    globus_ftp_client_handle_t *                handle,
    void *                                      user_specific,
    const char *                                source_url,
    const char *                                dest_url)
{
    throughput_plugin_info_t *                  info;
    struct timeb                                timebuf;

    info = (throughput_plugin_info_t *) user_specific;

    if(info->begin_cb)
    {
        info->begin_cb(
            handle,
            info->user_arg,
            source_url,
            dest_url);
    }

    ftime(&timebuf);
    info->start_time = timebuf.time + (timebuf.millitm / 1000.0);
}

/**
 * Perf plugin marker callback
 * @ingroup globus_ftp_client_throughput_plugin
 *
 * This callback is called by the perf_plugin when it has performance
 * data for us.  This callback will also call the user's 'per_stripe'
 * and 'total' callbacks with the calculated throughputs
 */

static
void
throughput_plugin_marker_cb(
    globus_ftp_client_handle_t *                handle,
    void *                                      user_specific,
    long                                        time_stamp_int,
    char                                        time_stamp_tength,
    int                                         stripe_ndx,
    int                                         num_stripes,
    globus_off_t                                nbytes)
{
    throughput_plugin_info_t *                  info;
    int                                         i;
    float                                       instantaneous_throughput;
    float                                       avg_throughput;
    double                                      time_stamp;
    double                                      elapsed;

    info = (throughput_plugin_info_t *) user_specific;

    time_stamp = time_stamp_int + (time_stamp_tength / 10.0);

    /* init prev and cur storage if not already done so */
    if(info->prev_times == GLOBUS_NULL)
    {
        info->start_marker_used = GLOBUS_FALSE;

        info->prev_times = (double *)
            globus_malloc(sizeof(double) * num_stripes);
        info->cur_times = (double *)
            globus_malloc(sizeof(double) * num_stripes);

        info->prev_bytes = (globus_off_t *)
            globus_malloc(sizeof(globus_off_t) * num_stripes);
        info->cur_bytes = (globus_off_t *)
            globus_malloc(sizeof(globus_off_t) * num_stripes);

        if(!(info->prev_times &&
            info->cur_times &&
            info->prev_bytes &&
            info->cur_bytes))
        {
            if(info->prev_times)
            {
                globus_free(info->prev_times);
            }

            if(info->cur_times)
            {
                globus_free(info->cur_times);
            }

            if(info->prev_bytes)
            {
                globus_free(info->prev_bytes);
            }

            if(info->cur_bytes)
            {
                globus_free(info->cur_bytes);
            }

            info->prev_times            = GLOBUS_NULL;
            info->cur_times             = GLOBUS_NULL;
            info->prev_bytes            = GLOBUS_NULL;
            info->cur_bytes             = GLOBUS_NULL;

            return;
        }

        info->num_stripes = num_stripes;

        i = num_stripes;
        while(i--)
        {
            info->prev_times[i] = 0;
            info->cur_times[i]  = 0;
            info->prev_bytes[i] = 0;
            info->cur_bytes[i]  = 0;
        }
    } /* init storage */

    /*
     * need to set stripe's start time
     * check for a 'start' marker...
     * only set the 'start' time once per stripe...
     * first 'start' marker received also sets total transfer start time
     * subsequent zero byte markers indicate no data
     */
    if(info->cur_times[stripe_ndx] < 0.1)
    {
        if(nbytes == 0)
        {
            info->cur_times[stripe_ndx] = time_stamp;

            if(!info->start_marker_used)
            {
                info->start_time = time_stamp;
                info->start_marker_used = GLOBUS_TRUE;
            }
        }
        else
        {
            info->cur_times[stripe_ndx] = info->start_time;
        }
    }

    /* dont allow duplicate timestamps (protects div by zero)
     * or a decrease in bytes
     * this also prevents 'start' markers from causing a callback
     */
    if(time_stamp - info->cur_times[stripe_ndx] < 0.1 ||
        nbytes < info->cur_bytes[stripe_ndx])
    {
        return;
    }

    info->prev_times[stripe_ndx] = info->cur_times[stripe_ndx];
    info->cur_times[stripe_ndx] = time_stamp;

    info->prev_bytes[stripe_ndx] = info->cur_bytes[stripe_ndx];
    info->cur_bytes[stripe_ndx] = nbytes;

    if(info->per_stripe_cb)
    {
        instantaneous_throughput =
            (info->cur_bytes[stripe_ndx] - info->prev_bytes[stripe_ndx]) /
            (info->cur_times[stripe_ndx] - info->prev_times[stripe_ndx]);

        avg_throughput =
            info->cur_bytes[stripe_ndx] /
            (info->cur_times[stripe_ndx] - info->start_time);

        info->per_stripe_cb(
            handle,
            info->user_arg,
            stripe_ndx,
            nbytes,
            instantaneous_throughput,
            avg_throughput);
    }

    if(info->total_cb)
    {
        instantaneous_throughput = 0;
        avg_throughput = 0;
        nbytes = 0;
        i = info->num_stripes;
        while(i--)
        {
            nbytes += info->cur_bytes[i];

            elapsed = info->cur_times[i] - info->prev_times[i];

            if(elapsed >= 0.1)
            {
                instantaneous_throughput += (float)
                    (info->cur_bytes[i] - info->prev_bytes[i]) /
                    elapsed;
            }

            elapsed = info->cur_times[i] - info->start_time;

            if(elapsed >= 0.1)
            {
                avg_throughput += (float)
                    info->cur_bytes[i] / elapsed;
            }
        }

        info->total_cb(
            handle,
            info->user_arg,
            nbytes,
            instantaneous_throughput,
            avg_throughput);
    }
}

/**
 * Perf plugin complete callback
 * @ingroup globus_ftp_client_throughput_plugin
 *
 * This callback is called by the perf_plugin when a transfer, either a
 * get, put, or 3pt, has completed (or failed).  This will call the user's
 *  'complete' callback.
 */

static
void
throughput_plugin_complete_cb(
    globus_ftp_client_handle_t *                handle,
    void *                                      user_specific,
    globus_bool_t                               success)
{
    throughput_plugin_info_t *                  info;

    info = (throughput_plugin_info_t *) user_specific;

    if(info->complete_cb)
    {
        info->complete_cb(handle, info->user_arg, success);
    }

    if(info->prev_times)
    {
        globus_free(info->prev_times);
        globus_free(info->cur_times);
        globus_free(info->prev_bytes);
        globus_free(info->cur_bytes);

        info->prev_times            = GLOBUS_NULL;
        info->cur_times             = GLOBUS_NULL;
        info->prev_bytes            = GLOBUS_NULL;
        info->cur_bytes             = GLOBUS_NULL;
    }
}

/**
 * Perf plugin user specific copy callback
 * @ingroup globus_ftp_client_throughput_plugin
 *
 * This callback is called by the perf_plugin when a copy of user_specific
 * data is required (for a new copy of the perf_plugin)
 */

static
void *
throughput_plugin_user_copy_cb(
    void *                                      user_specific)
{
    throughput_plugin_info_t *                  old_info;
    throughput_plugin_info_t *                  new_info;

    old_info = (throughput_plugin_info_t *) user_specific;

    new_info = (throughput_plugin_info_t *)
        globus_malloc(sizeof(throughput_plugin_info_t));

    if(new_info == GLOBUS_NULL)
    {
        return GLOBUS_NULL;
    }

    new_info->begin_cb          = old_info->begin_cb;
    new_info->per_stripe_cb     = old_info->per_stripe_cb;
    new_info->total_cb          = old_info->total_cb;
    new_info->complete_cb       = old_info->complete_cb;

    new_info->user_arg          = old_info->user_arg;

    new_info->prev_times        = GLOBUS_NULL;
    new_info->cur_times         = GLOBUS_NULL;
    new_info->prev_bytes        = GLOBUS_NULL;
    new_info->cur_bytes         = GLOBUS_NULL;

    new_info->start_time        = 0;
    new_info->num_stripes       = 0;

    return new_info;
}

/**
 * Perf plugin user specific destroy callback
 * @ingroup globus_ftp_client_throughput_plugin
 *
 * This callback is called by the perf_plugin when a copy of user_specific
 * data needs to be destroyed (because the copy of the perf_plugin is being
 * destroyed)
 */

static
void
throughput_plugin_user_destroy_cb(
    void *                                      user_specific)
{
    throughput_plugin_info_t *                  info;

    info = (throughput_plugin_info_t *) user_specific;

    if(info->prev_times)
    {
        globus_free(info->prev_times);
        globus_free(info->cur_times);
        globus_free(info->prev_bytes);
        globus_free(info->cur_bytes);
    }

    globus_free(info);
}

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

/**
 * Throughput plugin init
 * @ingroup globus_ftp_client_throughput_plugin
 *
 * Use this function to initialize a throughput plugin. The throughput plugin
 * sits on top of the perf_plugin. The only required param is 'plugin',
 * all others may be GLOBUS_NULL
 *
 * @param plugin
 *        a pointer to a plugin type to be initialized
 *
 * @param begin_cb
 *        the callback to be called upon the start of a transfer
 *
 * @param per_stripe_cb
 *        the callback to be called every time updated throughput info is
 *        available for a given stripe
 *
 * @param total_cb
 *        the callback to be called every time updated throughput info is
 *        available for any stripe
 *
 * @param complete_cb
 *        the callback to be called to indicate transfer completion
 *
 * @param user_arg
 *        a pointer to some user specific data that will be provided to
 *        all callbacks
 *
 * @return
 *        - GLOBUS_SUCCESS
 *        - Error on NULL plugin
 *        - Error on init perf plugin
 */

globus_result_t
globus_ftp_client_throughput_plugin_init(
    globus_ftp_client_plugin_t *                        plugin,
    globus_ftp_client_throughput_plugin_begin_cb_t      begin_cb,
    globus_ftp_client_throughput_plugin_stripe_cb_t     per_stripe_cb,
    globus_ftp_client_throughput_plugin_total_cb_t      total_cb,
    globus_ftp_client_throughput_plugin_complete_cb_t   complete_cb,
    void *                                              user_arg)
{
    throughput_plugin_info_t *                  info;
    globus_result_t                             result;
    static char *                               myname =
        "globus_ftp_client_throughput_plugin_init";

    if(plugin == GLOBUS_NULL)
    {
        return globus_error_put(globus_error_construct_string(
                GLOBUS_FTP_CLIENT_MODULE,
                GLOBUS_NULL,
                "[%s] NULL plugin at %s\n",
                GLOBUS_FTP_CLIENT_MODULE->module_name,
                myname));
    }

    info = (throughput_plugin_info_t *)
        globus_malloc(sizeof(throughput_plugin_info_t));

    if(info == GLOBUS_NULL)
    {
        return globus_error_put(globus_error_construct_string(
                                GLOBUS_FTP_CLIENT_MODULE,
                                GLOBUS_NULL,
                                "[%s] Out of memory at %s\n",
                                 GLOBUS_FTP_CLIENT_MODULE->module_name,
                                 myname));
    }

    /*
     *  initialize user specific structure.
     */
    info->begin_cb              = begin_cb;
    info->per_stripe_cb         = per_stripe_cb;
    info->total_cb              = total_cb;
    info->complete_cb           = complete_cb;

    info->user_arg              = user_arg;

    info->prev_times            = GLOBUS_NULL;
    info->cur_times             = GLOBUS_NULL;
    info->prev_bytes            = GLOBUS_NULL;
    info->cur_bytes             = GLOBUS_NULL;

    info->start_time            = 0;
    info->num_stripes           = 0;

    result = globus_ftp_client_perf_plugin_init(
        plugin,
        throughput_plugin_begin_cb,
        throughput_plugin_marker_cb,
        throughput_plugin_complete_cb,
        throughput_plugin_user_copy_cb,
        throughput_plugin_user_destroy_cb,
        info);

    if(result != GLOBUS_SUCCESS)
    {
        globus_free(info);

        return result;
    }

    return GLOBUS_SUCCESS;
}

/**
 * Destroy throughput plugin
 * @ingroup globus_ftp_client_throughput_plugin
 *
 * Frees up memory associated with plugin
 *
 * @param plugin
 *        plugin previously initialized with init (above)
 *
 * @return
 *        - GLOBUS_SUCCESS
 *        - Error on NULL plugin
 */

globus_result_t
globus_ftp_client_throughput_plugin_destroy(
    globus_ftp_client_plugin_t *                plugin)
{
    globus_result_t                             result;
    throughput_plugin_info_t *                  info;
    static char *                               myname =
        "globus_ftp_client_throughput_plugin_destroy";

    if(plugin == GLOBUS_NULL)
    {
        return globus_error_put(globus_error_construct_string(
                GLOBUS_FTP_CLIENT_MODULE,
                GLOBUS_NULL,
                "[%s] NULL plugin at %s\n",
                GLOBUS_FTP_CLIENT_MODULE->module_name,
                myname));
    }

    result = globus_ftp_client_perf_plugin_get_user_specific(
              plugin,
              (void **) &info);

    if(result != GLOBUS_SUCCESS)
    {
        return result;
    }

    if(info->prev_times)
    {
        globus_free(info->prev_times);
        globus_free(info->cur_times);
        globus_free(info->prev_bytes);
        globus_free(info->cur_bytes);
    }

    globus_free(info);

    return globus_ftp_client_perf_plugin_destroy(plugin);
}
