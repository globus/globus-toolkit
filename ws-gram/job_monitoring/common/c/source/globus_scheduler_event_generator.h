/**
 * Format and send an arbitrary event message to the JobSchedulerMonitor
 * implementation. This is used to implement the rest of the event signalling
 * API.
 *
 * @param format
 *     Format string using the same format as described in the printf
 *     manual page.
 * @param ...
 *     Varargs values used for type conversions in the format string.
 * @retval 0
 *    Message sent.
 */
int
globus_scheduler_event(
    const char * format,
    ...);

/**
 * Send a job pending event to the JobSchedulerMonitor implementation.
 *
 * @param timestamp
 *        Timestamp to use for the event. If set to 0, the time which
 *        this function was called is used.
 * @param jobid
 *        String indicating the scheduler-specific name of the job.
 * @retval 0
 *    Message sent.
 */
int
globus_scheduler_event_pending(
    time_t                              timestamp,
    const char *                        jobid);


/**
 * Send a job active event to the JobSchedulerMonitor implementation.
 *
 * @param timestamp
 *        Timestamp to use for the event. If set to 0, the time which
 *        this function was called is used.
 * @param jobid
 *        String indicating the scheduler-specific name of the job.
 * @retval 0
 *    Message sent.
 */
int
globus_scheduler_event_active(
    time_t                              timestamp,
    const char *                        jobid);

/**
 * Send a job failed event to the JobSchedulerMonitor implementation.
 *
 * @param timestamp
 *        Timestamp to use for the event. If set to 0, the time which
 *        this function was called is used.
 * @param jobid
 *        String indicating the scheduler-specific name of the job.
 * @param failure_code
 *        Failure code of the process if known.
 * @retval 0
 *    Message sent.
 */
int
globus_scheduler_event_failed(
    time_t                              timestamp,
    const char *                        jobid,
    int                                 failure_code);

/**
 * Send a job done event to the JobSchedulerMonitor implementation.
 *
 * @param timestamp
 *        Timestamp to use for the event. If set to 0, the time which
 *        this function was called is used.
 * @param jobid
 *        String indicating the scheduler-specific name of the job.
 * @param exit_code
 *        Exit code of the process if known.
 * @retval 0
 *    Message sent.
 */
int
globus_scheduler_event_done(
    time_t                              timestamp,
    const char *                        jobid,
    int                                 exit_code);
