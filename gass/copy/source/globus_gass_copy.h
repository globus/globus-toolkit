
typedef void (*globus_gass_copy_callback_t)(
    void * callback_arg,
    globus_gass_copy_handle_t * handle,
    globus_object_t * result);



typedef enum
{
    /** Don't change the TCP buffer/window size from the system default */
    GLOBUS_GSIFTP_CONTROL_TCPBUFFER_DEFAULT,

    /** Set the TCP buffer/window size to a fixed value */
    GLOBUS_GSIFTP_CONTROL_TCPBUFFER_FIXED,

    /** Automatically set the TCP buffer/window size */
    GLOBUS_GSIFTP_CONTROL_TCPBUFFER_AUTOMATIC
} globus_gsiftp_control_tcpbuffer_mode_t;
    
typedef struct globus_gsiftp_control_tcpbuffer_s
{
    globus_gsiftp_control_tcpbuffer_mode_t mode;
    union
    {
	/*
	 * No data required for:
	 *     GLOBUS_GSIFTP_CONTROL_TCPBUFFER_DEFAULT
	 */
	struct /* GLOBUS_GSIFTP_CONTROL_TCPBUFFER_FIXED */
	{
	    unsigned long size;
	} fixed;
	struct /* GLOBUS_GSIFTP_CONTROL_TCPBUFFER_AUTOMATIC */
	{
	    unsigned long initial_size;
	    unsigned long minimum_size;
	    unsigned long maximum_size;
	} automatic;
    } data;
} globus_gsiftp_control_tcpbuffer_t;



typedef enum {
    /** No parallelism */
    GLOBUS_GSIFTP_CONTROL_PARALLELISM_NONE,

    /** Partitioned parallelism */
    GLOBUS_GSIFTP_CONTROL_PARALLELISM_FIXED,

    /** Blocked parallelism with round-robin */
    GLOBUS_GSIFTP_CONTROL_PARALLELISM_AUTOMATIC,
} globus_gsiftp_control_parallelism_mode_t;
    
typedef struct globus_gsiftp_control_parallelism_s
{
    globus_gsiftp_control_parallelism_mode_t mode;
    union
    {
	/*
	 * No data required for:
	 *     GLOBUS_GSIFTP_CONTROL_PARALLELISM_NONE
	 */
	struct /* GLOBUS_GSIFTP_CONTROL_PARALLELISM_FIXED */
	{
	    unsigned long size;
	} fixed;
	struct /* GLOBUS_GSIFTP_CONTROL_PARALLELIS_AUTOMATIC */
	{
	    unsigned long initial_size;
	    unsigned long minimum_size;
	    unsigned long maximum_size;
	} automatic;
    } data;
} globus_gsiftp_control_parallelism_t;



typedef enum
{
    /** No striping */
    GLOBUS_GSIFTP_CONTROL_STRIPING_NONE,

    /** Partitioned striping */
    GLOBUS_GSIFTP_CONTROL_STRIPING_PARTITIONED,

    /** Blocked striping with round-robin */
    GLOBUS_GSIFTP_CONTROL_STRIPING_BLOCKED_ROUND_ROBIN,
} globus_gsiftp_control_striping_mode_t;
    
typedef struct globus_gsiftp_control_striping_s
{
    globus_gsiftp_control_striping_mode_t mode;
    union
    {
	/*
	 * No data required for:
	 *     GLOBUS_GSIFTP_CONTROL_STRIPING_NONE
	 *     GLOBUS_GSIFTP_CONTROL_STRIPING_PARTITIONED
	 */
	struct /* GLOBUS_GSIFTP_CONTROL_STRIPING_BLOCKED_ROUND_ROBIN */
	{
	    unsigned long long block_size;
	} blocked_round_robin;
    } data;
} globus_gsiftp_control_striping_t;




