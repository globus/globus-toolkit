
enum
{
    GLOBUS_I_GASS_COPY_URL_SCHEME_UNSUPPORTED,
    GLOBUS_I_GASS_COPY_URL_SCHEME_FTP,
    GLOBUS_I_GASS_COPY_URL_SCHEME_HTTP,
    GLOBUS_I_GASS_COPY_URL_SCHEME_FILE,
} globus_i_gass_copy_url_scheme_t;


struct globus_i_gass_copy_target_s
{
    globus_i_gass_copy_target_mode_t		mode;
    char *					url;
    globus_gass_copy_attr_t			attr;
    globus_mutex_t                              mutex;
    globus_fifo_t                               queue;
    union
    {
	struct /* GLOBUS_I_GASS_COPY_TARGET_MODE_FTP */
	{
	    globus_ftp_handle *			handle;
	    int					n_channels;
	} ftp;
	
	struct /* GLOBUS_I_GASS_COPY_TARGET_MODE_GASS */
	{
	    globus_gass_transfer_request_t	request;
	} gass;
	
	struct /* GLOBUS_I_GASS_COPY_TARGET_MODE_IO */
	{
	    globus_io_handle *			handle;
	    globus_bool_t			free_handle;
	    globus_bool_t			seekable;
	} io;
    } data;
} globus_i_gass_copy_target_t;

enum
{
    GLOBUS_I_GASS_COPY_TARGET_MODE_FTP,
    GLOBUS_I_GASS_COPY_TARGET_MODE_GASS,
    GLOBUS_I_GASS_COPY_TARGET_MODE_IO,
} globus_i_gass_copy_target_mode_t;


typedef struct globus_i_gass_copy_state_s
{
    globus_gass_copy_handle_t *		handle;
    globus_i_gass_copy_state_target_t	source;
    globus_i_gass_copy_state_target_t	dest;
    globus_i_gass_copy_state_number_t	number;
    globus_i_gass_copy_monitor_t        monitor;
} globus_i_gass_copy_state_t;

enum
{
    GLOBUS_I_GASS_COPY_STATE_INITIAL,
} globus_i_gass_copy_state_number_t;

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
typedef struct
{
    globus_byte_t *                     bytes;
    globus_size_t                       nbytes;
    globus_size_t                       offset;
} globus_i_gass_copy_buffer_t;
#endif

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
typedef struct
{
    globus_mutex_t                      mutex;
    globus_cond_t                       cond;
    globus_object_t *                   err;
    globus_bool_t                       use_err;
    volatile globus_bool_t              done;
} globus_i_gass_copy_monitor_t;
#endif

