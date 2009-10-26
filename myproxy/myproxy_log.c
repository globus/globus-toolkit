/*
 * myproxy_log.c
 *
 * See myproxy_log.h for documentation.
 */

#include "myproxy_common.h"	/* all needed headers included here */

/**********************************************************************
 *
 * Internal Variables
 *
 */

struct myproxy_log_context 
{
    int syslog_facility;
    char *syslog_name;
    int debug_level;
    FILE *log_stream;
};

static struct myproxy_log_context my_context = 
{
    0,
    NULL,
    0,
    NULL
};



/**********************************************************************
 *
 * Internal Functions
 *
 */

/*
 * do_log()
 *
 * Do the actual logging of the given string.
 */
static void
do_log(const char *string, int level)
{
    /*
     * We always want to use '"%s", string' when logging in case
     * string itself contains a '%s'.
     */
    if (my_context.syslog_facility != 0) 
    {
	syslog(my_context.syslog_facility|level, "%s", string);
    }
    
    if (my_context.log_stream != NULL)
    {
	fprintf(my_context.log_stream, "%s\n", string);
    }
	       
    return;
}

/* syslog() messages should be on a single line */
static void
strip_newlines(char *string)
{
    int i, len;

    for (i=0, len = strlen(string); i < len; i++) {
        if (string[i] == '\n') {
            string[i] = ' ';
        }
    }
}

/**********************************************************************
 *
 * API Functions
 *
 */

void
myproxy_log_use_syslog(const int facility,
		       const char *name)
{
    my_context.syslog_facility = facility;
    if (my_context.syslog_name != NULL) {
        free(my_context.syslog_name);  /* Mem allocated by strdup */
    }
    my_context.syslog_name = (name == NULL) ? NULL : strdup(name);
    openlog(my_context.syslog_name,LOG_PID,my_context.syslog_facility);
}

void
myproxy_log_use_stream(FILE *stream)
{
    my_context.log_stream = stream;
}


void
myproxy_log(const char *format, ...)
{
    char *string = NULL;
    va_list ap;

    va_start(ap, format);
    
    string = my_vsnprintf(format, ap);
    
    va_end(ap);
    
    if (string == NULL)
    {
	/* Punt */
	goto error;
    }
    
    strip_newlines(string);
    do_log(string, LOG_NOTICE);
    
  error:
    if (string != NULL)
    {
	free(string);
    }
    
    return;
}

void
myproxy_log_verror()
{
    char *string;
    
    string = verror_get_string();
    
    if (string != NULL)
    {
        strip_newlines(string);
        do_log(string, LOG_ERR);
    }

    if (verror_get_errno() != 0)
    {
	do_log(verror_strerror(), LOG_ERR);
    }

    return;
}

void
myproxy_log_perror(const char *format, ...)
{
    char *string = NULL;
    va_list ap;
    
    va_start(ap, format);
    
    string = my_vsnprintf(format, ap);
    
    va_end(ap);
    
    if (string == NULL)
    {
	/* Punt */
	goto error;
    }
    
    strip_newlines(string);
    do_log(string, LOG_ERR);
    do_log(strerror(errno), LOG_ERR);
    
  error:
    if (string != NULL)
    {
	free(string);
    }
    
    return;
}

void
myproxy_log_close()
{
    my_context.syslog_facility = 0;
    
    if (my_context.syslog_name != NULL)
    {
	free(my_context.syslog_name);
	my_context.syslog_name = NULL;
    }
    
    my_context.debug_level = 0;
    
    my_context.log_stream = NULL;
}


int
myproxy_debug_set_level(int level)
{
    int old_level = my_context.debug_level;

    my_context.debug_level = level;

    return old_level;
}


void
myproxy_debug(const char *format, ...)
{
    char *string = NULL;
    va_list ap;

    if (my_context.debug_level == 0)
    {
	return;
    }
	
    va_start(ap, format);
    
    string = my_vsnprintf(format, ap);
    
    va_end(ap);
    
    if (string == NULL)
    {
	/* Punt */
	goto error;
    }
    
    strip_newlines(string);
    do_log(string, LOG_NOTICE);
    
  error:
    if (string != NULL)
    {
	free(string);
    }
    
    return;
}
