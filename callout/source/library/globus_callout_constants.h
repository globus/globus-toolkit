#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_callout_constants.h
 * Globus Callout Infrastructure
 * @author Sam Meder
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#ifndef GLOBUS_CALLOUT_CONSTANTS_H
#define GLOBUS_CALLOUT_CONSTANTS_H

/**
 * @defgroup globus_callout_constants Globus Callout Constants
 */
/**
 * Globus Callout Error codes
 * @ingroup globus_callout_constants
 */
typedef enum
{
    GLOBUS_CALLOUT_ERROR_SUCCESS = 0,
    GLOBUS_CALLOUT_ERROR_WITH_HASHTABLE = 1,
    GLOBUS_CALLOUT_ERROR_OPENING_CONF_FILE = 2,
    GLOBUS_CALLOUT_ERROR_PARSING_CONF_FILE = 3,
    GLOBUS_CALLOUT_ERROR_WITH_DL = 4,
    GLOBUS_CALLOUT_ERROR_OUT_OF_MEMORY = 5,
    GLOBUS_CALLOUT_ERROR_TYPE_NOT_REGISTERED = 6,
    GLOBUS_CALLOUT_ERROR_LAST = 7
} globus_callout_error_t;

#endif /* GLOBUS_CALLOUT_CONSTANTS_H */
