#include "gram_client.h"

static char *
graml_error_strings[] =
{
    "Success",
    "GRAM_ERROR_PARAMETER_NOT_SUPPORTED",
    "GRAM_ERROR_INVALID_REQUEST",
    "GRAM_ERROR_NO_RESOURCES",
    "GRAM_ERROR_BAD_DIRECTORY",
    "GRAM_ERROR_BAD_EXECUTABLE",
    "GRAM_ERROR_INSUFFICIENT_FUNDS",
    "GRAM_ERROR_AUTHORIZATION",
    "GRAM_ERROR_USER_CANCELLED",
    "GRAM_ERROR_SYSTEM_CANCELLED",
    "GRAM_ERROR_PROTOCOL_FAILED",
    "GRAM_ERROR_STDIN_NOTFOUND",
    "GRAM_ERROR_CONNECTION_FAILED",
    "GRAM_ERROR_INVALID_MAXTIME",
    "GRAM_ERROR_INVALID_COUNT",
    "GRAM_ERROR_NULL_SPECIFICATION_TREE",
    "GRAM_ERROR_JM_FAILED_ALLOW_ATTACH",
    "GRAM_ERROR_JOB_EXECUTION_FAILED",
    "GRAM_ERROR_INVALID_PARADYN"
};

const char *
gram_error_string(int error_code)
{
    if (error_code < 0 || error_code >= GRAM_ERROR_LAST)
        return("Invalid error code");
    return(graml_error_strings[error_code]);
}
