#ifndef GLOBUS_I_RVF_H
#define GLOBUS_I_RVF_H
#include "globus_common.h"

EXTERN_C_BEGIN

typedef struct
{
    int aspect;
    char *string_value;
    int when_value;
    globus_bool_t bool_value;
}
globus_i_rvf_aspect_t;

EXTERN_C_END
#endif /* GLOBUS_I_RVF_H */
