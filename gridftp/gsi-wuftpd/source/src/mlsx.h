#ifndef _MLSX_INCLUDE
#define _MLSX_INCLUDE

void 
mlsd(
    const char *                        path);

void 
mlst(
    const char *                        path);
    
void
mlsx_options(
    const char *                        options);

int
get_fact_string(
    char *                              ret_val,
    int                                 size,
    const char *                        path,
    const char *                        facts);
    
#endif
