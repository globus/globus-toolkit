/******************************************************************************
globus_handle_table.h
 
Description:
    This header defines a reference-counting handle table structure.
 
CVS Information:
 
    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/
#ifndef GLOBUS_INCLUDE_HANDLE_TABLE_H
#define GLOBUS_INCLUDE_HANDLE_TABLE_H

#include "globus_common.h"

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif
 
EXTERN_C_BEGIN

typedef int globus_handle_t;

enum { GLOBUS_HANDLE_TABLE_NO_HANDLE = 0 };

typedef struct
{
    globus_handle_t				last_handle;
    globus_hashtable_t				table;
    globus_mutex_t				lock;
} globus_handle_table_t;

void
globus_handle_table_init(
    globus_handle_table_t *			handle_table);

void
globus_handle_table_destroy(
    globus_handle_table_t *			handle_table);

globus_handle_t
globus_handle_table_insert(
    globus_handle_table_t *			handle_table,
    void *					value,
    int						initial_refs);

globus_bool_t
globus_handle_table_increment_reference(
    globus_handle_table_t *			handle_table,
    globus_handle_t				handle);

globus_bool_t
globus_handle_table_increment_reference_by(
    globus_handle_table_t *			handle_table,
    globus_handle_t				handle,
    unsigned int                                inc);

globus_bool_t
globus_handle_table_decrement_reference(
    globus_handle_table_t *			handle_table,
    globus_handle_t				handle);

void *
globus_handle_table_lookup(
    globus_handle_table_t *			handle_table,
    globus_handle_t				handle);

EXTERN_C_END

#endif /* GLOBUS_INCLUDE_HANDLE_TABLE_H */
