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

typedef 
void 
(*globus_handle_destructor_t)(
    void *                              datum);

typedef struct
{
    struct globus_l_handle_entry_s **   table;
    int                                 next_slot;
    int                                 table_size;
    struct globus_l_handle_entry_s *    inactive;
    globus_handle_destructor_t          destructor;
} globus_handle_table_t;

#define GLOBUS_NULL_HANDLE 0
#define GLOBUS_HANDLE_TABLE_NO_HANDLE 0

int
globus_handle_table_init(
    globus_handle_table_t *             handle_table,
    globus_handle_destructor_t          destructor);

int
globus_handle_table_destroy(
    globus_handle_table_t *             handle_table);

globus_handle_t
globus_handle_table_insert(
    globus_handle_table_t *             handle_table,
    void *                              datum,
    int                                 initial_refs);

globus_bool_t
globus_handle_table_increment_reference(
    globus_handle_table_t *             handle_table,
    globus_handle_t                     handle);

globus_bool_t
globus_handle_table_increment_reference_by(
    globus_handle_table_t *             handle_table,
    globus_handle_t                     handle,
    unsigned int                        inc);

globus_bool_t
globus_handle_table_decrement_reference(
    globus_handle_table_t *             handle_table,
    globus_handle_t                     handle);

void *
globus_handle_table_lookup(
    globus_handle_table_t *             handle_table,
    globus_handle_t                     handle);

EXTERN_C_END

#endif /* GLOBUS_INCLUDE_HANDLE_TABLE_H */
