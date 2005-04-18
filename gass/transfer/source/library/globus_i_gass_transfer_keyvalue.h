/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

/******************************************************************************
globus_gass_transfer_keyvalue.h
 
Description:
    This header implements a keyvalue list
 
CVS Information:
 
    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/
#ifndef GLOBUS_GASS_INCLUDE_GLOBUS_GASS_TRANSFER_KEYVALUE_H
#define GLOBUS_GASS_INCLUDE_GLOBUS_GASS_TRANSFER_KEYVALUE_H

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

#include "globus_list.h"

EXTERN_C_BEGIN

typedef struct
{
    char *					key;
    char *					value;
} globus_gass_transfer_keyvalue_t;

char *
globus_i_gass_transfer_keyvalue_lookup(
    globus_list_t **				list,
    char *					key);

void
globus_i_gass_transfer_keyvalue_insert(
    globus_list_t **				list,
    char *					key,
    char *					value);

void
globus_i_gass_transfer_keyvalue_replace(
    globus_list_t **				list,
    char *					key,
    char *					value);

void
globus_i_gass_transfer_keyvalue_destroy(
    globus_list_t **				list);

EXTERN_C_END

#endif /* GLOBUS_GASS_INCLUDE_GLOBUS_GASS_TRANSFER_KEYVALUE_H */
