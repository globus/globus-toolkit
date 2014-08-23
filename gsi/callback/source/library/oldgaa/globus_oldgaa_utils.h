/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file globus_oldgaa-utils.h
 *
 * This header file used internally by the Globus-OLDGAA routines
 */

#ifndef GLOBUS_OLDGAA_UTILS_H
#define GLOBUS_OLDGAA_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

/**********************************************************************
                             Include header files
**********************************************************************/

#include <stdio.h> /* for FILE */

/**********************************************************************
                               Define constants
**********************************************************************/

#define GRID_CA_POLICY_FILENAME "ca-signing-policy.conf"

#define OLDGAA_X509_AUTHORITY        "X509"
 
#define POSITIVE_RIGHTS           "pos_rights"
#define NEGATIVE_RIGHTS           "neg_rights"

#define COND_PREFIX               "cond_"
#define PRINCIPAL_ACCESS_PREFIX   "access_"
#define PRINCIPAL_GRANTOR_PREFIX  "grantor_"
#define POS_RIGHTS_PREFIX         "pos"
#define NEG_RIGHTS_PREFIX         "neg"

#define COMMENT  			'#'
#define STRING_DELIMITER                '\''
#define ESCAPE_CHARACTER                '\\'
#define END_OF_LINE	         	'\n'

#define ERROR_WHILE_GETTING_DEFAULT_POLICY_LOCATION  100
#define ERROR_WHILE_RETRIEVING_POLICY  101

#define ERROR_WHILE_PARSING_PRINCIPALS 200
#define ERROR_WHILE_PARSING_CONDITIONS 201
#define ERROR_WHILE_PARSING_RIGHTS     202


/* Context information about our state reading the policy file */

typedef struct policy_file_context_struct  policy_file_context, 
                                          *policy_file_context_ptr;
struct policy_file_context_struct {
 char  *str;
 char  *parse_error;  
 char  *buf;
 long  buflen;
 long  index;
};

/**********************************************************************
 *
 * Function Prototypes
 *
 **********************************************************************/

/**********************************************************************
  OLDGAA Cleanup Functions 
 **********************************************************************/

oldgaa_error_code
oldgaa_globus_cleanup(oldgaa_sec_context_ptr *oldgaa_sc,
                   oldgaa_rights_ptr      *rights,
                   oldgaa_options_ptr      options,
                   oldgaa_answer_ptr      *answer,  
                   oldgaa_data_ptr         policy_db,
                   oldgaa_sec_attrb_ptr   *attributes);

/**********************************************************************
  OLDGAA Initialization Functions 
 **********************************************************************/

oldgaa_error_code
oldgaa_globus_initialize(oldgaa_sec_context_ptr       *oldgaa_sc,
                      oldgaa_rights_ptr            *rights,
                      oldgaa_options_ptr           *options,
                      oldgaa_data_ptr              *policy_db, 
                      char                      *subject, 
                      char                      *signer,
                      char                      *path);


oldgaa_sec_context_ptr
oldgaa_globus_allocate_sec_context(char *signer);

oldgaa_rights_ptr
oldgaa_globus_allocate_rights();

/**********************************************************************
  Policy Retrieving Functions 
 **********************************************************************/

oldgaa_policy_ptr
oldgaa_globus_policy_retrieve(uint32      *minor_status,
                           oldgaa_data_ptr object,
                           oldgaa_data_ptr policy_db, ...);

policy_file_context_ptr 
oldgaa_globus_policy_file_open(const char *filename);

void
oldgaa_globus_policy_file_close(policy_file_context_ptr  pcontext);


/**********************************************************************
  Policy Parsing Functions 
 **********************************************************************/

oldgaa_error_code  
oldgaa_globus_parse_policy (policy_file_context_ptr  pcontext,
                         oldgaa_policy_ptr          *policy_handle);

oldgaa_error_code
oldgaa_globus_parse_rights(policy_file_context_ptr  pcontext,
             char                    *tmp_str,
             oldgaa_rights_ptr          *start,
             int                     *cond_present,
             int                     *end_of_entry);

oldgaa_error_code
oldgaa_globus_parse_conditions( policy_file_context_ptr  pcontext,
                  oldgaa_conditions_ptr      *conditions,                  
                  char                    *tmp_str,
                  oldgaa_cond_bindings_ptr   *list, 
                  int                     *end_of_entry );

void
oldgaa_globus_print_rights(oldgaa_rights_ptr rights);


void
oldgaa_globus_print_attributes(oldgaa_sec_attrb_ptr attributes);


oldgaa_error_code
oldgaa_globus_get_trusted_ca_list(oldgaa_sec_attrb_ptr *attributes,
                               oldgaa_policy_ptr     policy_handle,
                               oldgaa_rights_ptr     rights);

#ifdef __cplusplus
}
#endif

#endif /* GLOBUS_OLDGAA_UTILS_H */
