/**********************************************************************
 globus_gaa-utils.h:

Description:
	This header file used internally by theGlobus-GAA routines
**********************************************************************/

#ifndef _GLOBUS_GAA_UTILS_H
#define _GLOBUS_GAA_UTILS_H

#ifndef EXTERN_C_BEGIN
#    ifdef __cplusplus
#        define EXTERN_C_BEGIN extern "C" {
#        define EXTERN_C_END }
#    else
#        define EXTERN_C_BEGIN
#        define EXTERN_C_END
#    endif
#endif

EXTERN_C_BEGIN


/**********************************************************************
                             Include header files
**********************************************************************/

#include <stdio.h> /* for FILE */

/**********************************************************************
                               Define constants
**********************************************************************/

#define GRID_CA_POLICY_FILENAME "ca-signing-policy.conf"

#define GAA_X509_AUTHORITY        "X509"
 
#define POSITIVE_RIGHTS           "pos_rights"
#define NEGATIVE_RIGHTS           "neg_rights"

#define COND_PREFIX               "cond_"
#define PRINCIPAL_ACCESS_PREFIX   "access_"
#define PRINCIPAL_GRANTOR_PREFIX  "grantor_"
#define POS_RIGHTS_PREFIX         "pos"
#define NEG_RIGHTS_PREFIX         "neg"

#define COMMENT  			'#'
#define STRING_DELIMITER                '\''
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
 FILE  *stream;	     
 char  *str;
 char  *parse_error;  
};

/**********************************************************************
 *
 * Function Prototypes
 *
 **********************************************************************/

/**********************************************************************
  GAA Cleanup Functions 
 **********************************************************************/

gaa_error_code
gaa_globus_cleanup(gaa_sec_context_ptr *gaa_sc,
                   gaa_rights_ptr      *rights,
                   gaa_options_ptr      options,
                   gaa_answer_ptr      *answer,  
                   gaa_data_ptr         policy_db,
                   gaa_sec_attrb_ptr   *attributes);

/**********************************************************************
  GAA Initialization Functions 
 **********************************************************************/

gaa_error_code
gaa_globus_initialize(gaa_sec_context_ptr       *gaa_sc,
                      gaa_rights_ptr            *rights,
                      gaa_options_ptr           *options,
                      gaa_data_ptr              *policy_db, 
                      char                      *subject, 
                      char                      *signer,
                      char                      *path);


gaa_sec_context_ptr
gaa_globus_allocate_sec_context(char *signer);

gaa_rights_ptr
gaa_globus_allocate_rights();

/**********************************************************************
  Policy Retrieving Functions 
 **********************************************************************/

gaa_policy_ptr
gaa_globus_policy_retrieve(uint32      *minor_status,
                           gaa_data_ptr object,
                           gaa_data_ptr policy_db, ...);
static
int
get_default_policy_file(gaa_data_ptr policy_db);

policy_file_context_ptr 
gaa_globus_policy_file_open(const char *filename);

void
gaa_globus_policy_file_close(policy_file_context_ptr  pcontext);


/**********************************************************************
  Policy Parsing Functions 
 **********************************************************************/

static
int
gaa_globus_help_read_string(policy_file_context_ptr  pcontext, 
                 char                    *str, 
                 const char              *message);
static
int
gaa_globus_read_string (policy_file_context_ptr  pcontext,
                        char                    *str,
                        char                    **errstring);
static
int
gaa_globus_get_string_with_whitespaces(policy_file_context_ptr  pcontext,
                            char                    *str);
static
int
gaa_globus_omit_comment_line(policy_file_context_ptr  pcontext);



gaa_error_code  
gaa_globus_parse_policy (policy_file_context_ptr  pcontext,
                         gaa_policy_ptr          *policy_handle);

gaa_error_code
gaa_globus_parse_principals(policy_file_context_ptr  pcontext,
                 gaa_policy_ptr          *policy,
                 char                    *tmp_str,
                 gaa_principals_ptr      *start);

gaa_error_code
gaa_globus_parse_rights(policy_file_context_ptr  pcontext,
             char                    *tmp_str,
             gaa_rights_ptr          *start,
             int                     *cond_present,
             int                     *end_of_entry);

gaa_error_code
gaa_globus_parse_conditions( policy_file_context_ptr  pcontext,
                  gaa_conditions_ptr      *conditions,                  
                  char                    *tmp_str,
                  gaa_cond_bindings_ptr   *list, 
                  int                     *end_of_entry );

void
gaa_globus_print_rights(gaa_rights_ptr rights);


void
gaa_globus_print_attributes(gaa_sec_attrb_ptr attributes);


gaa_error_code
gaa_globus_get_trusted_ca_list(gaa_sec_attrb_ptr *attributes,
                               gaa_policy_ptr     policy_handle,
                               gaa_rights_ptr     rights);

EXTERN_C_END

#endif /* _GLOBUS_GAA_UTILS_H */
