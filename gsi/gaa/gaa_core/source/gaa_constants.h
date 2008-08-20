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

#ifndef _GAA_CONSTANTS_H
#define _GAA_CONSTANTS_H

/*************************** GAA-API constants **************************/

#ifdef  TRUE
#undef  TRUE
#endif
#define TRUE   1

#ifdef  FALSE
#undef  FALSE
#endif
#define FALSE  0   

#define GAA_SSHIFT 16
#define GAA_SMASK 0xffff
#define GAA_STATUS(maj,minor) (((maj) & GAA_SMASK) | (((minor) & GAA_SMASK) << GAA_SSHIFT))
#define GAA_MAJSTAT(status)  ((status) & GAA_SMASK)
#define GAA_MINSTAT(status)  (((status) >> GAA_SSHIFT) & GAA_SMASK)
/********************** GAA-API  major status codes ***********************/

#define GAA_S_SUCCESS                      0
#define GAA_C_YES                          0
#define GAA_C_NO                           1
#define GAA_C_MAYBE                        2
#define GAA_S_FAILURE                      3
#define GAA_S_INVALID_STRING_DATA_HNDL     4
#define GAA_S_INVALID_LIST_HNDL            5
#define GAA_S_INVALID_GAA_HNDL             6
#define GAA_S_INVALID_POLICY_ENTRY_HNDL    7
#define GAA_S_INVALID_POLICY_HNDL          8
#define GAA_S_INVALID_SC_HNDL              9
#define GAA_S_INVALID_ANSWER_HNDL         10
#define GAA_S_INVALID_REQUEST_RIGHT_HNDL  11
#define GAA_S_INVALID_POLICY_RIGHT_HNDL   12
#define GAA_S_INVALID_CONDITION_HNDL      13
#define GAA_S_INVALID_OPTIONS_HNDL        14
#define GAA_S_INVALID_IDENTITY_INFO_HNDL  15
#define GAA_S_INVALID_AUTHR_INFO_HNDL     16
#define GAA_S_INVALID_PRINCIPAL_HNDL      17
#define GAA_S_INVALID_ATTRIBUTE_HNDL      18
#define GAA_S_UNIMPLEMENTED_FUNCTION      19
#define GAA_S_NO_MATCHING_ENTRIES         20
#define GAA_S_POLICY_PARSING_FAILURE      21
#define GAA_S_POLICY_RETRIEVING_FAILURE   22
#define GAA_S_INVALID_ARG                 23
#define GAA_S_UNKNOWN_CRED_TYPE           24
#define GAA_S_UNKNOWN_MECHANISM           25
#define GAA_S_NO_CRED_PULL_CALLBACK       26
#define GAA_S_NO_AUTHINFO_CALLBACK        27
#define GAA_S_NO_NEWVAL_CALLBACK          28
#define GAA_S_NO_GETPOLICY_CALLBACK       29
#define GAA_S_NO_MATCHRIGHTS_CALLBACK     30
#define GAA_S_INVALID_IDENTITY_CRED       31
#define GAA_S_BAD_CALLBACK_RETURN         32
#define GAA_S_INTERNAL_ERR                33
#define GAA_S_SYSTEM_ERR                  34
#define GAA_S_CRED_PULL_FAILURE           35
#define GAA_S_CRED_EVAL_FAILURE           36
#define GAA_S_CRED_VERIFY_FAILURE         37
#define GAA_S_CONFIG_ERR                  38

/***************************** GAA-API flags *****************************/
/*
Each condition is marked as evaluated or not evaluated, if evaluated 
marked as met, not met or further evaluation or enforcement is required.
This tells application which policies must be enforced.
*/

#define	GAA_COND_FLG_EVALUATED    0x01  /* condition has been evaluated */
#define	GAA_COND_FLG_MET	  0x10  /* condition has been met       */
#define	GAA_COND_FLG_ENFORCE      0x100 /* condition has to be enforced */
               
#endif /* _GAA_CONSTANTS_H */

