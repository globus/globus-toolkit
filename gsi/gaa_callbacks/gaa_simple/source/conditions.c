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

#include "gaa.h"
#include "gaa_simple.h"
#include "gaa_util.h"
#ifndef WIN32
#include <strings.h>
#endif
#include <string.h>
#include <stdio.h>
#ifndef WIN32
#include <unistd.h>
#include <sys/stat.h>
#else
#include "globus_common.h" /* For POSIX struct stat support, strcasecmp() */
#  ifndef W_OK
#    define W_OK	2
#  endif
#  ifndef R_OK
#    define R_OK	4
#  endif

#endif
#include <errno.h>

/** @defgroup gaa_simple_conditions_static "gaa simple conditions.c static routines"
 */

const gaa_cred_type		gaa_identity = GAA_IDENTITY;
const gaa_cred_type		gaa_group_memb = GAA_GROUP_MEMB;
const gaa_cred_type		gaa_group_non_memb = GAA_GROUP_NON_MEMB;

const int trivial_yes = (GAA_COND_FLG_EVALUATED|GAA_COND_FLG_MET);
const int trivial_no = (GAA_COND_FLG_EVALUATED);
const int trivial_maybe = 0;

static gaa_status
gaa_simple_l_check_id_cond(gaa_ptr		gaa,
			  gaa_sc_ptr		sc,
			  gaa_condition *	cond,
			  gaa_time_period *	valid_time,
			  gaa_list_ptr		req_options,
			  gaa_status *   	output_flags,
			  void *		params,
			  int			matchcase);


/** gaa_simple_check_id_cond()
 *
 * @ingroup gaa_simple
 *
 * Checks an identity condition.  Finds any credentials in the security
 * context with the same principal name and credential type, then calls
 * their cred_verify callbacks and checks any associated conditions.
 * This function is intended to be used as a gaa cond_eval callback
 * function.
 *
 * @param gaa
 *        input gaa pointer
 * @param sc
 *        input security context
 * @param cond
 *        input/output condition to check.
 * @param valid_time
 *        output valid time period
 * @param req_options
 *        input request options (passed on to any condition-evaluation
 *        callbacks used by credential conditions)
 * @param output_flags
 *        output status pointer.  On success, *output_flags will be set to
 *        the appropriate combination of GAA_COND_FLG_EVALUATED,
 *        GAA_COND_FLG_MET, GAA_COND_FLG_ENFORCE.
 * @param params
 *        input, should be a (gaa_cred_type *) pointer to a credential
 *        type (identity, group, etc.).
 *
 * @retval GAA_S_SUCCESS
 *         success
 * @retval standard gaa error returns
 */
gaa_status
gaa_simple_check_id_cond(gaa_ptr		gaa,
			gaa_sc_ptr	sc,
			gaa_condition *	cond,
			gaa_time_period *valid_time,
			gaa_list_ptr	req_options,
			gaa_status *    output_flags,
			void *		params)
{
    return(gaa_simple_l_check_id_cond(gaa, sc, cond, valid_time,
				    req_options, output_flags, params, 1));
}

/** gaa_simple_check_id_cond_nocase()
 *
 * @ingroup gaa_simple
 *
 * Case-insensitive version of gaa_simple_check_id_cond().
 * Checks an identity condition.  Finds any credentials in the security
 * context with the same principal name and credential type, then calls
 * their cred_verify callbacks and checks any associated conditions.
 * This function is intended to be used as a gaa cond_eval callback
 * function.
 *
 * @param gaa
 *        input gaa pointer
 * @param sc
 *        input security context
 * @param cond
 *        input/output condition to check.
 * @param valid_time
 *        output valid time period
 * @param req_options
 *        input request options (passed on to any condition-evaluation
 *        callbacks used by credential conditions)
 * @param output_flags
 *        output status pointer.  On success, *output_flags will be set to
 *        the appropriate combination of GAA_COND_FLG_EVALUATED,
 *        GAA_COND_FLG_MET, GAA_COND_FLG_ENFORCE.
 * @param params
 *        input, should be a (gaa_cred_type *) pointer to a credential
 *        type (identity, group, etc.).
 *
 * @retval GAA_S_SUCCESS
 *         success
 * @retval standard gaa error returns
 */
gaa_status
gaa_simple_check_id_cond_nocase(gaa_ptr		gaa,
			       gaa_sc_ptr 	sc,
			       gaa_condition *	cond,
			       gaa_time_period *valid_time,
			       gaa_list_ptr	req_options,
			       gaa_status *	output_flags,
			       void *		params)
{
    return(gaa_simple_l_check_id_cond(gaa, sc, cond, valid_time,
				    req_options, output_flags, params, 0));
}

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_simple_l_check_id_cond()
 *
 * @ingroup gaa_simple_conditions_static
 *
 * Does the work of gaa_simple_check_id_cond() and
 * gaa_simple_check_id_cond_nocase().
 * Checks an identity condition.  Finds any credentials in the security
 * context with the same principal name and credential type, then calls
 * their cred_verify callbacks and checks any associated conditions.
 * This function is intended to be used as a gaa cond_eval callback
 * function.
 *
 * @param gaa
 *        input gaa pointer
 * @param sc
 *        input security context
 * @param cond
 *        input/output condition to check.
 * @param valid_time
 *        output valid time period
 * @param req_options
 *        input request options (passed on to any condition-evaluation
 *        callbacks used by credential conditions)
 * @param output_flags
 *        output status pointer.  On success, *output_flags will be set to
 *        the appropriate combination of GAA_COND_FLG_EVALUATED,
 *        GAA_COND_FLG_MET, GAA_COND_FLG_ENFORCE.
 * @param params
 *        input, should be a (gaa_cred_type *) pointer to a credential
 *        type (identity, group, etc.).
 * @param matchcase
 *        input, 0 for case-insensitive matches, nonzero for case-sensitive
 *
 * @retval GAA_S_SUCCESS
 *         success
 * @retval standard gaa error returns
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */

static gaa_status
gaa_simple_l_check_id_cond(gaa_ptr		gaa,
			  gaa_sc_ptr		sc,
			  gaa_condition *	cond,
			  gaa_time_period *	valid_time,
			  gaa_list_ptr		req_options,
			  gaa_status *          output_flags,
			  void *		params,
			  int			matchcase)
{
    gaa_status				status;
    gaa_list_ptr			credlist;
    gaa_list_entry_ptr			ent;
    gaa_cred *				cred;
    gaa_cred *				idcred;
    int					(*cfunc)(const char *, const char *);
    gaa_condition *			idcond;
    gaa_time_period			vtp;
    gaa_time_period			cred_vtp;
    gaa_cred_type *			idtype;
    int 				thisflag;
    int 				on_no = GAA_COND_FLG_EVALUATED;

    if ((idtype = (gaa_cred_type *)params) == 0)
    {
	gaa_set_callback_err("gaa_simple_check_id_cond: null params");
	return(GAA_STATUS(GAA_S_FAILURE, 0));
    }
    if (*idtype != GAA_IDENTITY &&
	*idtype != GAA_GROUP_MEMB &&
	*idtype != GAA_GROUP_NON_MEMB)
    {
	gaa_set_callback_err("gaa_simple_check_id_cond: bad cred type");
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if (matchcase)
	cfunc = strcmp;
    else
	cfunc = strcasecmp;

    if (cond->authority == 0)
    {
	if (cond->value == 0)
	{
            /* Match anyone, with or without credentials */
	    *output_flags = (GAA_COND_FLG_EVALUATED | GAA_COND_FLG_MET);
	    return(GAA_S_SUCCESS);
	}
	else
	    return(GAA_STATUS(GAA_S_INVALID_CONDITION_HNDL, 0));
    }

    if (valid_time)
	valid_time->start_time = valid_time->end_time = 0;

    if ((status = gaa_pull_creds(gaa, sc, *idtype, 0)) != GAA_S_SUCCESS)
	return(status);
    if ((status = gaa_getcreds(gaa, sc, &credlist, *idtype)) != GAA_S_SUCCESS)
	return(status);
    *output_flags = GAA_COND_FLG_EVALUATED;
    for (ent = gaa_list_first(credlist); ent; ent = gaa_list_next(ent))
	if (idcred = (gaa_cred *)gaa_list_entry_value(ent))
	{
	    if (idcred->principal && (idcred->type == *idtype) &&
		(idcred->principal->type == *idtype) &&
		idcred->principal->authority &&
		((cond->authority == 0) ||
		 (cfunc(idcred->principal->authority, cond->authority) == 0)) &&
		((cond->value == 0) ||
		 (idcred->principal->value &&
		  (cfunc(idcred->principal->value, cond->value) == 0))))
	    {
		if (gaa_verify_cred(idcred) != GAA_S_SUCCESS)
		    continue;
		/*
		 * Found a matching credential, and verified the raw cred
		 * is still valid.  Answer YES if there are no conditions,
		 * or if all conditions are met.  Otherwise, keep looking
		 * for another match.
		 */
		    
		thisflag = (GAA_COND_FLG_EVALUATED | GAA_COND_FLG_MET);
		cred_vtp.start_time = cred_vtp.end_time = 0;
		if (idcred->info.id_info)
		    for (ent =
			     gaa_list_first(idcred->info.id_info->conditions);
			 ent; ent = gaa_list_next(ent))
		    {
			if (idcond = (gaa_condition *)gaa_list_entry_value(ent))
			{
			    if ((status =
				 gaa_check_condition(gaa, sc,
						     idcond, &vtp,
						     0,
						     req_options)) != GAA_S_SUCCESS)
				return(status);
			    else
				thisflag &= idcond->status;
			    if (vtp.start_time > cred_vtp.start_time)
				cred_vtp.start_time = vtp.start_time;
			    if ((vtp.end_time &&
				 (vtp.end_time < cred_vtp.end_time)) ||
				(cred_vtp.end_time == 0))
				cred_vtp.end_time = vtp.end_time;
			}
		    }
		if (thisflag & (GAA_COND_FLG_EVALUATED | GAA_COND_FLG_MET))
		{
		    /*
		     * The answer is "yes" for all conditions for this
		     * credential.  We're done.
		     */
		    *output_flags = thisflag;
		    if (valid_time)
		    {
			valid_time->start_time = cred_vtp.start_time;
			valid_time->end_time = cred_vtp.end_time;
		    }
		    break;
		}
		else if (thisflag & GAA_COND_FLG_EVALUATED)
		{
		    /*
		     * The current answer is "no".  Set the condition
		     * status to "on_no" (which will be "maybe", if a
		     * previous credential's conditions evaluated to
		     * "maybe", and "no" otherwise).  Then continue
		     * looking through other credentials.
		     */
		    *output_flags = on_no;
		}
		else
		{
		    /*
		     * The current answer is "maybe".  Set the condition
		     * status to the current answer, and save this status
		     * to use if a later credential evaluates to "no".
		     */
		    on_no = thisflag;
		    *output_flags = thisflag;
		}
	    }
	}
    return(GAA_S_SUCCESS);
}


/** gaa_simple_check_group_cond()
 *
 * @ingroup gaa_simple
 *
 * Checks a group condition.  Reads group entries from a file, and
 * checks to see whether any of the credentials in the security context
 * match the entries in the file.  If so, evaluates those identity
 * conditions recursively.
 *
 * @param gaa
 *        input gaa pointer
 * @param sc
 *        input security context
 * @param cond
 *        input condition to check
 * @param valid_time
 *        output valid time period
 * @param req_options
 *        input request options (passed on to any condition-evaluation
 *        callbacks used by credential conditions)
 * @param output_flags
 *        output status pointer.  On success, *output_flags will be set to
 *        the appropriate combination of GAA_COND_FLG_EVALUATED,
 *        GAA_COND_FLG_MET, GAA_COND_FLG_ENFORCE.
 * @param params
 *        input, should be a (char **) pointer to the name of the
 *        directory in which group files are kept.
 *
 * @retval GAA_S_YES
 *         meets the identity condition
 * @retval GAA_S_NO
 *         doesn't meet the identity condition
 * @retval standard gaa error returns
 */

gaa_status
gaa_simple_check_group_cond(gaa_ptr gaa, gaa_sc_ptr sc, gaa_condition *cond, gaa_time_period *valid_time, gaa_list_ptr req_options, gaa_status *output_flags, void *params)
{
    char *dirname;
    FILE *groupfile = 0;
    char buf[2048];
    char *auth = 0;
    char *next = 0;
    char *value = 0;
    gaa_condition *subcond = 0;
    gaa_status status = GAA_S_SUCCESS;
    int uneval = 0;		/* if nonzero, there was at least one
				 * unevaluated identity condition. */

    if (params == 0)
	return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));
    if ((dirname = *(char **)params) == 0)
	return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));
    if (cond == 0 || cond->authority == 0 || cond->value == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    if ((strlen(dirname) + strlen(cond->value) + 2) >= sizeof(buf))
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    sprintf(buf, "%s/%s", dirname, cond->value);
    if ((groupfile = fopen(buf, "r")) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    while (fgets(buf, sizeof(buf), groupfile)) {
	if (auth = gaautil_gettok(buf, &next))
	    value = gaautil_gettok(next, &next);
	if (auth && (*auth != '#')) {
	    if ((status = gaa_new_condition(&subcond, "cond_access_id", auth,
					    value)) != GAA_S_SUCCESS)
		break;
	    if ((status = gaa_check_condition(gaa, sc, subcond, valid_time,
					      0,
					      req_options)) != GAA_S_SUCCESS)
		break;
	    if (! (subcond->status & GAA_COND_FLG_EVALUATED))
		uneval = 1;
	    else if (subcond->status & GAA_COND_FLG_MET)
	    {
		*output_flags = subcond->status;
		break;
	    }
	}
    }

    if (! uneval)
	*output_flags |= GAA_COND_FLG_EVALUATED;
    fclose(groupfile);
    gaa_free_condition(subcond);
    return(status);
}

gaa_status
gaa_simple_check_trivial_cond(gaa_ptr		gaa,
			     gaa_sc_ptr		sc,
			     gaa_condition *	cond,
			     gaa_time_period *  valid_time,
			     gaa_list_ptr	req_options,
			     gaa_status *	output_flags,
			     void *		params)
{
    int *result_ptr = (int *)params;

    if (result_ptr == 0)
    {
	gaa_set_callback_err("gaa_simple_check_trivial_cond: don't know what answer you want");
	return(GAA_S_CONFIG_ERR);
    }
    *output_flags = *result_ptr;
    return(GAA_S_SUCCESS);
}

/* gaa_simple_check_local_access
 * 
 * Checks if the user has permissions to perform the requested action 
 * (in the condition) on the object (in the options). It maps the possible
 * requested actions (read, write, create, lookup, delete) to one of
 * the Unix file permissions (read, write, execute). 
 * 
 * @param   gaa
 *          Input gaa handle
 * @param   sc
 *          input gaa security context
 * @param   cond
 *          input condition to evaluate
 *          (authority is "file" and 
 *           value is one of "read" , "write","create", "delete", "lookup"
 * @param   valid_time
 *          output validity time (not filled in)
 * @param   req_options
 *          input options to evaluate condition
 *          (contains the filename for which access is requested)
 * @param   output_flags
 *          output flag indicating whether condition was met
 * @param   params
 *          callback-specific parameter (none for this callback)
 *
 * @retval  GAA_S_SUCCESS
 *          success
 * @retval  GAA_S_INVALID_ARG
 *          one of the input values was incorrect 
 * @retval  GAA_S_SYSTEM_ERR
 *          memory allocation error
 */

gaa_status
gaa_simple_check_local_access (gaa_ptr		gaa,
			     gaa_sc_ptr		sc,
			     gaa_condition *	cond,
			     gaa_time_period *  valid_time,
			     gaa_list_ptr	req_options,
			     gaa_status *	output_flags,
			     void *		params)
{
    gaa_list_entry_ptr          ent = NULL;
    gaa_request_option       *  opt = NULL;
    int i = 0;    
    int mode;
    int found = 0;
    char *filename;
    
    *output_flags = GAA_COND_FLG_EVALUATED;
#ifdef DEBUG
    fprintf(stderr,"Inside gaa_simple_check_local_access\n");
    fprintf(stderr,"COND: Type = %s\n",cond->type);
    fprintf(stderr,"COND: Authority = %s\n",cond->authority);
    fprintf(stderr,"COND: value = %s\n",cond->value);
#endif    
    if( gaa == 0 || sc == 0) 
	    return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    if (cond == 0 || cond->authority == 0 || cond->value == 0 || req_options == 0 )
	    return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    
    
    for (i = 0 ,ent = gaa_list_first(req_options); ent; 
       ent = gaa_list_next(ent), i++)
    {
        opt = (gaa_request_option *)gaa_list_entry_value(ent);
    
#ifdef DEBUG
        fprintf(stderr,"i=%i\n",i);
        fprintf(stderr,"OPT: Type = %s\n",opt->type);
        fprintf(stderr,"OPT: Authority = %s\n",opt->authority);
        fprintf(stderr,"OPT: value = %s\n",opt->value);
#endif    
        /*Check if this is the option we're looking for */
        if (opt->type && strcmp(opt->type,"ObjectName")==0 &&
         opt->authority && strcmp(opt->authority,cond->authority)==0){
            found = 1;
            break;
        }
    }

    if(!found)
    {
	    gaa_set_callback_err("gaa_simple_check_local_access: unable to \
                              find object name in options list");
	    return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    
    if((filename = (char *)malloc(strlen(opt->value)+1)) == 0)
    {
	    gaa_set_callback_err("gaa_simple_check_local_access: memory allocation error");
	    return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    }
    
    strcpy(filename, opt->value);
    /*strip off trailing '/'s */
    for(i = strlen(filename)-1; (i > 0) && (filename[i] == '/'); i--);
    filename[i+1] = 0;
    
    /*map between requested access mode and unix access modes*/
    if(!strcmp(cond->value,"read"))
        /*need read permission on file/directory*/
        mode = R_OK;
    else if(!strcmp(cond->value,"lookup"))
        /*need read permission on file/directory*/
        mode = R_OK;
    else if(!strcmp(cond->value,"write"))
        /*need write permission on file/directory*/
        mode = W_OK;
    else if(!strcmp(cond->value,"delete"))
    {   /*need write permission on parent directory*/
        /*get the parent directory (filename is an absolute path)*/
        for(i = strlen(filename)-1; 
                (i > 0) && (filename[i] != '/'); i--);
        filename[i+1] = 0;

        mode = W_OK;
    }
    else if(!strcmp(cond->value,"create"))
    {
        /*First, make sure the object does not exist*/
        struct stat buf;
        extern int errno;
        if(!(stat(filename, &buf) && errno == ENOENT))
        {
	        gaa_set_callback_err("gaa_simple_check_local_access: \
                            invalid access mode");
	        return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
        }
        
        /*need write permissions on parent dir*/
        for(i = strlen(filename)-2; 
                (i > 0) && (filename[i] != '/'); i--);
        filename[i+1] = 0;
        mode = W_OK;
    }    
    else /*invalid access mode*/
    {
	    gaa_set_callback_err("gaa_simple_check_local_access: \
                            invalid access mode");
	    return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }

    /*check if access allowed*/
    if(access(filename,mode) == 0)
        *output_flags |=  GAA_COND_FLG_MET;
    
    return (GAA_S_SUCCESS);
}



/** gaasimple_utc_time_notbefore_cond()
 * @ingroup gaa_simple
 *
 * Checks the time condition.  Checks whether the current time is within
 * the valid time period specified in the policy for the request.
 * This function is very similar to gaa_simple_utc_time_notonorafter_cond().
 * This function is intended to be used as a gaa cond_eval callback
 * function.
 *
 * @param gaa
 *        input gaa pointer
 * @param sc
 *        input security context
 * @param cond 
 *        input/output condition to check.
 * @param valid_time
 *        output valid time period
 * @param req_options
 *        input request options (passed on to any condition-evaluation
 *        callbacks, can be used by credential conditions)
 * @param output_flags
 *        output status pointer.  On success, *output_flags will be set to
 *        the appropriate combination of GAA_COND_FLG_EVALUATED,
 *        GAA_COND_FLG_MET, GAA_COND_FLG_ENFORCE. 
 * @param params
 *        input, should be a (gaa_cred_type *) pointer to a credential
 *        type (identity, group, etc.).
 * 
 * @retval GAA_S_SUCCESS
 *         success
 * @retval standard gaa error returns
 */
gaa_status
gaasimple_utc_time_notbefore_cond(gaa_ptr            gaa,
                                  gaa_sc_ptr         sc,
                                  gaa_condition     *cond,
                                  gaa_time_period   *valid_time,
				  gaa_list_ptr	req_options,
                                  gaa_status        *output_flags,
                                  void              *params)
{
  gaa_time_period t1;
  char *temp;
  struct tm *current_time;
  int valid_year, valid_month, valid_date;
  int  valid_hour, valid_min, valid_sec;
  
  char inputTime[22];

  *output_flags = GAA_COND_FLG_EVALUATED;

  strcpy(inputTime, (char *) cond->value);
  
  current_time= malloc(sizeof(struct tm));
 
  /* Get system time in UT or GMT */
 
  t1.start_time = time(NULL);
  current_time = gmtime_r(&t1.start_time, current_time);   
                         
  /* Read the valid time period, from the "condition" */
                         
  if((temp = strtok((char *) inputTime,"-")) == 0)
    return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
  valid_year = atoi(temp);
  
  if((temp = strtok(NULL,"-")) == 0)
    return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
  valid_month = atoi(temp);

  if((temp = strtok(NULL,"T")) == 0)
    return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
  valid_date = atoi(temp);

  if((temp = strtok(NULL,":")) == 0)
    return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
  valid_hour =atoi(temp);
  
  if((temp = strtok(NULL,":")) == 0)
    return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
  valid_min =atoi(temp);

  if((temp = strtok(NULL,"Z")) == 0)
    return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
  valid_sec =atoi(temp);

  
  /* Validate time */
  
  if((valid_year > current_time->tm_year + 1900))
    return(GAA_S_SUCCESS);
  else if((valid_year < current_time->tm_year + 1900))
    goto valid;
  else {
    if((valid_month > current_time->tm_mon + 1))
      return(GAA_S_SUCCESS);
    else if((valid_month < current_time->tm_mon + 1))
      goto valid;
    else {
      if((valid_date > current_time->tm_mday))
        return(GAA_S_SUCCESS);
      else if ((valid_date < current_time->tm_mday))
        goto valid;
      else {
        if((valid_hour > current_time->tm_hour))
          return(GAA_S_SUCCESS);
        else if((valid_hour < current_time->tm_hour))
          goto valid;
        else {
          if((valid_min > current_time->tm_min))
            return(GAA_S_SUCCESS);
          else if((valid_min < current_time->tm_min))
            goto valid;
          else {
            if((valid_sec > current_time->tm_sec))
              return(GAA_S_SUCCESS);
            else
              goto valid;
          }
        }
      }
    }
  }
  
  valid:
  *output_flags = (GAA_COND_FLG_EVALUATED | GAA_COND_FLG_MET);
  
  return(GAA_S_SUCCESS);
  }
/* End of gaasimple_utc_time_notbefore_cond() */                     


/** gaasimple_utc_time_notonorafter_cond()
 * @ingroup gaa_simple
 *
 * Checks the time condition.  Checks whether the current time is within
 * the valid time period specified in the policy for the request.
 * This function is very similar to gaa_simple_utc_time_notbefore_cond().
 * This function is intended to be used as a gaa cond_eval callback
 * function.
 *
 * @param gaa
 *        input gaa pointer
 * @param sc
 *        input security context
 * @param cond 
 *        input/output condition to check.
 * @param valid_time
 *        output valid time period
 * @param req_options
 *        input request options (passed on to any condition-evaluation
 *        callbacks, can be used by credential conditions)
 * @param output_flags
 *        output status pointer.  On success, *output_flags will be set to
 *        the appropriate combination of GAA_COND_FLG_EVALUATED,
 *        GAA_COND_FLG_MET, GAA_COND_FLG_ENFORCE. 
 * @param params
 *        input, should be a (gaa_cred_type *) pointer to a credential
 *        type (identity, group, etc.).
 * 
 * @retval GAA_S_SUCCESS
 *         success
 * @retval standard gaa error returns
 */
gaa_status
gaasimple_utc_time_notonorafter_cond(gaa_ptr            gaa,
                                     gaa_sc_ptr         sc,
                                     gaa_condition     *cond,
                                     gaa_time_period   *valid_time,
				     gaa_list_ptr	req_options,
                                     gaa_status        *output_flags,
                                     void              *params)
{
  gaa_time_period t1;
  char *temp;
  struct tm *current_time;
  int valid_year, valid_month, valid_date;
  int  valid_hour, valid_min, valid_sec;
  
  char inputTime[22];

  *output_flags = GAA_COND_FLG_EVALUATED;

  strcpy(inputTime, (char *) cond->value);
  
  current_time= malloc(sizeof(struct tm));
 
  /* Get system time in UT or GMT */
 
  t1.start_time = time(NULL);
  current_time = gmtime_r(&t1.start_time, current_time);   
                         
  /* Read the valid time period, from the "condition" */
                         
  if((temp = strtok((char *) inputTime,"-")) == 0)
    return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
  valid_year = atoi(temp);
  
  if((temp = strtok(NULL,"-")) == 0)
    return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
  valid_month = atoi(temp);

  if((temp = strtok(NULL,"T")) == 0)
    return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
  valid_date = atoi(temp);

  if((temp = strtok(NULL,":")) == 0)
    return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
  valid_hour =atoi(temp);
  
  if((temp = strtok(NULL,":")) == 0)
    return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
  valid_min =atoi(temp);

  if((temp = strtok(NULL,"Z")) == 0)
    return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
  valid_sec =atoi(temp);

  
  /* Validate time */
  
  if((valid_year < current_time->tm_year + 1900))
    return(GAA_S_SUCCESS);
  else if((valid_year > current_time->tm_year + 1900))
    goto valid;
  else {
    if((valid_month < current_time->tm_mon + 1))
      return(GAA_S_SUCCESS);
    else if((valid_month > current_time->tm_mon + 1))
      goto valid;
    else {
      if((valid_date < current_time->tm_mday))
        return(GAA_S_SUCCESS);
      else if ((valid_date > current_time->tm_mday))
        goto valid;
      else {
        if((valid_hour < current_time->tm_hour))
          return(GAA_S_SUCCESS);
        else if((valid_hour > current_time->tm_hour))
          goto valid;
        else {
          if((valid_min < current_time->tm_min))
            return(GAA_S_SUCCESS);
          else if((valid_min > current_time->tm_min))
            goto valid;
          else {
            if((valid_sec <= current_time->tm_sec))
              return(GAA_S_SUCCESS);
            else
              goto valid;
          }
        }
      }
    }
  }
  
  valid:
  *output_flags = (GAA_COND_FLG_EVALUATED | GAA_COND_FLG_MET);
  
  return(GAA_S_SUCCESS);
  }
/* End of gaasimple_utc_time_notbefore_cond() */                     
