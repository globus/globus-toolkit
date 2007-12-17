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

#define MAX_WORD_LEN        200


static gaa_status
gaa_simple_l_add_policy_right(
    gaa_ptr                             gaa,
    gaa_policy_right **                 right,
    gaa_right_type                      right_type,
    char *                              authority,
    char *                              val,
    gaa_policy *                        policy);


/*Strips off leading and trailing white spaces from string
 *Returns pointer to cleaned up string*/

static char *cleanup(char *line)
{
    int i, j;
    char *result;
         
    /*strip off leading and trailing white spaces from line*/
    for(i=0; isspace(line[i]) ; i++);
    result = line + i;

    for(j = strlen(line)-1; (j >= 0) && isspace(line[j]); j--);
    line[j+1] = 0;
     
    return result;
}        


/**
 *
 * @ingroup gaa_simple
 *
 * Create a GAA policy from a restrictions list.  This function
 * is meant to be used as a GAA getpolicy callback function.
 *
 * @param gaa
 *        input gaa pointer
 * @param policy
 *        output policy pointer
 * @param in_object
 *        input object (filename or dirname) to get policy for
 * @param params
 *        structure containing the restrictions, the actions and
 *        potentially a url base string.
 *
 * @retval GAA_S_SUCCESS
 *         success
 * @retval GAA_S_INVALID_ARG
 *         one of gaa, policy, object, params, or *params was 0
 * @retval GAA_S_POLICY_PARSING_FAILURE
 *         syntax error in restrictions string.
 */

gaa_status
gaa_simple_parse_restrictions(
    gaa_ptr                             gaa,
    gaa_policy **                       policy,
    gaa_string_data                     in_object,
    void *                              params)
{
    gaa_status                          status = GAA_S_SUCCESS;
    gaa_simple_callback_arg_t *          cb_arg;
    char                                ebuf[2048];
    gaa_policy_right *                  right = 0;
    char *                              restrictions;
    char                                lval[MAX_WORD_LEN];
    char                                rval[MAX_WORD_LEN];
    char                                object_name_type[MAX_WORD_LEN];
    char                                object_name[MAX_WORD_LEN];
    char *                              clean_obj_name_type = 0;
    char *                              clean_obj_name;
    char *                              clean_service_type;
    char *                              clean_service_action;
    char *                              object;
    char                                service_type[MAX_WORD_LEN];
    char                                service_action[MAX_WORD_LEN];
    char *                              line;
    char *                              token;
    int                                 linelen;
    int                                 open = 0;
    int                                 linecount;
    int                                 found_obj = 0;
    int                                 found_st = 0;
    int                                 policycount = 0;
    int                                 i;
    int                                 urlbase_len = 0;

   
    /*Check for null input values*/
    if (gaa == NULL || policy == NULL ||
        in_object == NULL || params == NULL)
    {
        gaa_set_callback_err("gaasimple_parse_restrictions: called with null gaa, policy, or objectname");
        return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }

    cb_arg = (gaa_simple_callback_arg_t *) params;
    
    /*create and initialize a new policy structure*/
    if ((status = gaa_new_policy(policy)) != GAA_S_SUCCESS)
    {
        snprintf(ebuf, sizeof(ebuf),
            "gaasimple_read_eacl: failed to create policy structure: %s\n",
            gaa_x_majstat_str(status));
        gaa_set_callback_err(ebuf);
        return(status);
    }

    /* if no restrictions were passed in, allow all operations --
     * ie build policy containing all rights*/
    if ((restrictions = cb_arg->restrictions) == 0)
    {
        /*
         * TODO - should simply have one "can do everything" entry, and should
         * install valmatch callbacks to understand it.
         */
        for (i = 0; cb_arg->actions[i]; i++)
        {
            status = gaa_simple_l_add_policy_right(
                gaa,
                &right,
                gaa_pos_access_right,
                cb_arg->service_type,
                cb_arg->actions[i],
                *policy);
            
            if (status != GAA_S_SUCCESS)
            {
                break;
            }
        }
        return(status);
    }

    /*remove leading and trailing white spaces from input object*/
    object = cleanup(in_object);
#ifdef DEBUG
    fprintf(stderr, "Checking for object: %s\n", object);
#endif /* DEBUG */    
    line = NULL;

    open = 0;
    
    while(*restrictions != '\0')
    {
        linecount++;
        /*how many chars before the first \n*/
        linelen = strcspn(restrictions,"\n");
        if(line)
        {
            free(line);
            line = NULL;
        }
        line = (char *)malloc(linelen+1);
        memset(line,0,linelen+1);
        
        /*read one line from the restrictions string*/
        sscanf(restrictions,"%[^\n]",line);
        restrictions += linelen+1;   

        /*remove leading and trailing white spaces from line*/
        token = cleanup(line);
        
#ifdef DEBUG
        fprintf(stderr,"Processing: <%s>\n",token);
#endif /* DEBUG */
        if(*token == '{')
        {
            if(open)
            {
                /*we have encountered an opening brace before this*/
                snprintf(ebuf, sizeof(ebuf),
                    "gaasimple_parse_restrictions: bad token (unbalanced brace) on line %d\n",linecount); 
                gaa_set_callback_err(ebuf);
                return(GAA_STATUS(GAA_S_POLICY_PARSING_FAILURE,0));
            }
            found_obj = found_st = 0;
            open = 1;
        }
        else if(*token == '}')
        {
            if(!open)
            {
                /*we have not seen an open brace before this*/
                snprintf(ebuf, sizeof(ebuf),
                    "gaasimple_parse_restrictions: bad token (unbalanced brace) on line %d\n",linecount); 
                gaa_set_callback_err(ebuf);
                return(GAA_STATUS(GAA_S_POLICY_PARSING_FAILURE,0));
            }
            found_obj = found_st = 0;
            open = 0;
        }
        else if(*token == 0)
        {
            /*blank line*/
            continue;
        }
        else
        {   /*Token is of the form <lval>=<rval>
             *lval and rval are 200 bytes long,
             * so make sure scanf reads in at most 199 byes per value*/
            if(sscanf(token,"%199[^=]=%199[^\n]",lval, rval) != 2)
            {
                snprintf(ebuf, sizeof(ebuf),
                 "gaasimple_parse_restrictions: invalid policy at line %d\n",linecount);
                gaa_set_callback_err(ebuf);
                return(GAA_STATUS(GAA_S_POLICY_PARSING_FAILURE,0));
            }
            /*force rval null terminated*/
            rval[MAX_WORD_LEN-1] = 0;
            
            if(!strcasecmp(lval,"OBJECT_NAME_TYPE"))
            {
                strncpy(object_name_type,rval,MAX_WORD_LEN);
                /*force object name type null terminated*/
                object_name_type[MAX_WORD_LEN-1] = 0;
                clean_obj_name_type = cleanup(object_name_type);
            }
            else if(!strcasecmp(lval,"OBJECT_NAME"))
            {
                int len ;
                strncpy(object_name,rval,MAX_WORD_LEN);
                /*force object name null terminated*/
                object_name[MAX_WORD_LEN-1] = 0;
                /*remove leading white chars from object name*/
                clean_obj_name = cleanup(object_name);
		       
                if (cb_arg->urlbase)
                {
                    urlbase_len = strlen(cb_arg->urlbase);
                    if(strncmp(clean_obj_name, cb_arg->urlbase, urlbase_len) == 0)
                    {   /* object name in policy file is url-encoded*/
                        clean_obj_name += urlbase_len;
                    }
                }
                
		if (clean_obj_name_type == 0)
		{
		    snprintf(ebuf, sizeof(ebuf),
			     "gaasimple_parse_restrictions: no object name type");
		    gaa_set_callback_err(ebuf);
		    return(GAA_STATUS(GAA_S_POLICY_PARSING_FAILURE, 0));
		}

                /*Strip off trailing /'s before compare 
                  Assumes that object name is an absolute path,
                  ie the first char is a '/' */
                for(len = strlen(object)-1; 
                    (len > 0) && (object[len] == '/'); len--);
                object[len+1] = 0;
                
                for(len = strlen(clean_obj_name)-1; 
                    (len > 0) && (clean_obj_name[len] == '/'); len--);
                clean_obj_name[len+1] = 0;

#ifdef DEBUG                
                fprintf(stderr, "Clean object name: %s\n", clean_obj_name);
#endif /* DEBUG */

		if (strcmp(clean_obj_name_type, "wildcard") == 0)
		{                        
		    /*Object names in policy file may end in *, which indicates subtrees*/
		    if(clean_obj_name[len] == '*')
		    {
			if(clean_obj_name[len-1] == '/')
			{
			    /*add a '/' to the input object*/
			    object[strlen(object)+1] = '\0';
			    object[strlen(object)]   = '/';
			}
			/* compare the two values upto but not
			   including the *.  */
			if(!strncmp(clean_obj_name,object,len))
			{
			    found_obj = 1;
			}
		    }
		    else
		    {
			if(!strcmp(clean_obj_name, object))
			{
			    found_obj = 1;
			}
		    }
		}
		else if (strcmp(clean_obj_name_type, "exact") == 0)
		{
		    if(!strcmp(clean_obj_name, object))
		    {
			found_obj = 1;
		    }
		}
		else
		{
		    snprintf(ebuf, sizeof(ebuf),
			     "gaasimple_parse_restrictions: unrecognized object name type '%s'",
			     clean_obj_name_type);
		    gaa_set_callback_err(ebuf);
		    return(GAA_STATUS(GAA_S_POLICY_PARSING_FAILURE, 0));
		}
#ifdef DEBUG
                fprintf(stderr, "Object \"%s\" %s match\n",
                        clean_obj_name,
                        (found_obj ? "does" : "does not"));
#endif /* DEBUG */                
            }
            else if(!strcasecmp(lval,"SERVICE_TYPE"))
            {
                strncpy(service_type,rval,MAX_WORD_LEN);
                /*force service type null terminated*/
                service_type[MAX_WORD_LEN-1] = 0;
                clean_service_type = cleanup(service_type);
                found_st  = 1;
            }
            else if(!strcasecmp(lval,"SERVICE_ACTION"))
            {
                if(found_obj){
                    if(!found_st){
                        snprintf(ebuf, sizeof(ebuf),
                        "gaasimple_parse_restrictions: unexpected token (SERVICE_ACTION) on line %d\n",linecount); 
                        gaa_set_callback_err(ebuf);
                        return(GAA_STATUS(GAA_S_POLICY_PARSING_FAILURE,0));
                    }
                    strncpy(service_action,rval,MAX_WORD_LEN);
                    /*force action null terminated*/
                    service_action[MAX_WORD_LEN-1] = 0;
                    clean_service_action = cleanup(service_action);

                    
                    /*Add a policy right*/
                    status =
                        gaa_simple_l_add_policy_right(gaa,
                                                      &right,
                                                      gaa_pos_access_right,
                                                      clean_service_type,
                                                      clean_service_action,
                                                      *policy);

                    if (status != GAA_S_SUCCESS)
                    {
#ifdef DEBUG
                        fprintf(stderr, "Error adding right\n");
#endif /* DEBUG */                        
                        return(status);
                    }

#ifdef DEBUG
                    fprintf(stderr,
                            "Added right: object=%s, service_type=%s, action=%s\n",
                            object, clean_service_type, clean_service_action);
#endif /* DEBUG */                    

                    policycount++;
                }/*end if found_obj*/
            }/*end else*/
            else
            {
                snprintf(ebuf, sizeof(ebuf),
                "gaasimple_parse_restrictions: unrecognized lvalue on line %d\n",linecount); 
                gaa_set_callback_err(ebuf);
                return(GAA_STATUS(GAA_S_POLICY_PARSING_FAILURE,0));
            }
        }/*end else*/
    }/*end while*/    

#ifdef DEBUG
    fprintf(stderr,"Built %d policy rights\n",policycount);
#endif
    /*gaadebug_policy_string(gaa, ebuf, sizeof(ebuf),*policy); */
    return(status);
}

static gaa_status
gaa_simple_l_add_policy_right(
    gaa_ptr                             gaa,
    gaa_policy_right **                 right,
    gaa_right_type                      right_type,
    char *                              authority,
    char *                              val,
    gaa_policy *                        policy)
{
    int			                pri = 0;
    static int			        num = 0;
    char		                ebuf[2048];

    gaa_status status = GAA_S_SUCCESS;

    *right = NULL;

    /*create and initialize a new policy right*/
    if((status = gaa_new_policy_right(gaa, 
				      right,
				      right_type,
				      authority,
				      val)) != GAA_S_SUCCESS)
    {
	snprintf(ebuf, sizeof(ebuf),
		 "gaasimple_parse_restrictions: failed to create right: %s\n",
		 gaa_x_majstat_str(status));
	gaa_set_callback_err(ebuf);
	return(status);
    }
	    
    if ((status = gaa_add_policy_entry(policy, (*right), 
				       pri, num++)) != GAA_S_SUCCESS)
    {
	snprintf(ebuf, sizeof(ebuf),
		 "gaasimple_parse_restrictions: failed to add right: %s\n",
		 gaa_x_majstat_str(status));
	gaa_set_callback_err(ebuf);
	return(status);
    }

    return(status);
}


				
