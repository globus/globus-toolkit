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
#include "gaa_private.h"
#include <stdio.h>
#define DEFAULT_STRSIZE 2048

/** @defgroup gaa_str_static "static routines from gaa_core/gaa_str.c"
 */
/** @defgroup gaa_core "gaacore routines"
 */

struct strtbl {
    int i;
    char *s;
};
typedef struct strtbl strtbl;

struct gaaint_strinfo {
    gaacore_tsdata tsdata;
    int size;
    void **fake;		/* for when there are no ts callbacks */
};

typedef struct gaaint_strinfo gaaint_strinfo;

static gaaint_strinfo Errinfo = {{0, 0}, 0, 0};

static gaaint_strinfo Callback_errinfo = {{0, 0}, 0, 0};

static char *
gaa_l_str_get(gaaint_strinfo *sinfo);

static
gaa_l_str_set(gaaint_strinfo *sinfo, char *s);

static void
gaa_l_str_free_sp(void *sp);

static char *
gaa_l_str_int2str(int in, strtbl *stbl, char *buf, int bsize);

static char *
gaa_l_str_flags2str(int in, strtbl *stbl, char *buf, int bsize);

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_str_int2str()
 *
 *  @ingroup gaa_str_static
 * 
 *  Translate an integer into a string.
 *
 *  @param in
 *         input integer to translate
 *  @param stbl
 *         input translation table
 *  @param buf
 *         input work buffer (should have enough room for final string)
 *  @param bsize
 *         input size of buf
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */
static char *
gaa_l_str_int2str(int			in,
		  strtbl *		stbl,
		  char *		buf,
		  int			bsize)
{
    strtbl *st;

    for (st = stbl; st->s; st++)
	if (in == st->i)
	    return(st->s);
    snprintf(buf, bsize, "unknown value %d\n", in);
    return(buf);
}

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_str_flags2str()
 *
 *  @ingroup gaa_str_static
 * 
 *  Translate a bitmask into a string.
 *
 *  @param in
 *         input bitmask to translate
 *  @param stbl
 *         input translation table
 *  @param buf
 *         input work buffer (should have enough room for final string)
 *  @param bsize
 *         input size of buf
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */
static char *
gaa_l_str_flags2str(int			in,
		    strtbl *		stbl,
		    char *		buf,
		    int			bsize)
{
    strtbl *				st;
    int					i;
    char *				s;

    buf[0] = '(';
    for (i = 1, st = stbl; st->s && (i < bsize); st++)
	if (in & st->i) {
	    if (i > 1)
		buf[i++] = '|';
	    for (s = st->s; *s && (i < bsize); s++, i++)
		buf[i] = *s;
	}
    if (i < bsize-1)
	buf[i++] = ')';
    buf[i] = '\0';
    return(buf);
}

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_str_get()
 *
 *  @ingroup gaa_str_static
 * 
 *  Get thread-specific data corresponding to the specified strinfo.
 *  If thread-specific data isn't supported, use the same data for
 *  all threads.
 *
 *  @param sinfo
 *         input string info
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */
static char *
gaa_l_str_get(gaaint_strinfo *sinfo)
{
    int status;
    char **sp;
    int use_tsdata = 0;

    if (! sinfo)
	return(0);
    if (gaacore_tsdata_create(&sinfo->tsdata, gaa_l_str_free_sp))
	return(0);
    if ((use_tsdata = gaa_i_tsdata_supported()))
	sp = gaacore_tsdata_get(&sinfo->tsdata);
    else
	sp = (char **)sinfo->fake;

    if (sp == 0)
    {
	if ((sp = (char **)malloc(sizeof(char *))) == 0)
	    return(0);
	*sp = malloc(sinfo->size ? sinfo->size :
		     (sinfo->size = DEFAULT_STRSIZE));
	if (sp && *sp)
	    **sp = '\0';
    }
    if (use_tsdata)
    {
	if (gaacore_tsdata_set(&sinfo->tsdata, sp))
	{
	    if (sp) 
		gaa_l_str_free_sp(sp);
	    return(0);
	}
    }
    else
	sinfo->fake = (void *)sp;

    return(sp ? (*sp) : 0);
}

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_str_free_sp()
 *
 *  @ingroup gaa_str_static
 *
 *  Free a (char **) pointer and the string it points to.  Used by
 *  gaa_l_str_get().
 *
 *  @param sp
 *         input/output pointer to free.
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */
static void
gaa_l_str_free_sp(void *sp)
{
    char **spp = (char **)sp;
    if (spp)
    {
	if (*spp)
	    free(*spp);
	free(spp);
    }
}

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_str_set()
 *
 *  @ingroup gaa_str_static
 *
 *  Set thread-specific string data.
 *
 *  @param sinfo
 *         input/output string info
 *  @param s
 *         input value to set sinfo's thread-specific data to
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */
static 
gaa_l_str_set(gaaint_strinfo *		sinfo,
	      char			*s)
{
    char *str;
    if ((str = gaa_l_str_get(sinfo)) == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    strncpy(str, s, sinfo->size);
    str[sinfo->size-1] = '\0';
    return(GAA_STATUS(GAA_S_SUCCESS, 0));
}

/** gaacore_set_err()
 *
 *  @ingroup gaa_core
 *
 *  Set the gaa thread-specific error string.
 *
 *  @param s
 *         input string to set the error to.
 */
gaa_status	
gaacore_set_err(char *s)
{
    return(gaa_l_str_set(&Errinfo, s));
}

/** gaa_get_err()
 *
 *  @ingroup gaa
 *
 *  Get the gaa thread-specific error string.
 */
char *
gaa_get_err()
{
    return(gaa_l_str_get(&Errinfo));
}

/** gaa_get_err()
 *
 *  @ingroup gaa
 *
 *  Set the gaa thread-specific callback error string.
 *
 *  @param s
 *         input string to set the callback error to.
 */
gaa_status
gaa_set_callback_err(char *s)
{
    return(gaa_l_str_set(&Callback_errinfo, s));
}

/** gaa_get_err()
 *
 *  @ingroup gaa
 *
 *  Get the gaa thread-specific calback error string.
 */
char *
gaa_get_callback_err()
{
    return(gaa_l_str_get(&Callback_errinfo));
}

/** gaacore_condstat2str()
 *
 *  @ingroup gaa_core
 *
 *  Return a string representation of the condition status.
 *
 *  @param status
 *         input status
 */
char *
gaacore_condstat2str(int status)
{
    static strtbl stbl[] = {
	{GAA_COND_FLG_EVALUATED, "evaluated"},
	{GAA_COND_FLG_MET, "met"},
	{GAA_COND_FLG_ENFORCE, "enforce"},
	{0, 0},
    };
    static gaaint_strinfo sinfo = {{0, 0}, 128, 0};
    char *s;

    if (s = gaa_l_str_get(&sinfo))
	return(gaa_l_str_flags2str(status, stbl, s, sinfo.size));
    return(0);
}

/** gaacore_majstat_str()
 *
 *  @ingroup gaa_core
 *
 *  Return a string representation of the major part of the status.
 *
 *  @param status
 *         input status
 */
char *
gaacore_majstat_str(int status)
{
    static strtbl stbl[] = {
	{GAA_S_SUCCESS, "GAA_S_SUCCESS"},
	{GAA_C_YES, "GAA_C_YES"},
	{GAA_C_NO, "GAA_C_NO"},
	{GAA_C_MAYBE, "GAA_C_MAYBE"},
	{GAA_S_FAILURE, "GAA_S_FAILURE"},
	{GAA_S_INVALID_STRING_DATA_HNDL, "GAA_S_INVALID_STRING_DATA_HNDL"},
	{GAA_S_INVALID_LIST_HNDL, "GAA_S_INVALID_LIST_HNDL"},
	{GAA_S_INVALID_GAA_HNDL, "GAA_S_INVALID_GAA_HNDL"},
	{GAA_S_INVALID_POLICY_ENTRY_HNDL, "GAA_S_INVALID_POLICY_ENTRY_HNDL"},
	{GAA_S_INVALID_POLICY_HNDL, "GAA_S_INVALID_POLICY_HNDL"},
	{GAA_S_INVALID_SC_HNDL, "GAA_S_INVALID_SC_HNDL"},
	{GAA_S_INVALID_ANSWER_HNDL, "GAA_S_INVALID_ANSWER_HNDL"},
	{GAA_S_INVALID_REQUEST_RIGHT_HNDL, "GAA_S_INVALID_REQUEST_RIGHT_HNDL"},
	{GAA_S_INVALID_POLICY_RIGHT_HNDL, "GAA_S_INVALID_POLICY_RIGHT_HNDL"},
	{GAA_S_INVALID_CONDITION_HNDL, "GAA_S_INVALID_CONDITION_HNDL"},
	{GAA_S_INVALID_OPTIONS_HNDL, "GAA_S_INVALID_OPTIONS_HNDL"},
	{GAA_S_INVALID_IDENTITY_INFO_HNDL, "GAA_S_INVALID_IDENTITY_INFO_HNDL"},
	{GAA_S_INVALID_AUTHR_INFO_HNDL, "GAA_S_INVALID_AUTHR_INFO_HNDL"},
	{GAA_S_INVALID_PRINCIPAL_HNDL, "GAA_S_INVALID_PRINCIPAL_HNDL"},
	{GAA_S_INVALID_ATTRIBUTE_HNDL, "GAA_S_INVALID_ATTRIBUTE_HNDL"},
	{GAA_S_UNIMPLEMENTED_FUNCTION, "GAA_S_UNIMPLEMENTED_FUNCTION"},
	{GAA_S_NO_MATCHING_ENTRIES, "GAA_S_NO_MATCHING_ENTRIES"},
	{GAA_S_POLICY_PARSING_FAILURE, "GAA_S_POLICY_PARSING_FAILURE"},
	{GAA_S_POLICY_RETRIEVING_FAILURE, "GAA_S_POLICY_RETRIEVING_FAILURE"},
	{GAA_S_INVALID_ARG, "GAA_S_INVALID_ARG"},
	{GAA_S_UNKNOWN_MECHANISM, "GAA_S_UNKNOWN_MECHANISM"},
	{GAA_S_NO_CRED_PULL_CALLBACK, "GAA_S_NO_CRED_PULL_CALLBACK"},
	{GAA_S_NO_AUTHINFO_CALLBACK, "GAA_S_NO_AUTHINFO_CALLBACK"},
	{GAA_S_NO_NEWVAL_CALLBACK, "GAA_S_NO_NEWVAL_CALLBACK"},
	{GAA_S_NO_GETPOLICY_CALLBACK, "GAA_S_NO_GETPOLICY_CALLBACK"},
	{GAA_S_NO_MATCHRIGHTS_CALLBACK, "GAA_S_NO_MATCHRIGHTS_CALLBACK"},
	{GAA_S_INVALID_IDENTITY_CRED, "GAA_S_INVALID_IDENTITY_CRED"},
	{GAA_S_BAD_CALLBACK_RETURN, "GAA_S_BAD_CALLBACK_RETURN"},
	{GAA_S_INTERNAL_ERR, "GAA_S_INTERNAL_ERR"},
	{GAA_S_SYSTEM_ERR, "GAA_S_SYSTEM_ERR"},
	{GAA_S_CRED_PULL_FAILURE, "GAA_S_CRED_PULL_FAILURE"},
	{GAA_S_CRED_EVAL_FAILURE, "GAA_S_CRED_EVAL_FAILURE"},
	{GAA_S_CRED_VERIFY_FAILURE, "GAA_S_CRED_VERIFY_FAILURE"},
	{GAA_S_CONFIG_ERR, "GAA_S_CONFIG_ERR"},
	{0, 0},
    };
    static gaaint_strinfo sinfo = {{0, 0}, 128, 0};
    char *s;

    if (s = gaa_l_str_get(&sinfo))
	return(gaa_l_str_int2str(GAA_MAJSTAT(status), stbl, s, sinfo.size));
    return(0);
}


/** gaacore_right_type_to_string()
 *
 *  @ingroup gaa_core
 *
 *  Return a string representation of the right type.
 *
 *  @param type
 *         input right type
 */
char *
gaacore_right_type_to_string(gaa_right_type rtype)
{
    static strtbl stbl[] = {
	{gaa_pos_access_right, "pos_access_right"},
	{gaa_neg_access_right, "neg_access_right"},
	{0, 0},
    };
    static gaaint_strinfo sinfo = {{0, 0}, 32, 0};
    char *s;

    if (s = gaa_l_str_get(&sinfo))
	return(gaa_l_str_int2str(rtype, stbl, s, sinfo.size));
    return(0);
}

/** gaacore_cred_type_to_string()
 *
 *  @ingroup gaa_core
 *
 *  Return a string representation of the credential type.
 *
 *  @param type
 *         input credential type
 */
char *
gaacore_cred_type_to_string(gaa_cred_type ctype)
{
    static strtbl stbl[] = {
	{GAA_IDENTITY, "GAA_IDENTITY"},
	{GAA_GROUP_MEMB, "GAA_GROUP_MEMB"},
	{GAA_GROUP_NON_MEMB, "GAA_GROUP_NON_MEMB"},
	{GAA_AUTHORIZED, "GAA_AUTHORIZED"},
	{GAA_ATTRIBUTES, "GAA_ATTRIBUTES"},
	{GAA_UNEVAL, "GAA_UNEVAL"},
	{GAA_ANY, "GAA_ANY"},
	{0, 0},
    };
    static gaaint_strinfo sinfo = {{0, 0}, 128, 0};
    char *s;

    if (s = gaa_l_str_get(&sinfo))
	return(gaa_l_str_int2str(ctype, stbl, s, sinfo.size));
    return(0);
}

