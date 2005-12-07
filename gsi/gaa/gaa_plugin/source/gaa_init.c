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

#include <stdio.h>
#include <string.h>
#include <ltdl.h>
#include "gaa.h"
#include "gaa_util.h"
#include "gaa_plugin.h"
#include "gaa_plugin_private.h"

/** @defgroup gaa_plugin_init_static "gaa plugin init static functions"
 */
#define DEF_CFINFO_SIZE 16

typedef enum {
    gaa_l_plugin_unknown_cfg,
    gaa_l_plugin_symdesc_cfg,
    gaa_l_plugin_param_cfg,
    gaa_l_plugin_symparam_cfg,
    gaa_l_plugin_boolean_cfg,
    gaa_l_plugin_valinfo_cfg
} gaa_l_plugin_cfg_type_t;

struct gaa_l_plugin_cfg_info {
    char *name;
    gaa_l_plugin_cfg_type_t type;
    void *val;
};

typedef struct gaa_l_plugin_cfg_info gaa_l_plugin_cfg_info;

static gaa_status
gaa_l_plugin_read_miargs(gaa_plugin_mechinfo_args *miargs, FILE *cffile,
			 char *str);

static gaa_status
gaa_l_plugin_read_mxargs(gaa_plugin_mutex_args *mxargs, FILE *cffile,
			 char *str);

static gaa_status
gaa_l_plugin_read_ceargs(gaa_plugin_cond_eval_args *ceargs, FILE *cffile,
			 char *str);

static gaa_status
gaa_l_plugin_read_aiargs(gaa_plugin_authinfo_args *aiargs, FILE *cffile,
			 char *str);

static gaa_status
gaa_l_plugin_read_matchrights(gaa_plugin_matchrights_args *mrargs,
			      FILE *cffile, char *str);

static gaa_status
gaa_l_plugin_read_getpolicy(gaa_plugin_getpolicy_args *gpargs, FILE *cffile,
			    char *str);

static gaa_status
gaa_l_x_plugin_read_authz_id(gaa_plugin_authz_id_args *gpargs, FILE *cffile,
			     char *str);

static gaa_status
gaa_l_plugin_parse_boolean(int *result, char *str);

static gaa_status
gaa_l_plugin_read_cfinfo(gaa_l_plugin_cfg_info *cfinfo, FILE *cffile,
			 char *str, int firstbrace);

static gaa_status
gaa_l_plugin_read_valinfo(gaa_plugin_valinfo_args *viargs, FILE *cffile,
			  char *str);

static gaa_status
gaa_l_plugin_parse_param(gaa_plugin_parameter *param, char *str,
			 gaa_plugin_parameter_type type);

static gaa_status
gaa_l_plugin_parse_symdesc(gaa_plugin_symbol_desc *symdesc, char *str);

static gaa_status
gaa_l_plugin_init_cfinfo(gaa_l_plugin_cfg_info *cfinfo, int i, int cfisize,
			 char *name, gaa_l_plugin_cfg_type_t type, void *val);

static gaa_status gaa_l_init(gaa_ptr *			gaa,
			     gaa_string_data		cfname);

gaa_status
gaa_initialize(gaa_ptr *	gaa,
	       void *		param)
{
    gaa_string_data		cfname = (gaa_string_data) param;
    gaa_status			status = GAA_S_SUCCESS;
    gaa_valinfo_ptr		pvinfo = 0;
    gaa_valinfo_ptr		rvinfo = 0;

    /* Init from config file (if any). */
    if ((status = gaa_l_init(gaa, cfname)) != GAA_S_SUCCESS)
	return(status);

    /* Ensure that all mandatory callbacks have been installed. */
    if (! gaacore_has_matchrights_callback(*gaa))
	if ((status =
	     gaa_set_matchrights_callback(*gaa, gaa_plugin_default_matchrights,
					  0, 0)) != GAA_S_SUCCESS)
	    goto end;
    if (! gaacore_has_default_authinfo_callback(*gaa))
    {
	if ((status =
	     gaa_new_valinfo(&pvinfo,
			     gaa_plugin_default_copy_pval,
			     gaa_plugin_default_new_pval,
			     gaa_plugin_default_free_pval,
			     gaa_plugin_default_pval2str)) != GAA_S_SUCCESS)
	    goto end;
	if ((status =
	     gaa_new_valinfo(&rvinfo,
			     gaa_plugin_default_copy_rval,
			     gaa_plugin_default_new_rval,
			     free,
			     gaa_plugin_default_rval2str)) != GAA_S_SUCCESS)
	    goto end;
	if ((status = gaa_add_authinfo(*gaa, 0, pvinfo, rvinfo,
				       gaa_plugin_default_valmatch,
				       0, 0)) != GAA_S_SUCCESS)
	    goto end;
    }
 end:
    if (status != GAA_S_SUCCESS)
    {
	gaa_free_gaa(*gaa);
	*gaa = 0;
    }
    return(status);
}
	    
/** gaa_l_init()
 *
 * Create a gaa structure and initialize GAA, reading plugin information
 * from the specified configuration file (if specified).
 *
 * @ingroup gaa_plugin
 *
 * @param gaa
 *        output gaa pointer.
 * @param param
 *        input name of configuration file.
 *
 * @retval GAA_S_SUCCESS
 *         success
 * @retval GAA_S_SYSTEM_ERR
 *         error opening config file, or libtool error.
 * @retval GAA_S_INVALID_ARG
 *         gaa or cfname is null
 * @retval GAA_S_CONFIG_ERR
 *         syntax error in configuration file.
 */
static gaa_status
gaa_l_init(gaa_ptr *			gaa,
	   gaa_string_data		cfname)
{
    gaa_status				status;
    FILE *				cffile = 0;
    char				buf[8192];
    char *				tok;
    char *				next = 0;
    gaa_plugin_mechinfo_args		miargs;
    gaa_plugin_cond_eval_args		ceargs;
    gaa_plugin_authinfo_args		aiargs;
    gaa_plugin_matchrights_args		mrargs;
    gaa_plugin_getpolicy_args		gpargs;
    gaa_plugin_mutex_args		mxargs;
    gaa_plugin_authz_id_args		azargs;
    char *				s;

    if (gaa == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));

    if ((status = gaa_new_gaa(gaa)) != GAA_S_SUCCESS)
	return(status);

    if (cfname == 0)
	return(GAA_S_SUCCESS);

    if ((status = gaa_i_plugin_init_libtool()) != GAA_S_SUCCESS)
	return(status);

    if ((cffile = fopen(cfname, "r")) == 0)
    {
	snprintf(buf, sizeof(buf), "gaa_init: couldn't open config file %s",
		 cfname);
	gaacore_set_err(buf);
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    }

    while (fgets(buf, sizeof(buf), cffile))
    {
	if ((tok = gaautil_gettok(buf, &next)) == 0)
	    continue;
	if (*tok == '#')
	    continue;
	if (strcmp(tok, "libdir") == 0)
	{
	    if ((s = gaautil_gettok(next, &next)) == 0)
	    {
		gaacore_set_err("gaa_init: null libdir");
		return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));
	    }
	    if ((status = gaa_plugin_add_libdir(s)) != GAA_S_SUCCESS)
		return(status);
	}
	else if (strcmp(tok, "mechinfo") == 0)
	{
	    if ((status =
		 gaa_l_plugin_read_miargs(&miargs, cffile,
					  next)) != GAA_S_SUCCESS)
		return(status);
	    if ((status =
		 gaa_plugin_install_mechinfo(*gaa, &miargs)) != GAA_S_SUCCESS)
		return(status);
	}
	else if (strcmp(tok, "cond_eval") == 0)
	{
	    if ((status =
		 gaa_l_plugin_read_ceargs(&ceargs, cffile,
					  next)) != GAA_S_SUCCESS)
		return(status);
	    if ((status =
		 gaa_plugin_install_cond_eval(*gaa, &ceargs)) != GAA_S_SUCCESS)
		return(status);
	}
	else if (strcmp(tok, "authinfo") == 0)
	{
	    if ((status =
		 gaa_l_plugin_read_aiargs(&aiargs, cffile,
					  next)) != GAA_S_SUCCESS)
		return(status);
	    if ((status =
		 gaa_plugin_install_authinfo(*gaa, &aiargs)) != GAA_S_SUCCESS)
		return(status);
	}
	else if (strcmp(tok, "matchrights") == 0)
	{
	    if ((status =
		 gaa_l_plugin_read_matchrights(&mrargs, cffile,
					       next)) != GAA_S_SUCCESS)
		return(status);
	    if ((status =
		 gaa_plugin_install_matchrights(*gaa,
						&mrargs)) != GAA_S_SUCCESS)
		return(status);
	}
	else if (strcmp(tok, "getpolicy") == 0)
	{
	    if ((status =
		 gaa_l_plugin_read_getpolicy(&gpargs, cffile,
					     next)) != GAA_S_SUCCESS)
		return(status);
	    if ((status =
		 gaa_plugin_install_getpolicy(*gaa, &gpargs)) != GAA_S_SUCCESS)
		return(status);
	}
	else if (strcmp(tok, "mutex") == 0)
	{
	    if ((status =
		 gaa_l_plugin_read_mxargs(&mxargs, cffile,
					   next)) != GAA_S_SUCCESS)
		return(status);
	    if ((status =
		 gaa_plugin_install_mutex_callbacks(&mxargs)) != GAA_S_SUCCESS)
		return(status);
	}
	else if (strcmp(tok, "get_authz_identity") == 0)
	{
	    if ((status =
		 gaa_l_x_plugin_read_authz_id(&azargs, cffile,
					      next)) != GAA_S_SUCCESS)
		return(status);
	    if ((status =
		 gaa_plugin_install_authz_id(*gaa, &azargs)) != GAA_S_SUCCESS)
		return(status);
	}

    }
    fclose(cffile);
    return(GAA_S_SUCCESS);
}

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_plugin_read_miargs()
 *
 *  @ingroup gaa_plugin_init_static
 * 
 * Read mechinfo args from a configuration file.  Called by gaa_init().
 *
 * @param miargs
 *        output args to fill in
 * @param cffile
 *        input config file
 * @param str
 *        input string (leftover text from other config-reading routines)
 *
 * @retval GAA_S_SUCCESS
 *         success
 * @retval GAA_S_INTERNAL_ERR
 *         cffile or miargs is null.
 * @retval GAA_S_CONFIG_ERR
 *         syntax error in mechinfo entry.
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */
static gaa_status
gaa_l_plugin_read_miargs(gaa_plugin_mechinfo_args *miargs,
			 FILE *			   cffile,
			 char *			   str)
{
    char *				next = 0;
    char *				tok = 0;
    int					firstbrace = 0;
    gaa_status				status;
    int					i = 0;
    gaa_l_plugin_cfg_info		cfinfo[DEF_CFINFO_SIZE];

    if (cffile == 0 || miargs == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));

    i = 0;
    if ((status = (gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			       "cred_pull",
			       gaa_l_plugin_symdesc_cfg,
			       &miargs->cred_pull))) != GAA_S_SUCCESS)
	return(status);
    
	
    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "cred_eval",
			      gaa_l_plugin_symdesc_cfg,
			      &miargs->cred_eval)) != GAA_S_SUCCESS)
	return(status);
    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "cred_verify",
			      gaa_l_plugin_symdesc_cfg,
			      &miargs->cred_verify)) != GAA_S_SUCCESS)
	return(status);
    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "cred_free",
			      gaa_l_plugin_symdesc_cfg,
			      &miargs->cred_free)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "params",
			      gaa_l_plugin_param_cfg,
			      &miargs->param)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "sym_params",
			      gaa_l_plugin_symparam_cfg,
			      &miargs->param)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "freeparam",
			      gaa_l_plugin_symdesc_cfg,
			      &miargs->freeparam)) != GAA_S_SUCCESS)
	return(status);

    gaa_plugin_init_mechinfo_args(miargs);
    if ((tok = gaautil_gettok(str, &next)) == 0)
    {
	gaacore_set_err("gaa_init: no name for mechinfo");
	return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));
    }
    miargs->mech_type = tok;
    if (tok = gaautil_gettok(next, &next))
    {
	if (strcmp(tok, "{") == 0)
	    firstbrace++;
	else
	{
	    gaacore_set_err("gaa_init: bad text after \"mechinfo\"");
	    return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));
	}
    }

    return(gaa_l_plugin_read_cfinfo(cfinfo, cffile, next, firstbrace));
}

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_plugin_read_ceargs()
 *
 *  @ingroup gaa_plugin_init_static
 * 
 * Read cond_eval args from a configuration file.  Called by gaa_init().
 *
 * @param ceargs
 *        output args to fill in
 * @param cffile
 *        input config file
 * @param str
 *        input string (leftover text from other config-reading routines)
 *
 * @retval GAA_S_SUCCESS
 *         success
 * @retval GAA_S_INTERNAL_ERR
 *         cffile or ceargs is null.
 * @retval GAA_S_CONFIG_ERR
 *         syntax error in entry.
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */
static gaa_status
gaa_l_plugin_read_ceargs(gaa_plugin_cond_eval_args *ceargs,
			 FILE *		            cffile,
			 char *		            str)
{
    char *				next = 0;
    char *				tok = 0;
    int					firstbrace = 0;
    gaa_status				status;
    int					i;
    gaa_l_plugin_cfg_info		cfinfo[DEF_CFINFO_SIZE];

    if (cffile == 0 || ceargs == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));

    i = 0;
    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "cond_eval",
			      gaa_l_plugin_symdesc_cfg,
			      &ceargs->cond_eval)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "params",
			      gaa_l_plugin_param_cfg,
			      &ceargs->param)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "sym_params",
			      gaa_l_plugin_symparam_cfg,
			      &ceargs->param)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "freeparam",
			      gaa_l_plugin_symdesc_cfg,
			      &ceargs->freeparam)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "idcred",
			      gaa_l_plugin_boolean_cfg,
			      &ceargs->is_idcred)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_plugin_init_cond_eval_args(ceargs)) != GAA_S_SUCCESS)
	return(status);
    if ((tok = gaautil_gettok(str, &next)) == 0)
    {
	gaacore_set_err("gaa_init: no type for condition plugin");
	return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));
    }
    ceargs->cond_type = (strcmp(tok, "DEFAULT") ? tok : 0);

    if ((tok = gaautil_gettok(next, &next)) == 0)
    {
	gaacore_set_err("gaa_init: no authority for condition plugin");
	return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));
    }
    ceargs->cond_authority = (strcmp(tok, "DEFAULT") ? tok : 0);

    if (tok = gaautil_gettok(next, &next))
    {
	if (strcmp(tok, "{") == 0)
	    firstbrace++;
	else
	{
	    gaacore_set_err("gaa_init: bad text after \"cond_eval\"");
	    return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));
	}
    }

    return(gaa_l_plugin_read_cfinfo(cfinfo, cffile, next, firstbrace));
}

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_plugin_read_aiargs()
 *
 *  @ingroup gaa_plugin_init_static
 * 
 * Read authinfo args from a configuration file.  Called by gaa_init().
 *
 * @param aiargs
 *        output args to fill in
 * @param cffile
 *        input config file
 * @param str
 *        input string (leftover text from other config-reading routines)
 *
 * @retval GAA_S_SUCCESS
 *         success
 * @retval GAA_S_INTERNAL_ERR
 *         cffile or aiargs is null.
 * @retval GAA_S_CONFIG_ERR
 *         syntax error in authinfo entry.
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */
static gaa_status
gaa_l_plugin_read_aiargs(gaa_plugin_authinfo_args *aiargs,
			 FILE *		           cffile,
			 char *			   str)
{
    char *				next = 0;
    char *				tok = 0;
    int					firstbrace = 0;
    gaa_status				status;
    gaa_l_plugin_cfg_info		cfinfo[DEF_CFINFO_SIZE];
    int					i = 0;

    if (cffile == 0 || aiargs == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    i = 0;
    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "pvinfo",
			      gaa_l_plugin_valinfo_cfg,
			      &aiargs->pvinfo)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "rvinfo",
			      gaa_l_plugin_valinfo_cfg,
			      &aiargs->rvinfo)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "valmatch",
			      gaa_l_plugin_symdesc_cfg,
			      &aiargs->valmatch)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "params",
			      gaa_l_plugin_param_cfg,
			      &aiargs->param)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "sym_params",
			      gaa_l_plugin_symparam_cfg,
			      &aiargs->param)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "freeparam",
			      gaa_l_plugin_symdesc_cfg,
			      &aiargs->freeparam)) != GAA_S_SUCCESS)
	return(status);


    if (cffile == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    gaa_plugin_init_authinfo_args(aiargs);
    if ((tok = gaautil_gettok(str, &next)) == 0)
    {
	gaacore_set_err("gaa_init: no name for authinfo");
	return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));
    }
    aiargs->authority = ((strcmp(tok, "DEFAULT") == 0) ? 0 : tok);
    if (tok = gaautil_gettok(next, &next))
    {
	if (strcmp(tok, "{") == 0)
	    firstbrace++;
	else
	{
	    gaacore_set_err("gaa_init: bad text after \"authinfo\"");
	    return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));
	}
    }
    return(gaa_l_plugin_read_cfinfo(cfinfo, cffile, next, firstbrace));
}

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_plugin_read_matchrights()
 *
 *  @ingroup gaa_plugin_init_static
 * 
 * Read matchrights args from a configuration file.  Called by gaa_init().
 *
 * @param mrargs
 *        output args to fill in
 * @param cffile
 *        input config file
 * @param str
 *        input string (leftover text from other config-reading routines)
 *
 * @retval GAA_S_SUCCESS
 *         success
 * @retval GAA_S_INTERNAL_ERR
 *         cffile or mrargs is null.
 * @retval GAA_S_CONFIG_ERR
 *         syntax error in matchrights entry.
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */
static gaa_status
gaa_l_plugin_read_matchrights(gaa_plugin_matchrights_args *mrargs,
			      FILE *			   cffile,
			      char *			   str)
{
    char *				next = 0;
    char *				tok = 0;
    int					firstbrace = 0;
    gaa_status				status;
    gaa_l_plugin_cfg_info		cfinfo[DEF_CFINFO_SIZE];
    int					i = 0;

    i = 0;
    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "matchrights",
			      gaa_l_plugin_symdesc_cfg,
			      &mrargs->matchrights)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "params",
			      gaa_l_plugin_param_cfg,
			      &mrargs->param)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "sym_params",
			      gaa_l_plugin_symparam_cfg,
			      &mrargs->param)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "freeparam",
			      gaa_l_plugin_symdesc_cfg,
			      &mrargs->freeparam)) != GAA_S_SUCCESS)
	return(status);

    if (cffile == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    gaa_plugin_init_matchrights_args(mrargs);

    if (tok = gaautil_gettok(next, &next))
    {
	if (strcmp(tok, "{") == 0)
	    firstbrace++;
	else
	{
	    gaacore_set_err("gaa_init: bad text after \"getpolicy\"");
	    return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));
	}
    }
    return(gaa_l_plugin_read_cfinfo(cfinfo, cffile, next, firstbrace));
}

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_plugin_read_getpolicy()
 *
 *  @ingroup gaa_plugin_init_static
 * 
 * Read getpolicy args from a configuration file.  Called by gaa_init().
 *
 * @param gpargs
 *        output args to fill in
 * @param cffile
 *        input config file
 * @param str
 *        input string (leftover text from other config-reading routines)
 *
 * @retval GAA_S_SUCCESS
 *         success
 * @retval GAA_S_INTERNAL_ERR
 *         cffile or gpargs is null.
 * @retval GAA_S_CONFIG_ERR
 *         syntax error in getpolicy entry.
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */
static gaa_status
gaa_l_plugin_read_getpolicy(gaa_plugin_getpolicy_args *gpargs,
			    FILE *		       cffile,
			    char *		       str)
{
    char *				next = 0;
    char *				tok = 0;
    int					firstbrace = 0;
    gaa_status				status;
    gaa_l_plugin_cfg_info		cfinfo[DEF_CFINFO_SIZE];
    int					i = 0;

    if (cffile == 0 || gpargs == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));

    i = 0;
    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "getpolicy",
			      gaa_l_plugin_symdesc_cfg,
			      &gpargs->getpolicy)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "params",
			      gaa_l_plugin_param_cfg,
			      &gpargs->param)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "sym_params",
			      gaa_l_plugin_symparam_cfg,
			      &gpargs->param)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "freeparam",
			      gaa_l_plugin_symdesc_cfg,
			      &gpargs->freeparam)) != GAA_S_SUCCESS)
	return(status);

    if (cffile == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    gaa_plugin_init_getpolicy_args(gpargs);
    if (tok = gaautil_gettok(next, &next))
    {
	if (strcmp(tok, "{") == 0)
	    firstbrace++;
	else
	{
	    gaacore_set_err("gaa_init: bad text after \"getpolicy\"");
	    return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));
	}
    }
    return(gaa_l_plugin_read_cfinfo(cfinfo, cffile, next, firstbrace));
}

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_plugin_read_getpolicy()
 *
 *  @ingroup gaa_plugin_init_static
 * 
 * Read getpolicy args from a configuration file.  Called by gaa_init().
 *
 * @param gpargs
 *        output args to fill in
 * @param cffile
 *        input config file
 * @param str
 *        input string (leftover text from other config-reading routines)
 *
 * @retval GAA_S_SUCCESS
 *         success
 * @retval GAA_S_INTERNAL_ERR
 *         cffile or gpargs is null.
 * @retval GAA_S_CONFIG_ERR
 *         syntax error in getpolicy entry.
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */
static gaa_status
gaa_l_x_plugin_read_authz_id(gaa_plugin_authz_id_args *azargs,
			    FILE *		     cffile,
			    char *		     str)
{
    char *				next = 0;
    char *				tok = 0;
    int					firstbrace = 0;
    gaa_status				status;
    gaa_l_plugin_cfg_info		cfinfo[DEF_CFINFO_SIZE];
    int					i = 0;

    if (cffile == 0 || azargs == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));

    i = 0;
    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "get_authz_identity",
			      gaa_l_plugin_symdesc_cfg,
			      &azargs->get_authz_id)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "params",
			      gaa_l_plugin_param_cfg,
			      &azargs->param)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "sym_params",
			      gaa_l_plugin_symparam_cfg,
			      &azargs->param)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "freeparam",
			      gaa_l_plugin_symdesc_cfg,
			      &azargs->freeparam)) != GAA_S_SUCCESS)
	return(status);

    if (cffile == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    gaa_plugin_init_authz_id_args(azargs);
    if (tok = gaautil_gettok(next, &next))
    {
	if (strcmp(tok, "{") == 0)
	    firstbrace++;
	else
	{
	    gaacore_set_err("gaa_init: bad text after \"get_authz_identity\"");
	    return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));
	}
    }
    return(gaa_l_plugin_read_cfinfo(cfinfo, cffile, next, firstbrace));
}

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_plugin_parse_boolean()
 *
 *  @ingroup gaa_plugin_init_static
 * 
 * Reads yes/no/true/false args from a configuration file (sets result
 * to 1 if string is yes/true, 0 if string is no/false).  Called by
 * gaa_l_plugin_read_cfinfo().
 *
 * @param result
 *        output result to fill in.
 * @param str
 *        input string.
 *
 * @retval GAA_S_SUCCESS
 *         success
 * @retval GAA_S_INTERNAL_ERR
 *         result or str is null.
 * @retval GAA_S_CONFIG_ERR
 *         syntax error in string
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */
static gaa_status
gaa_l_plugin_parse_boolean(int *result, char *str)
{
    char *next = 0;
    char *tok;
    char ebuf[2048];

    if (result == 0 || str == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    
    if ((tok = gaautil_gettok(str, &next)) == 0)
	return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));

    if ((strcasecmp(tok, "yes") == 0 || strcasecmp(tok, "true") == 0) ||
	strcmp(tok, "1") == 0)
	*result = 1;
    else if ((strcasecmp(tok, "no") == 0 || strcasecmp(tok, "false") == 0) ||
	strcmp(tok, "0") == 0)
	*result = 0;
    else {
	snprintf(ebuf, sizeof(ebuf),
		 "gaa_init: unrecognized boolean value \"%s\"", tok);
	gaacore_set_err(ebuf);
	return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));
    }
    return(GAA_S_SUCCESS);
}

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_plugin_read_valinfo()
 *
 *  @ingroup gaa_plugin_init_static
 * 
 * Read valinfo args from a configuration file.  Called by
 * gaa_l_plugin_read_aiargs().
 *
 * @param viargs
 *        output args to fill in
 * @param cffile
 *        input config file
 * @param str
 *        input string (leftover text from other config-reading routines)
 *
 * @retval GAA_S_SUCCESS
 *         success
 * @retval GAA_S_CONFIG_ERR
 *         syntax error in valinfo entry.
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */
static gaa_status
gaa_l_plugin_read_valinfo(gaa_plugin_valinfo_args *viargs,
			  FILE *		   cffile,
			  char *		   str)
{
    char *				next = 0;
    char *				tok = 0;
    int					firstbrace = 0;
    gaa_status				status;
    gaa_l_plugin_cfg_info		cfinfo[DEF_CFINFO_SIZE];
    int					i = 0;

    i = 0;
    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "copyval",
			      gaa_l_plugin_symdesc_cfg,
			      &viargs->copyval)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "newval",
			      gaa_l_plugin_symdesc_cfg,
			      &viargs->newval)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "freeval",
			      gaa_l_plugin_symdesc_cfg,
			      &viargs->freeval)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
			      "val2str",
			      gaa_l_plugin_symdesc_cfg,
			      &viargs->val2str)) != GAA_S_SUCCESS)
	return(status);


    if (cffile == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    /*
     * Don't bother initializing viargs; this is only called from
     * gaa_l_plugin_read_aiargs, which will already have initialized
     * viargs for us.
     */
    if (tok = gaautil_gettok(next, &next))
    {
	if (strcmp(tok, "{") == 0)
	    firstbrace++;
	else
	{
	    gaacore_set_err("gaa_init: bad text after \"pvinfo\" or \"rvinfo\"");
	    return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));
	}
    }
    return(gaa_l_plugin_read_cfinfo(cfinfo, cffile, next, firstbrace));
}

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_plugin_read_cfinfo()
 *
 *  @ingroup gaa_plugin_init_static
 * 
 * Do the work of reading an entry from a configuration file.
 * Called by gaa_l_plugin_read_miargs(), gaa_l_plugin_read_ceargs(),
 * gaa_l_plugin_read_aiargs(), gaa_l_plugin_read_matchrights(),
 * gaa_l_plugin_read_getpolicy(), and gaa_l_plugin_read_valinfo().
 *
 * @param cfingo
 *        input/output config info
 * @param cffile
 *        input config file
 * @param str
 *        input string (leftover text from other config-reading routines)
 * @param firstbrace
 *        input: 1 if the opening brace of this entry has been read;
          0 otherwise
 *
 * @retval GAA_S_SUCCESS
 *         success
 * @retval GAA_S_INTERNAL_ERR
 *         cfinfo or cffile is null.
 * @retval GAA_S_CONFIG_ERR
 *         syntax error in entry.
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */
static gaa_status
gaa_l_plugin_read_cfinfo(gaa_l_plugin_cfg_info *cfinfo,
			 FILE *			cffile,
			 char *			str,
			 int			firstbrace)
{
    char *				next = 0;
    char *				tok = 0;
    char				buf[2048];
    char				ebuf[2048];
    gaa_status				status = GAA_S_SUCCESS;
    gaa_l_plugin_cfg_info *		cfi;
    int					found = 0;
    
    if (cfinfo == 0 || cffile == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));

    if (! firstbrace)
	if (tok = gaautil_gettok(str, &next))
	{
	if (strcmp(tok, "{") == 0)
		firstbrace++;
	    else
		return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));
	}
    
    while (fgets(buf, sizeof(buf), cffile))
    {
	if ((tok = gaautil_gettok(buf, &next)) == 0)
	    continue;
	if (strcmp(tok, "{") == 0)
	{
	    if (firstbrace)
		return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));
	    firstbrace++;
	    if ((tok = gaautil_gettok(next, &next)) == 0)
		continue;
	}
	else if (*tok == '}')
	    break;
	for (found = 0, cfi = cfinfo; cfi->name && ! found; cfi++)
	    if (strcmp(tok, cfi->name) == 0)
	    {
		found++;
		switch(cfi->type)
		{
		case gaa_l_plugin_symdesc_cfg:
		    if ((status = gaa_l_plugin_parse_symdesc((gaa_plugin_symbol_desc *)cfi->val, next)) != GAA_S_SUCCESS)
			return(status);
		    break;
		case gaa_l_plugin_param_cfg:
		    if ((status = gaa_l_plugin_parse_param((gaa_plugin_parameter *)cfi->val, next, GAA_PLUGIN_TEXT_PARAM)) != GAA_S_SUCCESS)
			return(status);
		    break;
		case gaa_l_plugin_symparam_cfg:
		    if ((status = gaa_l_plugin_parse_param((gaa_plugin_parameter *)cfi->val, next, GAA_PLUGIN_SYMBOLIC_PARAM)) != GAA_S_SUCCESS)
			return(status);
		    break;
		case gaa_l_plugin_boolean_cfg:
		    if ((status = gaa_l_plugin_parse_boolean((int *)cfi->val, next)) != GAA_S_SUCCESS)
			return(status);
		    break;
		case gaa_l_plugin_valinfo_cfg:
		    if ((status = gaa_l_plugin_read_valinfo((gaa_plugin_valinfo_args *)cfi->val, cffile, next)) != GAA_S_SUCCESS)
			return(status);
		    break;
		default:
		    return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
		}
	    }
	if (! found)
	{
	    snprintf(ebuf, sizeof(ebuf), "gaa_init: unrecognized token \"%s\"",
		     tok);
	    gaacore_set_err(ebuf);
	    return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));
	}
    }
    return(status);
}

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_plugin_parse_param()
 *
 *  @ingroup gaa_plugin_init_static
 * 
 * Translate a character string and parameter type into a gaa_plugin_parameter.
 * Called by gaa_l_plugin_read_cfinfo().
 *
 * @param param
 *        output param to fill in
 * @param str
 *        input string
 * @param type
 *        input parameter type
 *
 * @retval GAA_S_SUCCESS
 *         success
 * @retval GAA_S_INTERNAL_ERR
 *         param is null
 * @retval GAA_S_CONFIG_ERR
 *         bad parameter type.
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */
static gaa_status
gaa_l_plugin_parse_param(gaa_plugin_parameter *    param,
			 char *			   str,
			 gaa_plugin_parameter_type type)
{
    char *				s;
    gaa_status				status = GAA_S_SUCCESS;

    if (param == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    if (param->type != GAA_PLUGIN_NULL_PARAM)
    {
	gaacore_set_err("attempt to set more than one parameter for a callback");
	return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));
    }
    switch(type)
    {
    case GAA_PLUGIN_NULL_PARAM:
	param->value.val = 0;
	break;
    case GAA_PLUGIN_TEXT_PARAM:
	if (str)
	{
	    while (isspace(*str))	/* strip leading whitespace */
		str++;
	    if (*str != '\0')		/* strip trailing whitespace */
		for (s = strchr(str, '\n'); s && isspace(*s); s--)
		    *s = '\0';
	}
	if ((param->value.text = (char **)malloc(sizeof(char *))) == 0)
	    return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
	if (str && *str)
	{
	    if ((*(param->value.text) = strdup(str)) == 0)
		return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
	} else
	    *(param->value.text) = 0;
	param->type = type;
	break;
    case GAA_PLUGIN_SYMBOLIC_PARAM:
	if ((status = gaa_l_plugin_parse_symdesc(&param->value.symdesc,
						str)) == GAA_S_SUCCESS)
	    param->type = type;
	break;
    default:
	gaacore_set_err("bad parameter type");
	return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));
    }
    return(status);
}

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_plugin_parse_symdesc()
 *
 *  @ingroup gaa_plugin_init_static
 * 
 * Translate a character string and parameter type into a
 * gaa_plugin_symbol_desc.  Called by gaa_l_plugin_read_cfinfo()
 * and gaa_l_plugin_parse_param().
 *
 * @param symdesc
 *        output symdesc to fill in
 * @param str
 *        input string
 *
 * @retval GAA_S_SUCCESS
 *         success
 * @retval GAA_S_INTERNAL_ERR
 *         symdesc of string is null
 * @retval GAA_S_CONFIG_ERR
 *         syntax error in string.
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */
static gaa_status
gaa_l_plugin_parse_symdesc(gaa_plugin_symbol_desc *symdesc, char *str)
{
    char *libname;
    char *symname;
    char *next = 0;

    if (symdesc == 0 || str == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    
    if ((libname = gaautil_gettok(str, &next)) == 0)
	return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));

    if ((symname = gaautil_gettok(next, &next)) == 0)
	return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));

    if (strcmp(libname, "SELF") == 0)
	symdesc->libname = 0;
    else
	if ((symdesc->libname = strdup(libname)) == 0)
	    return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));

    if ((symdesc->symname = strdup(symname)) == 0)
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    return(GAA_S_SUCCESS);
}


#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_plugin_init_cfinfo()
 *
 *  @ingroup gaa_plugin_init_static
 * 
 * Initialize an entry in a gaa_l_plugin_cfg_info structure.
 * Called by the same functions that call gaa_l_plugin_read_cfinfo().
 *
 * @param cfinfo
 *        input/output cfinfo array
 * @param i
 *        input -- initialize the i-th element in the array
 * @param cfisize
 *        size of cfinfo array (actual size, not number of entries)
 * @param name
 *        entry name
 * @param type
 *        entry type
 * @param val
 *        entry value (address for gaa_l_plugin_read_cfinfo() to
 *        eventually fill in).
 *
 * @retval GAA_S_SUCCESS
 *         success
 * @retval GAA_S_INTERNAL_ERR
 *         i is too big for this size cfinfo array.
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */
static gaa_status
gaa_l_plugin_init_cfinfo(gaa_l_plugin_cfg_info * cfinfo,
			 int		         i,
			 int			 cfisize,
			 char *			 name,
			 gaa_l_plugin_cfg_type_t type,
			 void *			 val)
{
    if (i >= (cfisize / sizeof(gaa_l_plugin_cfg_info) - 1))
    {
	gaacore_set_err("gaa_l_plugin_init_cfinfo: cfinfo size too small");
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    }

    /* initialize this entry */
    cfinfo[i].name = name;
    cfinfo[i].type = type;
    cfinfo[i].val = val;

    /* zero out the next entry */
    i++;
    cfinfo[i].name = 0;
    cfinfo[i].type = gaa_l_plugin_unknown_cfg;
    cfinfo[i].val = 0;
    return(GAA_S_SUCCESS);
}


#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_plugin_read_mxargs()
 *
 *  @ingroup gaa_plugin_init_static
 * 
 * Read mutex args from a configuration file.  Called by gaa_init().
 *
 * @param mxargs
 *        output args to fill in
 * @param cffile
 *        input config file
 * @param str
 *        input string (leftover text from other config-reading routines)
 *
 * @retval GAA_S_SUCCESS
 *         success
 * @retval GAA_S_INTERNAL_ERR
 *         cffile or mxargs is null.
 * @retval GAA_S_CONFIG_ERR
 *         syntax error in mutex arg entry.
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */
static gaa_status
gaa_l_plugin_read_mxargs(gaa_plugin_mutex_args *mxargs,
			 FILE *			cffile,
			 char *			str)
{
    char *				next = 0;
    char *				tok = 0;
    int					firstbrace = 0;
    gaa_status				status;
    int					i = 0;
    gaa_l_plugin_cfg_info		cfinfo[DEF_CFINFO_SIZE];

    if (cffile == 0 || mxargs == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));

    i = 0;
    if ((status = (gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
					    "create",
					    gaa_l_plugin_symdesc_cfg,
					    &mxargs->create))) != GAA_S_SUCCESS)
	return(status);
    
	
    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
					   "destroy",
					   gaa_l_plugin_symdesc_cfg,
					   &mxargs->destroy)) != GAA_S_SUCCESS)
	return(status);
    if ((status =
	 gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
				  "lock",
				  gaa_l_plugin_symdesc_cfg,
				  &mxargs->lock)) != GAA_S_SUCCESS)
	return(status);
    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
					   "unlock",
					   gaa_l_plugin_symdesc_cfg,
					   &mxargs->unlock)) != GAA_S_SUCCESS)
	return(status);
    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
					   "tscreate",
					   gaa_l_plugin_symdesc_cfg,
					   &mxargs->tscreate)) != GAA_S_SUCCESS)
	return(status);
    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
					   "tsset",
					   gaa_l_plugin_symdesc_cfg,
					   &mxargs->tsset)) != GAA_S_SUCCESS)
	return(status);
    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
					   "tsget",
					   gaa_l_plugin_symdesc_cfg,
					   &mxargs->tsget)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
					   "params",
					   gaa_l_plugin_param_cfg,
					   &mxargs->param)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_init_cfinfo(cfinfo, i++, sizeof(cfinfo),
					   "sym_params",
					   gaa_l_plugin_symparam_cfg,
					   &mxargs->param)) != GAA_S_SUCCESS)
	return(status);

    gaa_plugin_init_mutex_args(mxargs);
    if (tok = gaautil_gettok(next, &next))
    {
	if (strcmp(tok, "{") == 0)
	    firstbrace++;
	else
	{
	    gaacore_set_err("gaa_init: bad text after \"mutex\"");
	    return(GAA_STATUS(GAA_S_CONFIG_ERR, 0));
	}
    }

    return(gaa_l_plugin_read_cfinfo(cfinfo, cffile, next, firstbrace));
}
