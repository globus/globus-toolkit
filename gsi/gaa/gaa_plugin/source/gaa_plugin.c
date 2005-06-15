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
#ifndef WIN32
#include <ltdl.h>
#else
#include <globus_libtool_windows.h>
#endif
#include "gaa.h"
#include "gaa_util.h"
#include "gaa_plugin.h"
#include "gaa_plugin_private.h"

/* GAA Flavor Name == Globus Flavor Name */
#ifdef WIN32
/* ToDo: A Hack To Get It To Build! Fix This */
#define GAA_FLAVOR_NAME "win32dbgmtdthr"
#endif


/** @defgroup gaa_plugin "gaa plugin implementation"
 */
/** @defgroup gaa_plugin_static "gaa plugin static functions"
 */

/* use libtool_mutex to lock all calls to libtdl routines */
void *                          libtool_mutex = 0;

static gaa_status
gaa_l_plugin_find_symbol(lt_ptr *		 sym,
			 gaa_plugin_symbol_desc *symdesc);

static gaa_status
gaa_l_plugin_param_value(void **	       val,
			 gaa_plugin_parameter *param);

static gaa_status
gaa_l_plugin_parse_valinfo(gaa_valinfo_ptr *	    valinfo,
			   gaa_plugin_valinfo_args *viargs);


struct gaa_l_plugin_subst_t
{
    char label;
    char *value;
};

static gaa_status
gaa_l_plugin_expand_name(char *				inname,
			 char *				outname,
			 int				outnamesize,
			 const struct gaa_l_plugin_subst_t *	substitutions);


static const struct gaa_l_plugin_subst_t substitutions[] =
{
    {'f', GAA_FLAVOR_NAME},
    {0, 0},
};


static gaa_status
gaa_l_plugin_init_mutex();

/** gaa_plugin_add_libdir()
 *
 *  @ingroup gaa_plugin
 *
 *  Add a directory to the library search path used to find GAA
 *  plugin functions.
 *
 * @param libdir
 *        input directory name.
 *
 * @retval GAA_S_SUCCESS
 *         success
 */
gaa_status
gaa_plugin_add_libdir(char *		libdir)
{
    int					err;
    gaa_status				status;
    char				tlibdir[8192];

    /* always lock firstent with libtool_mutex */
    static int				firstent = 1;
    
    if (libdir == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));

    if ((status = gaa_l_plugin_init_mutex()) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_expand_name(libdir, tlibdir, sizeof(tlibdir),
					   substitutions)) != GAA_S_SUCCESS)
	return(status);
    gaacore_mutex_lock(libtool_mutex);
    if (firstent)
	err = lt_dlsetsearchpath(tlibdir);
    else
	err = lt_dladdsearchdir(tlibdir);
    firstent = 0;
    gaacore_mutex_unlock(libtool_mutex);
    return(err ? GAA_STATUS(GAA_S_SYSTEM_ERR, 0) : GAA_S_SUCCESS);
}

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_i_plugin_init_libtool()
 *
 *  Called by gaa_init() to initialize libltdl.
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_SYSTEM_ERR
 *          lt_dlinit failed.
 */
#endif /* DOCUMENT_INTERNAL_FUNCTIONS */
gaa_status
gaa_i_plugin_init_libtool()
{
    int err;
    char ebuf[2048];
    const char *s;
    gaa_status status;

    if ((status = gaa_l_plugin_init_mutex()) != GAA_S_SUCCESS)
	return(status);

    gaacore_mutex_lock(libtool_mutex);
    err = lt_dlinit();
    gaacore_mutex_unlock(libtool_mutex);
    if (err) {
	snprintf(ebuf, sizeof(ebuf), "gaa_init: lt_dlinit failed: %s",
		 ((s = lt_dlerror()) ? s : ""));
	gaacore_set_err(ebuf);
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    }
    return(GAA_S_SUCCESS);
}

/** gaa_plugin_install_mechinfo()
 *
 *  @ingroup gaa_plugin
 *
 *  Find the appropriate dynamically-linked mechinfo routines and
 *  parameters, and call gaa_add_mech_info() to install the callback.
 *
 *  @param gaa
 *         input/output gaa pointer
 *  @param miargs
 *         input mechinfo args to install.
 * 
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          One of gaa, miargs, or miargs->mech_type was null.
 */
gaa_status
gaa_plugin_install_mechinfo(gaa_ptr		      gaa,
			    gaa_plugin_mechinfo_args *miargs)
{
    gaa_cred_pull_func			cred_pull = 0;
    gaa_cred_eval_func			cred_eval = 0;
    gaa_cred_verify_func		cred_verify = 0;
    gaa_freefunc			cred_free = 0;
    gaa_freefunc			freeparam = 0;
    void *				param = 0;
    gaa_status				status;

    if (gaa == 0 || miargs == 0 || miargs->mech_type == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    if ((status =
	 gaa_l_plugin_find_symbol((lt_ptr *)&cred_pull,
				  &miargs->cred_pull)) != GAA_S_SUCCESS)
	return(status);
    if ((status =
	 gaa_l_plugin_find_symbol((lt_ptr *)&cred_eval,
				  &miargs->cred_eval)) != GAA_S_SUCCESS)
	return(status);
    if ((status =
	 gaa_l_plugin_find_symbol((lt_ptr *)&cred_verify,
				  &miargs->cred_verify)) != GAA_S_SUCCESS)
	return(status);
    if ((status =
	 gaa_l_plugin_find_symbol((lt_ptr *)&cred_free,
				  &miargs->cred_free)) != GAA_S_SUCCESS)
	return(status);
    if ((status =
	 gaa_l_plugin_find_symbol((lt_ptr *)&freeparam,
				  &miargs->freeparam)) != GAA_S_SUCCESS)
	return(status);
    if ((status =
	 gaa_l_plugin_param_value(&param, &miargs->param)) != GAA_S_SUCCESS)
	return(status);
    return(gaa_add_mech_info(gaa, miargs->mech_type,
			     cred_pull, cred_eval, cred_verify,
			     cred_free, param,
			     freeparam));
}

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_plugin_find_symbol()
 *
 *  @ingroup gaa_plugin_static
 *
 *  Find a symbol in the appropriate shared library.  Looks up
 *  symdesc->symname in symdesc->libname (or in the calling program,
 *  if symdesc->libname is null).
 *
 *  Called by gaa_plugin_install_mechinfo(), gaa_plugin_install_cond_eval(),
 *  gaa_l_plugin_param_value(), gaa_l_plugin_install_authinfo(),
 *  gaa_l_plugin_parse_valinfo(), gaa_plugin_install_matchrights(),
 *  and gaa_plugin_install_getpolicy().
 *
 *  @param sym
 *         output symbol
 *  @param symdesc
 *         input symbol description to look up.
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INTERNAL_ERR
 *          sym or symdesc was null
 *  @retval GAA_S_INVALID_ARG
 *          symdesc had a null symbol name but a non-null library name.
 *  @retval GAA_S_SYSTEM_ERR
 *          one of the dl routines failed.
 */
#endif  /* DOCUMENT_INTERNAL_FUNCTIONS */
static gaa_status
gaa_l_plugin_find_symbol(lt_ptr *		 sym,
			 gaa_plugin_symbol_desc *symdesc)
{
    lt_dlhandle				dlh;
    char				errstr[8192];
    char				libname[8192];
    const char *			s;
    gaa_status				status;

    if ((status = gaa_l_plugin_init_mutex()) != GAA_S_SUCCESS)
	return(status);

    if (sym == 0 || symdesc == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    if (symdesc->symname == 0)
    {
	if (symdesc->libname == 0)
	    return(GAA_S_SUCCESS); /* nothing to do */
	else
	    return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    }
    if ((status = gaa_l_plugin_expand_name(symdesc->libname, libname,
					   sizeof(libname),
					   substitutions)) != GAA_S_SUCCESS)
	return(status);
    gaacore_mutex_lock(libtool_mutex);
    dlh = lt_dlopen(libname);
    gaacore_mutex_unlock(libtool_mutex);
    if (dlh == 0)
    {
	snprintf(errstr, sizeof(errstr),
		 "gaa_l_plugin_find_symbol: couldn't dlopen %s: %s",
		 (libname ? libname : "(self)"),
		 ((s = lt_dlerror()) ? s : ""));
	gaacore_set_err(errstr);
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    }
    gaacore_mutex_lock(libtool_mutex);
    *sym = lt_dlsym(dlh, symdesc->symname);
    gaacore_mutex_unlock(libtool_mutex);
    if (*sym == 0)
    {
	snprintf(errstr, sizeof(errstr),
		 "gaa_l_plugin_find_symbol: couldn't find symbol %s in %s: %s",
		 symdesc->symname,
		 (libname ? libname : "(self)"),
		 ((s = lt_dlerror()) ? s : ""));
	gaacore_set_err(errstr);
	return(GAA_STATUS(GAA_S_SYSTEM_ERR, 0));
    }
    return(GAA_S_SUCCESS);
}

/** gaa_plugin_install_cond_eval()
 *
 *  @ingroup gaa_plugin
 *
 *  Find the appropriate dynamically-linked condition evaluation routines
 *  and parameters, and call gaa_add_cond_eval_callback() to install
 *  the callback.
 *
 *  @param gaa
 *         input/output gaa pointer
 *  @param ceargs
 *         input cond_eval args to install.
 * 
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          One of gaa, or ceargs is null
 */
gaa_status
gaa_plugin_install_cond_eval(gaa_ptr		        gaa,
			     gaa_plugin_cond_eval_args *ceargs)
{
    gaa_cond_eval_func			cond_eval = 0;
    gaa_freefunc			freeparam = 0;
    gaa_cond_eval_callback_ptr		callback = 0;
    void *				param;
    gaa_status				status;

    if (gaa == 0 || ceargs == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));

    if ((status =
	 gaa_l_plugin_find_symbol((lt_ptr *)&cond_eval,
				  &ceargs->cond_eval)) != GAA_S_SUCCESS)
	return(status);

    if ((status =
	 gaa_l_plugin_find_symbol((lt_ptr *)&freeparam,
				  &ceargs->freeparam)) != GAA_S_SUCCESS)
	return(status);

    if ((status =
	 gaa_l_plugin_param_value(&param, &ceargs->param)) != GAA_S_SUCCESS)
	return(status);
    if ((status =
	 gaa_new_cond_eval_callback(&callback, cond_eval, param,
				    freeparam)) != GAA_S_SUCCESS)
	return(status);
    return(gaa_add_cond_eval_callback(gaa, callback,
				      ceargs->cond_type,
				      ceargs->cond_authority,
				      ceargs->is_idcred));
}

/** gaa_plugin_init_mechinfo_args()
 *
 *  @ingroup gaa_plugin
 *
 *  Initializes mechinfo args to default values.
 *
 *  @param miargs
 *         input/output mechinfo args.
 * 
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          miargs is null
 */
gaa_status
gaa_plugin_init_mechinfo_args(gaa_plugin_mechinfo_args *miargs)
{
    if (miargs == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));

    memset(miargs, 0, sizeof(gaa_plugin_mechinfo_args));
    gaa_plugin_init_param(&miargs->param);
    return(GAA_S_SUCCESS);
}

/** gaa_plugin_init_cond_eval_args()
 *
 *  @ingroup gaa_plugin
 *
 *  Initializes cond_eval args to default values.
 *
 *  @param ceargs
 *         input/output cond_eval args.
 * 
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          ceargs is null
 */
gaa_status
gaa_plugin_init_cond_eval_args(gaa_plugin_cond_eval_args *ceargs)
{
    if (ceargs == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));

    memset(ceargs, 0, sizeof(gaa_plugin_cond_eval_args));
    gaa_plugin_init_param(&ceargs->param);
    return(GAA_S_SUCCESS);
}

/** gaa_plugin_init_param()
 *
 *  @ingroup gaa_plugin
 *
 *  Initializes parameter args to default values.
 *
 *  @param param
 *         input/output parameter.
 * 
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          param is null
 */
gaa_status
gaa_plugin_init_param(gaa_plugin_parameter *param)
{
    if (param == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    memset(param, 0, sizeof(gaa_plugin_parameter));
    param->type = GAA_PLUGIN_NULL_PARAM;
    return(GAA_S_SUCCESS);
}

#ifdef DOCUMENT_INTERNAL_FUNCTIONS
/** gaa_l_plugin_param_value()
 *
 *  @ingroup gaa_plugin_static
 *
 *  Finds the value of a gaa_plugin_parameter.
 *
 *  Called by gaa_plugin_install_mechinfo(), gaa_plugin_install_cond_eval(),
 *  gaa_l_plugin_install_authinfo(), gaa_plugin_install_matchrights(),
 *  and gaa_plugin_install_getpolicy().
 *
 *  @param val
 *         output value
 *  @param param
 *         input plugin parameter
 *
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INTERNAL_ERR
 *          val or param is nll
 *  @retval GAA_S_INVALID_ARG
 *          unknown parameter type.
 */
#endif  /* DOCUMENT_INTERNAL_FUNCTIONS */
static gaa_status
gaa_l_plugin_param_value(void **	       val,
			 gaa_plugin_parameter *param)
{
    gaa_status				status = GAA_S_SUCCESS;

    if (val == 0 || param == 0)
	return(GAA_STATUS(GAA_S_INTERNAL_ERR, 0));
    switch(param->type)
    {
    case GAA_PLUGIN_NULL_PARAM:
	*val = 0;
	break;
    case GAA_PLUGIN_TEXT_PARAM:
	*val = param->value.text;
	break;
    case GAA_PLUGIN_SYMBOLIC_PARAM:
	status = gaa_l_plugin_find_symbol((lt_ptr)val, &param->value.symdesc);
	break;
    case GAA_PLUGIN_VALUE_PARAM:
	*val = param->value.val;
	break;
    default:
	gaacore_set_err("unknown parameter type");
	status = GAA_STATUS(GAA_S_INVALID_ARG, 0);
    }
    return(status);
}

/** gaa_plugin_install_authinfo()
 *
 *  @ingroup gaa_plugin
 *
 *  Find the appropriate dynamically-linked authinfo routines and
 *  parameters, and call gaa_add_authinfo() to install the callback.
 *
 *  @param gaa
 *         input/output gaa pointer
 *  @param aiargs
 *         input authinfo args to install.
 * 
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          One of gaa, or aiargs was null.
 */
gaa_status
gaa_plugin_install_authinfo(gaa_ptr	              gaa,
			    gaa_plugin_authinfo_args *aiargs)
{
    gaa_status				status;
    gaa_valinfo_ptr			pvinfo = 0;
    gaa_valinfo_ptr			rvinfo = 0;
    gaa_valmatch_func			valmatch = 0;
    void *				param = 0;
    gaa_freefunc			freeparam = 0;

    if (gaa == 0 || aiargs == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));

    if ((status = gaa_l_plugin_parse_valinfo(&pvinfo,
					    &aiargs->pvinfo)) != GAA_S_SUCCESS)
	return(status);

    if ((status = gaa_l_plugin_parse_valinfo(&rvinfo,
					    &aiargs->rvinfo)) != GAA_S_SUCCESS)
	return(status);
    if ((status = gaa_l_plugin_find_symbol((lt_ptr *)&valmatch,
					  &aiargs->valmatch)) != GAA_S_SUCCESS)
	return(status);
    if ((status = gaa_l_plugin_param_value(&param,
					  &aiargs->param)) != GAA_S_SUCCESS)
	return(status);
    if ((status =
	 gaa_l_plugin_find_symbol((lt_ptr *)&freeparam,
				  &aiargs->freeparam)) != GAA_S_SUCCESS)
	return(status);
    return(gaa_add_authinfo(gaa, aiargs->authority, pvinfo, rvinfo, valmatch,
			    param, freeparam));
}

/** gaa_plugin_parse_valinfo()
 *
 *  @ingroup gaa_plugin
 *
 *  Find the appropriate dynamically-linked valinfo routines, and
 *  call gaa_new_valinfo() to create a new valinfo.
 *
 *  Called by gaa_plugin_install_authinfo().
 *
 *  @param valinfo
 *         output valinfo pointer.
 *  @param viargs
 *         input valinfo args to parse.
 * 
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          One of gaa, or aiargs was null.
 */
static gaa_status
gaa_l_plugin_parse_valinfo(gaa_valinfo_ptr *	    valinfo,
			   gaa_plugin_valinfo_args *viargs)
{
    gaa_status				status;
    gaa_copyval_func			copyval = 0;
    gaa_string2val_func			newval = 0;
    gaa_freefunc			freeval = 0;
    gaa_val2string_func			val2str = 0;

    if (valinfo == 0 || viargs == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));

    if ((status = gaa_l_plugin_find_symbol((lt_ptr *)&copyval,
					  &viargs->copyval)) != GAA_S_SUCCESS)
	return(status);
    if ((status = gaa_l_plugin_find_symbol((lt_ptr *)&newval,
					  &viargs->newval)) != GAA_S_SUCCESS)
	return(status);
    if ((status = gaa_l_plugin_find_symbol((lt_ptr *)&freeval,
					  &viargs->freeval)) != GAA_S_SUCCESS)
	return(status);
    if ((status = gaa_l_plugin_find_symbol((lt_ptr *)&val2str,
					  &viargs->val2str)) != GAA_S_SUCCESS)
	return(status);
    return(gaa_new_valinfo(valinfo, copyval, newval, freeval, val2str));
}


/** gaa_plugin_init_authinfo_args()
 *
 *  @ingroup gaa_plugin
 *
 *  Initializes authinfo args to default values.
 *
 *  @param aiargs
 *         input/output authinfo args.
 * 
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          aiargs is null
 */
gaa_status
gaa_plugin_init_authinfo_args(gaa_plugin_authinfo_args *aiargs)
{
    if (aiargs == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));

    memset(aiargs, 0, sizeof(gaa_plugin_authinfo_args));
    return(GAA_S_SUCCESS);
}

/** gaa_plugin_init_matchrights_args()
 *
 *  @ingroup gaa_plugin
 *
 *  Initializes matchrights args to default values.
 *
 *  @param args
 *         input/output matchrights args.
 * 
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          args is null
 */
gaa_status
gaa_plugin_init_matchrights_args(gaa_plugin_matchrights_args *args)
{
    if (args == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    memset(args, 0, sizeof(gaa_plugin_matchrights_args));
    return(GAA_S_SUCCESS);
}

/** gaa_plugin_init_getpolicy_args()
 *
 *  @ingroup gaa_plugin
 *
 *  Initializes getpolicy args to default values.
 *
 *  @param args
 *         input/output getpolicy args.
 * 
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          args is null
 */
gaa_status
gaa_plugin_init_getpolicy_args(gaa_plugin_getpolicy_args *args)
{
    if (args == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    memset(args, 0, sizeof(gaa_plugin_getpolicy_args));
    return(GAA_S_SUCCESS);
}

/** gaa_plugin_init_authz_id_args()
 *
 *  @ingroup gaa_plugin
 *
 *  Initializes getpolicy args to default values.
 *
 *  @param args
 *         input/output getpolicy args.
 * 
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          args is null
 */
gaa_status
gaa_plugin_init_authz_id_args(gaa_plugin_authz_id_args *args)
{
    if (args == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    memset(args, 0, sizeof(gaa_plugin_authz_id_args));
    return(GAA_S_SUCCESS);
}

/** gaa_plugin_install_matchrights()
 *
 *  @ingroup gaa_plugin
 *
 *  Find the appropriate dynamically-linked matchrights routines
 *  and parameters, and call gaa_set_matchrights_callback() to install
 *  the callback.
 *
 *  @param gaa
 *         input/output gaa pointer
 *  @param mrargs
 *         input matchrights args to install.
 * 
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          One of gaa or mrargs is null
 */
gaa_status
gaa_plugin_install_matchrights(gaa_ptr			    gaa,
			       gaa_plugin_matchrights_args *mrargs)
{
    gaa_status				status;
    gaa_matchrights_func		matchrights = 0;
    void *				param = 0;
    gaa_freefunc			freeparam = 0;

    if (gaa == 0 || mrargs == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));

    if ((status =
	 gaa_l_plugin_find_symbol((lt_ptr *)&matchrights,
				  &mrargs->matchrights)) != GAA_S_SUCCESS)
	return(status);
    if ((status =
	 gaa_l_plugin_param_value(&param,
				  &mrargs->param)) != GAA_S_SUCCESS)
	return(status);
    if ((status =
	 gaa_l_plugin_find_symbol((lt_ptr *)&freeparam,
				  &mrargs->freeparam)) != GAA_S_SUCCESS)
	return(status);
    return(gaa_set_matchrights_callback(gaa, matchrights, param, freeparam));
}


/** gaa_plugin_install_getpolicy()
 *
 *  @ingroup gaa_plugin
 *
 *  Find the appropriate dynamically-linked getpolicy routines
 *  and parameters, and call gaa_set_getpolicy_callback() to install
 *  the callback.
 *
 *  @param gaa
 *         input/output gaa pointer
 *  @param gpargs
 *         input getpolicy args to install.
 * 
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          One of gaa or gpargs is null
 */
gaa_status
gaa_plugin_install_getpolicy(gaa_ptr		        gaa,
			     gaa_plugin_getpolicy_args *gpargs)
{
    gaa_status				status;
    gaa_getpolicy_func			getpolicy = 0;
    void *				param = 0;
    gaa_freefunc			freeparam = 0;

    if (gaa == 0 || gpargs == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));

    if ((status =
	 gaa_l_plugin_find_symbol((lt_ptr *)&getpolicy,
				  &gpargs->getpolicy)) != GAA_S_SUCCESS)
	return(status);
    if ((status =
	 gaa_l_plugin_param_value(&param,
				  &gpargs->param)) != GAA_S_SUCCESS)
	return(status);
    if ((status =
	 gaa_l_plugin_find_symbol((lt_ptr *)&freeparam,
				  &gpargs->freeparam)) != GAA_S_SUCCESS)
	return(status);
    return(gaa_set_getpolicy_callback(gaa, getpolicy, param, freeparam));
}

/** gaa_plugin_install_getpolicy()
 *
 *  @ingroup gaa_plugin
 *
 *  Find the appropriate dynamically-linked getpolicy routines
 *  and parameters, and call gaa_set_getpolicy_callback() to install
 *  the callback.
 *
 *  @param gaa
 *         input/output gaa pointer
 *  @param gpargs
 *         input getpolicy args to install.
 * 
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          One of gaa or gpargs is null
 */
gaa_status
gaa_plugin_install_authz_id(gaa_ptr		        gaa,
			     gaa_plugin_authz_id_args *gpargs)
{
    gaa_status					status;
    gaa_x_get_authorization_identity_func	authz_id_func = 0;
    void *					param = 0;
    gaa_freefunc				freeparam = 0;

    if (gaa == 0 || gpargs == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));

    if ((status =
	 gaa_l_plugin_find_symbol((lt_ptr *)&authz_id_func,
				  &gpargs->get_authz_id)) != GAA_S_SUCCESS)
	return(status);
    if ((status =
	 gaa_l_plugin_param_value(&param,
				  &gpargs->param)) != GAA_S_SUCCESS)
	return(status);
    if ((status =
	 gaa_l_plugin_find_symbol((lt_ptr *)&freeparam,
				  &gpargs->freeparam)) != GAA_S_SUCCESS)
	return(status);
    return(gaa_x_set_get_authorization_identity_callback(gaa, authz_id_func, param, freeparam));
}

static gaa_status
gaa_l_plugin_init_mutex()
{
    if (libtool_mutex == 0)
	return(gaacore_mutex_create(&libtool_mutex));
    return(GAA_S_SUCCESS);
}

/** gaa_plugin_install_mutex_callbacks()
 *
 *  @ingroup gaa_plugin
 *
 *  Find the appropriate dynamically-linked mechinfo routines and
 *  parameters, and call gaa_add_mech_info() to install the callback.
 *
 *  @param gaa
 *         input/output gaa pointer
 *  @param mxargs
 *         input mutex callback args to install.
 * 
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          One of gaa or mxargs was null.
 */
gaa_status
gaa_plugin_install_mutex_callbacks(gaa_plugin_mutex_args *mxargs)
{
    gaacore_mutex_create_func		create = 0;
    gaacore_mutex_destroy_func 		destroy = 0;
    gaacore_mutex_lock_func 		lock = 0;
    gaacore_mutex_unlock_func		unlock = 0;
    gaacore_tsdata_create_func		tscreate = 0;
    gaacore_tsdata_setspecific_func	tsset = 0;
    gaacore_tsdata_getspecific_func	tsget = 0;
    void *				param = 0;
    gaa_status				status;

    if (mxargs == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));
    if ((status =
	 gaa_l_plugin_find_symbol((lt_ptr *)&create,
				  &mxargs->create)) != GAA_S_SUCCESS)
	return(status);
    if ((status =
	 gaa_l_plugin_find_symbol((lt_ptr *)&destroy,
				  &mxargs->destroy)) != GAA_S_SUCCESS)
	return(status);
    if ((status =
	 gaa_l_plugin_find_symbol((lt_ptr *)&lock,
				  &mxargs->lock)) != GAA_S_SUCCESS)
	return(status);
    if ((status =
	 gaa_l_plugin_find_symbol((lt_ptr *)&unlock,
				  &mxargs->unlock)) != GAA_S_SUCCESS)
	return(status);
    if ((status =
	 gaa_l_plugin_find_symbol((lt_ptr *)&tscreate,
				  &mxargs->tscreate)) != GAA_S_SUCCESS)
	return(status);
    if ((status =
	 gaa_l_plugin_find_symbol((lt_ptr *)&tsset,
				  &mxargs->tsset)) != GAA_S_SUCCESS)
	return(status);
    if ((status =
	 gaa_l_plugin_find_symbol((lt_ptr *)&tsget,
				  &mxargs->tsget)) != GAA_S_SUCCESS)
	return(status);
    if ((status =
	 gaa_l_plugin_param_value(&param, &mxargs->param)) != GAA_S_SUCCESS)
	return(status);

    return(gaacore_set_mutex_callback(create, destroy, lock, unlock,
				      tscreate, tsset, tsget, param));
}

/** gaa_plugin_init_mutex_args()
 *
 *  @ingroup gaa_plugin
 *
 *  Initializes mutex args to default values.
 *
 *  @param mxargs
 *         input/output mutex args.
 * 
 *  @retval GAA_S_SUCCESS
 *          success
 *  @retval GAA_S_INVALID_ARG
 *          mxargs is null
 */
gaa_status
gaa_plugin_init_mutex_args(gaa_plugin_mutex_args *mxargs)
{
    if (mxargs == 0)
	return(GAA_STATUS(GAA_S_INVALID_ARG, 0));

    memset(mxargs, 0, sizeof(gaa_plugin_mutex_args));
    gaa_plugin_init_param(&mxargs->param);
    return(GAA_S_SUCCESS);
}

char *
gaa_x_majstat_str(gaa_status status)
{
    return(gaacore_majstat_str(status));
}

void
gaa_cleanup(gaa_ptr		gaa,
	    void *		params)
{
    gaa_free_gaa(gaa);
}

static gaa_status
gaa_l_plugin_expand_name(char *				inname,
			 char *				outname,
			 int				outnamesize,
			 const struct gaa_l_plugin_subst_t *	substitutions)
{
    char *in;
    char *out;
    int i;
    char *val;
    char c;
    int found;
    char errstr[2048];

    if (inname == 0)
	return GAA_S_SUCCESS;
    if (outname == 0)
	return(GAA_S_INTERNAL_ERR);

    if (substitutions == 0)
	for (in = inname, out = outname; *in && (outnamesize > 1); in++, out++)
	{
	    *out = *in;
	    outnamesize--;
	}
    else
	for (in = inname, out = outname; *in && (outnamesize > 1); in++)
	{
	    found = 0;
	    if (*in == '$')
	    {
		for (i = 0; substitutions[i].label && ! found; i++)
		    if (*(in+1) == substitutions[i].label)
		    {
			found = 1;
			in++;
			for (val = substitutions[i].value;
			     *val && (outnamesize > 1);
			     val++, out++)
			{
			    *out = *val;
			    outnamesize--;
			}
			
		    }
	    }
	    if (! found)
	    {
		*out++ = *in;
		outnamesize--;
	    }
	}
    if (outnamesize > 0)
    {
	*out = '\0';
	return(GAA_S_SUCCESS);
    }
    else
    {
	strcpy(errstr, "gaa_l_plugin_expand_name: name too long");
	gaacore_set_err(errstr);
	return(GAA_S_INTERNAL_ERR);
    }
}
