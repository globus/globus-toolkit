/* 
 * globusfile.h
 */


#ifndef GLOBUSFILE_H_
#define GLOBUSFILE_H_

#include "gssapi.h"                    /* for gss_buffer_t etc. */
#include "gssapi_ssleay.h"             /* for tis_gss_ret_t */

tis_gss_ret_t
retrieve_globusid
(gss_name_desc** globusid) ;

#endif /* GLOBUSFILE_H_ */
