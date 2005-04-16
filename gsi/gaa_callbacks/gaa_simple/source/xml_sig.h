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

#ifndef XML_SIG_H
#define XML_SIG_H

extern gaa_status
gaa_simple_i_verify_xml_sig(xmlDocPtr doc);
extern int
gaa_simple_i_xml_sig_ok(xmlDocPtr doc, char *errbuf, int errbuflen);
extern gaa_status
gaa_simple_i_find_signer(xmlDocPtr doc, char **signer, char *errbuf, int errbuflen);
#endif /* XML_SIG_H */
