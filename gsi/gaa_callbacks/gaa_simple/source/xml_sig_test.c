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

#include <libxml/parser.h>
#define USAGE "Usage: %s xmlfile\n"

main(int argc, char **argv)
{
    char errbuf[2048];
    xmlDocPtr doc;

    errbuf[0] = '\0';

    if (argc < 2) {
	fprintf(stderr, USAGE, argv[0]);
	exit(1);
    }
    xmlInitParser();
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);

    doc = xmlParseFile(argv[1]);

    if (gaa_simple_i_xml_sig_ok(doc, errbuf, sizeof(errbuf))) {
	printf("signature is okay\n");
    } else {
	printf("signature is bad\n");
    }
}
