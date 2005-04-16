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
#include <proxycertinfo.h>
#include <proxypolicy.h>
#include <string.h>
#include <openssl/pem.h>

void usage();

int main(int argc, char * argv[]) 
{
    char * plstring;
    char * pllang;
    char * filename;
    char * out_filename;

    FILE * instream;

    PROXYPOLICY * rst;
    PROXYCERTINFO * pcinfo;
    ASN1_OBJECT * pol_lang;

    int haspclength, haspolicy, pclength;
    int ind, from_file, to_file;

    from_file = to_file = haspclength = haspolicy = pclength = 0;

    if(argc > 1)
    {	
	ind = 1;
	while(ind < argc) 
	{
            if(!strcmp(argv[ind], "-path"))
	    {
		ind++;
		pclength = atoi(argv[ind]);
		haspclength = 1;
		ind++;
                continue;
	    }
	    else if(!strcmp(argv[ind], "-rest"))
	    {
		ind++;
		pllang = argv[ind];
		haspolicy = 1;
		ind++;
		plstring = argv[ind];
		ind++;
                continue;
	    }
	    else if(!strcmp(argv[ind], "-in"))
	    {
		ind++;
		from_file = 1;
		filename = argv[ind];
		ind++;
                continue;
	    }
            else if(!strcmp(argv[ind], "-out"))
            {
                ind++;
                to_file = 1;
                out_filename = argv[ind];
                ind++;
                continue;
            }
	    else
	    {
                usage();
	    }
	}
    }

    if(from_file)
    {
	pcinfo = PROXYCERTINFO_new();
	instream = fopen(filename, "r");
	ASN1_d2i_fp((char *(*)()) PROXYCERTINFO_new, 
		    (char *(*)()) d2i_PROXYCERTINFO, 
		    instream, 
		    (unsigned char **) &pcinfo);

	PROXYCERTINFO_print_fp(stdout, pcinfo);
	
        if(to_file)
        {
            FILE * outstream = fopen(out_filename, "w");
            if(!ASN1_i2d_fp(i2d_PROXYCERTINFO, 
                            outstream, 
                            (unsigned char *)pcinfo))
            {
                fprintf(stderr, 
                        "Could not print the proxy cert info struct\n");
            }
            fclose(outstream);
        }
            
	fclose(instream);
    }
    else
    {
	pcinfo = PROXYCERTINFO_new();
	
	if(haspclength)
	{
	    PROXYCERTINFO_set_path_length(pcinfo, pclength);
	}

	if(haspolicy)
	{
	    rst = PROXYPOLICY_new();
	    PROXYPOLICY_set_policy(rst, plstring, strlen(plstring));
	    pol_lang = ASN1_OBJECT_new();
	    pol_lang->sn = pllang;
	    pol_lang->ln = pllang;
	    pol_lang->data = pllang;
	    pol_lang->length = strlen(pllang);
	    pol_lang->flags = 0;
            PROXYPOLICY_set_policy_language(rst, pol_lang);
            PROXYCERTINFO_set_policy(pcinfo, rst);
	}

	PROXYCERTINFO_print_fp(stdout, pcinfo);

        if(to_file)
        {
            FILE * outstream = fopen(out_filename, "w");
            if(!ASN1_i2d_fp(i2d_PROXYCERTINFO, 
                            outstream, 
                            (unsigned char *)pcinfo))
            {
                fprintf(stderr, 
                        "Could not print the proxy cert info struct\n");
            }
            fclose(outstream);
        }
    }

    PROXYCERTINFO_free(pcinfo);

    return 0;
}

void usage()
{
    fprintf(stderr, 
            "\nSyntax: test_pci [-help][-pc] ... \\\n\n"
            "  -help\n      Displays usage information\n\n"
            "  -path  <path length>\n      Sets the path length "
            "of the proxy cert info,\n      otherwise "
            "no max length exists\n\n"
            "  -rest  <language> <policy>\n"
            "      adds a policy to the proxy cert info\n"
            "      and sets the policy language and\n"
            "      and policy string\n\n"
            "  -in  <proxycertfile>\n"
            "      takes a DER encoded proxy cert info and prints\n"
            "      it out to stderr.  This flag causes all other\n"
            "      flags to be ignored\n\n"
            "  -out <proxycertfile>\n"
            "      outputs the DER encoded form of the proxy cert info\n\n");
    exit(1);
}
