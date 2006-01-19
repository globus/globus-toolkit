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
