
#include <stdio.h>
#include <proxycertinfo.h>
#include <proxyrestriction.h>
#include <proxygroup.h>
#include <string.h>
#include <openssl/pem.h>

void usage();

int main(int argc, char * argv[]) 
{

    char * grpname;
    char * plstring;
    char * pllang;
    char * filename;
    char * out_filename;
    char * x509file;

    FILE * instream;
    FILE * x509stream;


    PROXYRESTRICTION * rst;
    PROXYGROUP * grp;
    PROXYCERTINFO * pcinfo;
    ASN1_OBJECT * pol_lang;
    X509 * my_x509;
    X509_SIG * signature;

    int ispc, haspclength, hasgroup, hasrestriction, hasissuer,
	pclength, grpatt, ind, from_file, to_file, version;

    from_file = to_file = haspclength = hasgroup = hasissuer =
	        hasrestriction = pclength = 0;
    version = 1;
    ispc = 1;

    if(argc > 1)
    {	
	ind = 1;
	while(ind < argc) 
	{
	    if(!strcmp(argv[ind], "-pc"))
	    {
		ind++;
                ispc = atoi(argv[ind]);
                ind++;
                continue;
	    }
	    else if(!strcmp(argv[ind], "-path"))
	    {
		ind++;
		pclength = atoi(argv[ind]);
		haspclength = 1;
		ind++;
                continue;
	    }
            else if(!strcmp(argv[ind], "-version"))
            {
                ind++;
                version = atoi(argv[ind]);
                ind++;
                continue;
            }
	    else if(!strcmp(argv[ind], "-group"))
	    {
		ind++;
		grpname = argv[ind];
		hasgroup = 1;
		ind++;
		grpatt  = atoi(argv[ind]);
		ind++;
                continue;
	    }
	    else if(!strcmp(argv[ind], "-rest"))
	    {
		ind++;
		pllang = argv[ind];
		hasrestriction = 1;
		ind++;
		plstring = argv[ind];
		ind++;
                continue;
	    }
	    else if(!strcmp(argv[ind], "-issuer"))
	    {
		ind++;
		x509file = argv[ind];
		hasissuer = 1;
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
	
	PROXYCERTINFO_set_pC(pcinfo, ispc);
        PROXYCERTINFO_set_version(pcinfo, version);
	
	if(haspclength)
	{
	    PROXYCERTINFO_set_path_length(pcinfo, pclength);
	}

	if(hasrestriction)
	{
	    rst = PROXYRESTRICTION_new();
	    PROXYRESTRICTION_set_policy(rst, plstring, strlen(plstring));
	    pol_lang = ASN1_OBJECT_new();
	    pol_lang->sn = pllang;
	    pol_lang->ln = pllang;
	    pol_lang->data = pllang;
	    pol_lang->length = strlen(pllang);
	    pol_lang->flags = 0;
            PROXYRESTRICTION_set_policy_language(rst, pol_lang);
            PROXYCERTINFO_set_restriction(pcinfo, rst);
	}

	if(hasgroup)
	{
	    grp = PROXYGROUP_new();
	    PROXYGROUP_set_name(grp, grpname, strlen(grpname));
	    PROXYGROUP_set_attached(grp, grpatt);
            PROXYCERTINFO_set_group(pcinfo, grp);
	}
        
	if(hasissuer)
	{
            my_x509 = X509_new();
            x509stream = fopen(x509file, "r");
            PEM_read_X509(x509stream, 
                          &my_x509,
                          NULL, NULL);

            signature = X509_SIG_new();
            signature->algor = my_x509->sig_alg;
            signature->digest = (ASN1_OCTET_STRING *) my_x509->signature;
	    PROXYCERTINFO_set_issuer_signature(pcinfo, signature);
            X509_SIG_free(signature);
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
            "  -pc <is a proxy>\n"
            "      Sets the proxy cert info flag to 1 (true)\n"
            "      or 0 (false), the default is true\n\n"
            "  -path  <path length>\n      Sets the path length "
            "of the proxy cert info,\n      otherwise "
            "no max length exists\n\n"
            "  -group  <group name> <is attached>\n"
            "      Sets the group name and if its attached\n"
            "      attached should be 0 or 1.  Without\n"
            "      this option, none will be added to the proxy cert info\n\n"
            "  -rest  <language> <policy>\n"
            "      adds a restriction to the proxy cert info\n"
            "      and sets the policy language and\n"
            "      and policy string\n\n"
            "  -issuer  <x509 cert file>\n"
            "      adds an issuer signature to the proxy cert info\n"
            "      the file must be a valid PEM"
            " formatted signed cert\n"
            "  -in  <proxycertfile>\n"
            "      takes a DER encoded proxy cert info and prints\n"
            "      it out to stderr.  This flag causes all other\n"
            "      flags to be ignored\n\n"
            "  -out <proxycertfile>\n"
            "      outputs the DER encoded form of the proxy cert info\n\n");
    exit(1);
}
