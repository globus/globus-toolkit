
#include <stdio.h>
#include <proxycertinfo.h>
#include <proxyrestriction.h>
#include <proxygroup.h>

#include <openssl/pem.h>

void usage();

int main(int argc, char * argv[]) 
{

    char * grpname;
    char * plstring;
    char * pllang;
    char * filename;
    char * x509file;

    FILE * instream;
    FILE * x509stream;

    PROXYRESTRICTION * rst;
    PROXYGROUP * grp;
    PROXYCERTINFO * pcinfo;
    PROXYCERTINFO * pc2;
    ASN1_OBJECT * pol_lang;
    X509 * my_x509;
    X509_SIG * signature;

    int ispc, haspclength, hasgroup, hasrestriction, hasissuer,
	pclength, grpatt, ind, from_file;

    from_file = haspclength = hasgroup = hasissuer =
	        hasrestriction = pclength = 0;
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
	    if(!strcmp(argv[ind], "-path"))
	    {
		ind++;
		pclength = atoi(argv[ind]);
		haspclength = 1;
		ind++;
                continue;
	    }
	    if(!strcmp(argv[ind], "-group"))
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

	PROXYCERTINFO_print_fp(stderr, pcinfo);
	
	fclose(instream);
    }
    else
    {
	pcinfo = PROXYCERTINFO_new();
	
	PROXYCERTINFO_set_pC(pcinfo, ispc);
	
	if(haspclength)
	{
	    PROXYCERTINFO_set_path_length(pcinfo, (long *) & pclength);
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
                          (char **) & my_x509,
                          NULL, NULL);

            /* stupid X509 struct doesn't even contain */
            /* an X509_SIG - instead, its got an X509_ALGOR */
            /* and an ASN1_BIT_STRING */
            signature = X509_SIG_new();
            signature->algor = my_x509->sig_alg;
            signature->digest = (ASN1_OCTET_STRING *) my_x509->signature;
	    PROXYCERTINFO_set_issuer_signature(pcinfo, signature);
	}

	PROXYCERTINFO_print_fp(stderr, pcinfo);

	if(!ASN1_i2d_fp(i2d_PROXYCERTINFO, stdout, (unsigned char *)pcinfo))
	{
	    fprintf(stderr, "Could not print the proxy cert info struct\n");
	}
    }

    PROXYCERTINFO_free(pcinfo);
}

void usage()
{
    fprintf(stderr, "\nSyntax: test_pci [-help][-pc] ... \\\n\n");
    fprintf(stderr, "  -help\n      Displays usage information\n\n");
    fprintf(stderr, "  -pc <is a proxy>\n");
    fprintf(stderr, "      Sets the proxy cert flag to 1 (true)\n");
    fprintf(stderr, "      or 0 (false), the default is true\n\n");
    fprintf(stderr, "  -path  <path length>\n      Sets the path length");
    fprintf(stderr, "of the proxy cert,\n      otherwise no max length exists\n\n");
    fprintf(stderr, "  -group  <group name> <is attached>\n");
    fprintf(stderr, "      Sets the group name and if its attached\n");
    fprintf(stderr, "      attached should be 0 or 1.  Without\n");
    fprintf(stderr, "      this option, none will be added to the proxy\n\n");
    fprintf(stderr, "  -rest  <language> <policy>\n");
    fprintf(stderr, "      adds a restriction to the proxy\n");
    fprintf(stderr, "      and sets the policy language and\n");
    fprintf(stderr, "      and policy string\n\n");
    fprintf(stderr, "  -issuer  <x509 cert file>\n");
    fprintf(stderr, "      adds an issuer signature to the proxy\n");
    fprintf(stderr, "      the file must be a valid PEM formatted signed cert\n");
    fprintf(stderr, "  -in  <proxycertfile>\n");
    fprintf(stderr, "      takes a DER encoded proxy cert and prints\n");
    fprintf(stderr, "      it out to stderr.  This flag causes all other\n");
    fprintf(stderr, "      flags to be ignored\n\n");
    exit(1);
}
