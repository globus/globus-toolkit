
#include <stdio.h>
#include <proxycertinfo.h>
#include <proxyrestriction.h>
#include <proxygroup.h>

int main(int argc, char * argv[]) 
{

    char * grpname;
    char * plstring;
    char * pllang;
    char * filename;
    char * issuer;
    
    FILE * instream;
    FILE * issuerfile;

    PROXYRESTRICTION * rst;
    PROXYGROUP * grp;
    PROXYCERTINFO * pcinfo;
    ASN1_OBJECT * pol_lang;
    X509_SIG * signature;

    int ispc, haspclength, hasgroup, hasrestriction, hasissuer,
	pclength, grpatt, ind, from_file;

    from_file = ispc = haspclength = hasgroup = hasissuer =
	        hasrestriction = pclength = 0;

    if(argc > 1)
    {	
	ind = 1;
	while(ind < argc) 
	{
	    if(!strcmp(argv[ind], "-pc"))
	    {
		ispc = 1;
		ind++;
	    }
	    if(!strcmp(argv[ind], "-path"))
	    {
		ind++;
		pclength = atoi(argv[ind]);
		haspclength = 1;
		ind++;
	    }
	    if(!strcmp(argv[ind], "-group"))
	    {
		ind++;
		grpname = argv[ind];
		hasgroup = 1;
		ind++;
		grpatt  = atoi(argv[ind]);
		ind++;
	    }
	    else if(!strcmp(argv[ind], "-rest"))
	    {
		ind++;
		pllang = argv[ind];
		hasrestriction = 1;
		ind++;
		plstring = argv[ind];
		ind++;
	    }
	    else if(!strcmp(argv[ind], "-issuer"))
	    {
		ind++;
		issuer = argv[ind];
		hasissuer = 1;
		ind++;
	    }
	    else if(!strcmp(argv[ind], "-in"))
	    {
		ind++;
		from_file = 1;
		filename = argv[ind];
		ind++;
	    }
	    else
	    {
		fprintf(stderr, "Syntax: test_pci [-help][-pc] ... \\\n\n");
		fprintf(stderr, "\t-help\t\tDisplays usage information\n");
		fprintf(stderr, "\t-pc\t\tSets the proxy cert flag to true\n");
		fprintf(stderr, "\t\t\tthe default is false\n");
		fprintf(stderr, "\t-path\t<path length>\tSets the path length\n");
		fprintf(stderr, "\t\t\tof the proxy cert, otherwise no max\n");
		fprintf(stderr, "\t\t\tpath length exists\n");
		fprintf(stderr, "\t-group\t<group name> <is attached>\n");
		fprintf(stderr, "\t\t\tSets the group name and if its attached\n");
		fprintf(stderr, "\t\t\tattached should be 0 or 1\n");
		fprintf(stderr, "\t\t\twithout -group, none will be added\n");
		fprintf(stderr, "\t-rest\t<language> <policy>\n");
		fprintf(stderr, "\t\t\tadds a restriction to the proxy\n");
		fprintf(stderr, "\t\t\tand sets the policy language and\n");
		fprintf(stderr, "\t\t\tand policy string\n");
		fprintf(stderr, "-issuer\t<signature file>\tadds an issuer signature\n");
		fprintf(stderr, "\t\t\tto the proxy\n");
		fprintf(stderr, "-in\t<proxycertfile>\ttakes a DER encoded\n");
		fprintf(stderr, "\t\t\tproxy cert and prints it out to stderr\n");
		fprintf(stderr, "\t\t\tthis flag causes all other flags to be ignored\n\n");
		exit(1);
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
	
	if(hasgroup)
	{
	    grp = PROXYCERTINFO_get_group(pcinfo);
	    PROXYGROUP_set_name(grp, grpname, strlen(grpname));
	    PROXYGROUP_set_attached(grp, grpatt);
	}
	else
	{
	    PROXYCERTINFO_set_group(pcinfo, NULL);
	}

	if(hasrestriction)
	{
	    rst = PROXYCERTINFO_get_restriction(pcinfo);
	    PROXYRESTRICTION_set_policy(rst, plstring, strlen(plstring));
	    pol_lang = PROXYRESTRICTION_get_policy_language(rst);	
	    pol_lang->sn = pllang;
	    pol_lang->ln = pllang;
	    pol_lang->data = pllang;
	    pol_lang->length = strlen(pllang);
	    pol_lang->flags = 0;
	}
	else
	{
	    PROXYCERTINFO_set_restriction(pcinfo, NULL);
	}

	PROXYCERTINFO_set_pC(pcinfo, ispc);
	
	if(haspclength)
	{
	    PROXYCERTINFO_set_path_length(pcinfo, (long *)&pclength);
	}
	else
	{
	    PROXYCERTINFO_set_path_length(pcinfo, NULL);
	}

	if(hasissuer)
	{
	    signature = X509_SIG_new();
	    issuerfile = fopen(issuer, "r");
	    ASN1_d2i_fp((char *(*)()) X509_SIG_new, 
			(char *(*)()) d2i_X509_SIG, 
			issuerfile, 
			(unsigned char **) &signature);
	    PROXYCERTINFO_set_issuer_cert_digest(pcinfo, signature);
	}

	PROXYCERTINFO_print_fp(stderr, pcinfo);

	if(!ASN1_i2d_fp(i2d_PROXYCERTINFO, stdout, (unsigned char *)pcinfo))
	{
	    fprintf(stderr, "Could not print the proxy cert info struct\n");
	}
    }

    PROXYCERTINFO_free(pcinfo);
}
