
#include "myproxy_common.h"	/* all needed headers included here */

main(int argc, char **argv)
{
    SSL_CREDENTIALS *creds;
    SSL_CREDENTIALS *proxy;
    const char *pass;
    unsigned char *init_buffer = NULL;
    int init_buffer_len;
    unsigned char *signed_buffer = NULL;
    int signed_buffer_len;
    
    creds = ssl_credentials_new();
    
    if (creds == NULL)
    {
	printf("Error geting new credentials: %s %s\n",
	       verror_get_string(), verror_strerror());
	exit(1);
    }
    
    if (ssl_proxy_load_from_file(creds, argv[1], NULL) == SSL_ERROR)
    {
	printf("Error loading proxy: %s %s\n",
	       verror_get_string(), verror_strerror());
	exit(1);
    }

    printf("Proxy loaded\n");

    if (ssl_proxy_delegation_init(&proxy,
				  &init_buffer,
				  &init_buffer_len,
				  0,
				  NULL) == SSL_ERROR)
    {
	printf("Error generating proxy request: %s %s\n",
	       verror_get_string(), verror_strerror());
	exit(1);
    }

    printf("Proxy request generated: length is %d\n", init_buffer_len);

    if (ssl_proxy_delegation_sign(creds,
				  NULL /* no restrictions */,
				  init_buffer,
				  init_buffer_len,
				  &signed_buffer,
				  &signed_buffer_len) == SSL_ERROR)
    {
	printf("Error signing proxy request: %s %s\n",
	       verror_get_string(), verror_strerror());
	exit(1);
    }

    ssl_free_buffer(init_buffer);
    
    printf("Proxy signed: length is %d\n", signed_buffer_len);

    if (ssl_proxy_delegation_finalize(proxy,
				      signed_buffer,
				      signed_buffer_len) == SSL_ERROR)
    {
	printf("Error finalizing proxy certificate: %s %s\n",
	       verror_get_string(), verror_strerror());
	exit(1);
    }

    ssl_free_buffer(signed_buffer);
    
    printf("Proxy generated\n");

    if (ssl_proxy_store_to_file(proxy, argv[2], NULL) == SSL_ERROR)
    {
	printf("Error storing proxy certificate: %s %s\n",
	       verror_get_string(), verror_strerror());
	exit(1);
    }	
}
