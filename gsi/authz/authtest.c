#include <string.h>
#include <strings.h>

#include "globus_i_gsi_authz.h"


#define USAGE "Usage: %s configfile {1-4}\n"
// #define USAGE "Usage: %s saml_assertion_file\n"

#define cas   "casNamespace:casServer"
#define ftp1  "FTPNamespace|ftp://sample1.org"
#define ftp2  "FTPNamespace|ftp://sample2.org"
#define ftp3  "FTPNamespace|ftp://sample3.org"

#define ftp11  "FTPNameSpace|ftp://sample1.org"
#define bad   "WrongObject"

char *users = 0;

static globus_gsi_authz_handle_t        handle;
static void *                           authz_system_state;
static globus_result_t result;


int
main(int argc, char **argv)
{
  globus_gsi_authz_handle_t        handle;
  char object = "hello";
  char buf[1024];
  char *repl;
  char *what;
  char *cfname;

  /** Need to take care of these */
  char *service_name;
  gss_ctx_id_t                  context;
  globus_gsi_authz_cb_t         callback;
  void *                    callback_arg;
  void *                        action;
  /******************************/

  char resource_name[256], *rname;
  
  switch(argc) {
    case 3:
      cfname = argv[1];
      rname = argv[2];
      break;
    default:
      fprintf(stderr, USAGE, argv[0]);
      exit(1);
  }

  result = globus_l_gsi_authz_activate();
  
  globus_gsi_authz_handle_init(handle, service_name, context, callback, callback_arg);

  switch (atoi(rname)) {
    case 1:
      strcat (buf, cas);      
      strcpy (resource_name, cas);
      break;
    case 2:
      strcat (buf, ftp1);
      strcpy (resource_name, ftp1);
      break;
    case 3:
      strcat (buf, ftp2);      
      strcpy (resource_name, ftp2);
      break;
    case 4:
      strcat (buf, ftp3);      
      strcpy (resource_name, ftp3);
      break;
    case 5:
      strcat (buf, ftp11);      
      strcpy (resource_name, ftp3);
      break;
    case 6:
      strcat (buf, bad);      
      strcpy (resource_name, ftp3);
      break;
    default:
      printf ("Wrong argument... no object specified. \n");
      exit (1);
  }

  globus_gsi_authorize(handle, action, object, callback, callback_arg);

  printf("Handle->status = %d\n", handle->status);

  globus_l_gsi_authz_deactivate();

  exit(0);
}
