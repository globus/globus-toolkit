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

#include <globus_module.h>
#include <globus_gss_assist.h>
#include <gssapi.h>

#include <stdio.h>

int
ask(
    char *                              question)
{
   int answer, i, doit;

   printf("%s [Y/N]: ",question);
   answer = fgetc(stdin);

   do {
      i = fgetc(stdin);
   } while(i != '\n');

   doit = ((answer & 0xdf) == 'Y') ? 1 : 0;

   return doit;
}

int main()
{
    OM_uint32		maj_stat, min_stat;
    gss_cred_id_t       cred_handle;
    int doit;

    doit = ask("explicit activate for first acquire/release?");
  
    if (doit)  
      globus_module_activate(GLOBUS_GSI_GSSAPI_MODULE);

    printf("going to start first gss_acquire_cred\n");

    maj_stat = gss_acquire_cred(&min_stat,
                                NULL,
                                GSS_C_INDEFINITE,
                                GSS_C_NO_OID_SET,
                                GSS_C_BOTH,
                                &cred_handle,
                                NULL,
                                NULL);

    printf("gss_acquire_cred: maj_stat=%d min_stat=%d\n",maj_stat,min_stat);

    if(GSS_ERROR(maj_stat)) {
      fprintf(stderr,"Got gss error!\n");
      exit(1);
    }

    maj_stat = gss_release_cred(&min_stat,
                                &cred_handle);

    printf("gss_release_cred: maj_stat=%d min_stat=%d\n",maj_stat,min_stat);

    if(GSS_ERROR(maj_stat)) {
      fprintf(stderr,"Got gss error!\n");
      exit(1);
    }

    if (doit)
      globus_module_deactivate(GLOBUS_GSI_GSSAPI_MODULE);

    doit = ask("now activate/deactivate GLOBUS_GASS_COPY_MODULE?");

    if (doit) {
      printf("going to activate GLOBUS_GASS_COPY_MODULE.. ");
      globus_module_activate(GLOBUS_GSI_GSS_ASSIST_MODULE);
      printf(" done\n");
      printf("going to deactivate GLOBUS_GASS_COPY_MODULE.. ");
      globus_module_deactivate(GLOBUS_GSI_GSS_ASSIST_MODULE);
      printf(" done\n");
    }

    printf("going to start second gss_acquire_cred\n");

    maj_stat = gss_acquire_cred(&min_stat,
                                NULL,
                                GSS_C_INDEFINITE,
                                GSS_C_NO_OID_SET,
                                GSS_C_BOTH,
                                &cred_handle,
                                NULL,
                                NULL);

    printf("second gss_acquire_cred: maj_stat=%d min_stat=%d\n",
           maj_stat,min_stat);

    if(GSS_ERROR(maj_stat)) {
      fprintf(stderr,"Got gss error!\n");
      exit(1);
    }

    maj_stat = gss_release_cred(&min_stat,
                                &cred_handle);

    printf("second gss_release_cred: maj_stat=%d min_stat=%d\n",
           maj_stat,min_stat);

    if(GSS_ERROR(maj_stat)) {
      fprintf(stderr,"Got gss error!\n");
      exit(1);
    }


    doit=ask("final activate of GLOBUS_GASS_COPY_MODULE?");

    if (doit)
      globus_module_activate(GLOBUS_GSI_GSS_ASSIST_MODULE);

    printf("doing globus_module_deactivate_all\n");
    globus_module_deactivate_all();
    printf("now leaving OK\n");
    return 0;
}
