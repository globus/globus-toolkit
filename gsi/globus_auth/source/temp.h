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

#include <sys/stat.h>

 extern gaa_status
 gaasimple_parse_eacl_str(gaa_ptr        gaa,
      gaa_policy **   policy,
      gaa_string_data object,
      void *      params)  ;


#if 0
void print_req(char *inbuff, int inlen)
{
 
    int i;
     
    printf("Buffer: %d bytes\n\n",inlen);
    for(i = 0; i< inlen; i++){
        if(inbuff[i] == '\r')
            printf("\\r");
        else if(inbuff[i] == '\n')
            printf("\\n");
        else if(inbuff[i] == '\t')
            printf("\\t");
        else if(inbuff[i] == ' ')
            printf("$");
        else printf("%c", inbuff[i]);
    }
    printf("End of buffer\n");
}           


OM_uint32
GSS_CALLCONV gss_inquire_sec_context_by_oid(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    gss_OID                             desired_object,
    char  **                            data_set)
{
    char    *str,*oldstr;
    struct stat buf;
    FILE    *fp;
    int     offset = 0;
    int     i;

    if(stat("policy",&buf))
    {
        printf("Error in stat\n");
        exit(-1);
    }

    printf("Allocating %d bytes\n",buf.st_size);
    *data_set = (char *)malloc(buf.st_size+1);
    oldstr = *data_set;

    if((fp=fopen("policy","r"))==0)
    {
        printf("Error in opening file\n");
        exit(-2);
    }

    while(!feof(fp))
    {
        fgets(*data_set+offset, 200,fp);
        offset = strlen(*data_set);
    }

    fclose(fp);

    printf("Got %d bytes in buffer\n", strlen(*data_set));
    //print_req(str,strlen(str));
    
    return GSS_S_COMPLETE;
   
    

}    

#endif 0
