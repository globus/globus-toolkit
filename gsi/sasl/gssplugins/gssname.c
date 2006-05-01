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

/*
 * generate the GSSAPI implementation's GSS name
 * several routines are from Meyer's draft
 */

#include <globus_config.h>

#include <stdio.h>
#include <openssl/md5.h>

#include "config.h"

#ifdef HAVE_GSSAPI_H
#include <gssapi.h>
#else
#include <gssapi/gssapi.h>
#endif


#define SASL_MECHNAMEMAX 20

static const
struct compat_map {
const unsigned char oid[15];
const char *saslname;
} compat_map[] = {
{ { 0x06, 0x05, 0x2b, 0x05, 0x01, 0x05, 0x02 }, "GSSAPI" },
{ { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 },
  "GSSAPI" }, /* old Kerberos V5 OID */
{ { 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 }, "GSS-SPNEGO" },
};

static char basis_32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/*
* Convert the GSSAPI mechanism 'oid' of length 'oidlen', placing
* the result into 'retbuf', which must be of size 21
*/
void 
oidToSaslMech(const unsigned char *oid, unsigned oidlen, char *retbuf)
{
     int i;
     MD5_CTX md5ctx;
     unsigned char md5buf[16];
     char *out;
     unsigned char *in;
     unsigned char *p;
     int len;

     /* See if it has a backwards-compatibility SASL mechsnism name */
     for (i = 0; i < (sizeof(compat_map) / sizeof(compat_map[0])); i++) {
         if (memcmp(compat_map[i].oid, oid, oidlen) == 0) {
             strcpy(retbuf, compat_map[i].saslname);
             return;
         }
     }

     MD5_Init(&md5ctx);
     MD5_Update(&md5ctx, (unsigned char *)oid, oidlen);
     MD5_Final(md5buf, &md5ctx);
     
     in = md5buf;
     strcpy(retbuf, "GSS-");
     out = retbuf + strlen(retbuf);
     len = 10;
     while (len) {
         *out++ = basis_32[in[0] >> 3];
         *out++ = basis_32[((in[0] & 7) << 2) | (in[1] >> 6)];
         *out++ = basis_32[(in[1] & 0x3f) >> 1];
         *out++ = basis_32[((in[1] & 1) << 4) | (in[2] >> 4)];
         *out++ = basis_32[((in[2] & 0xf) << 1) | (in[3] >> 7)];
         *out++ = basis_32[(in[3] & 0x7f) >> 2];
         *out++ = basis_32[((in[3] & 3) << 3) | (in[4] >> 5)];
         *out++ = basis_32[(in[4] & 0x1f)];
         in += 5;
         len -= 5;
     }
     *out++ = '\0';
}

const char *
convert_gss_name_from_oid(unsigned char* oid, int oid_len)
{
     unsigned char *p;
     MD5_CTX md5ctx;
     char *saslmechbuf;

     unsigned char *asn1start;
     unsigned char *asn1next;

   
     /* preallocate enough space for the oid and tag and length */
     asn1start= (unsigned char *) malloc (sizeof (unsigned char) * (oid_len+2));
     asn1next=asn1start+oid_len+2;

     saslmechbuf=(char *) malloc ( sizeof(unsigned char)*SASL_MECHNAMEMAX+1);
     saslmechbuf[0]='\0';

     /* prepend the tag and length in front of oid */
     *asn1start=6;
     *(asn1start+1)=oid_len;
     memcpy(asn1start+2,oid,oid_len);

     oidToSaslMech(asn1start, asn1next - asn1start, saslmechbuf);
     
     return saslmechbuf;
}

/* return 1 oid from the mechlist,
   if there are more than 1 in the mechlist, return the
   mechidx_th one, index starts from 0 */
unsigned char*
get_oid(int mechidx, int *a_oid_len)
{
     OM_uint32 maj_stat, min_stat;
     gss_OID_set some_mech_set;
     size_t count;
     int length;

     gss_OID elements;
     gss_OID a_element;
     unsigned char* a_oid;

     maj_stat = gss_indicate_mechs(&min_stat, &some_mech_set);
     if (maj_stat == GSS_S_COMPLETE) {
         int i;
         count=some_mech_set->count;
         if(mechidx>=count || mechidx<0) {
             return NULL;
         }
         elements=some_mech_set->elements;
         a_element=&(elements[mechidx]);
         a_oid=(unsigned char *) a_element->elements;
         *a_oid_len=a_element->length;
         return a_oid;
     }
     return NULL;
}

const char *
get_gss_name_from_oid(int oididx)
{
   int oid_len=0;
   const char *gss_name;
   unsigned char* oid=get_oid(oididx, &oid_len);
   if(oid==NULL) return NULL;
   gss_name=convert_gss_name_from_oid(oid, oid_len);
   return gss_name;
}


const char* get_gss_name() {
  return "GSI-GSSAPI";
}
const char* get_gss_version() {
  return "unknown";
}



