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

#ifndef XML_SIG_H
#define XML_SIG_H

extern gaa_status
gaa_simple_i_verify_xml_sig(xmlDocPtr doc);
extern int
gaa_simple_i_xml_sig_ok(xmlDocPtr doc, char *errbuf, int errbuflen);
extern gaa_status
gaa_simple_i_find_signer(xmlDocPtr doc, char **signer, char *errbuf, int errbuflen);
#endif /* XML_SIG_H */
