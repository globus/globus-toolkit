#ifndef XML_SIG_H
#define XML_SIG_H

extern gaa_status
gaa_simple_i_verify_xml_sig(xmlDocPtr doc);
extern int
gaa_simple_i_xml_sig_ok(xmlDocPtr doc, char *errbuf, int errbuflen);
extern gaa_status
gaa_simple_i_find_signer(xmlDocPtr doc, char **signer, char *errbuf, int errbuflen);
#endif /* XML_SIG_H */
