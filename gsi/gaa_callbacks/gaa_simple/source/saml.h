#include <string.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

/*****************************************************************/
#define DEBUG(x) printf(x)

//#define debug

#define SAML_NS_URN "urn:oasis:names:tc:SAML:1.0:assertion"
#define ADS      "AuthorizationDecisionStatement"

/*
 * a Description for an Assertion
 */
typedef struct assertion {
  xmlChar *AssertionID;
  xmlChar *IssueInstant;
  xmlChar *Issuer;
  xmlChar *MajorVersion;
  xmlChar *MinorVersion;
  xmlChar *NotBefore;
  xmlChar *NotOnOrAfter;
  struct ads *ads;
} assertion, *assertionPtr;

typedef struct ads 
{
  xmlChar *decision;
  xmlChar *resource;
  xmlChar *NameIDformat;
  xmlChar *NameIDNameQualifier;
  xmlChar *NameID;
  xmlChar *ConfirmationMethod;
  struct action *action;
  struct ads  *next;
} ads, *adsPtr;

typedef struct action {
  xmlChar *ActionNS;
  xmlChar *Action;
  struct   action *next;
} action, *actionPtr;

assertionPtr
getConditions(xmlNodePtr cur, assertionPtr Assertion);


assertionPtr
getADSattributes(xmlDocPtr doc, xmlNodePtr cur, assertionPtr Assertion);


assertionPtr
handleSubject(xmlDocPtr doc, xmlNodePtr cur, assertionPtr Assertion);

assertionPtr
handleAction(xmlDocPtr doc, xmlNodePtr cur, assertionPtr Assertion);

assertionPtr
parseADS(xmlDocPtr doc, xmlNsPtr ns, xmlNodePtr cur, assertionPtr Assertion);

assertionPtr
parseSAMLassertion(char *filename);

void
printSAMLassertion(assertionPtr as);

void
freeAssertion(assertionPtr Assertion);
