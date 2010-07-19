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
 * samlparse.c
 *
 * Dongho Kim
 *
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "gaa.h"
#include "saml.h"
#include "xml_sig.h"

/**
 * getConditions -- return 0 on success, nonzero on failure
 */

static int
getConditions(xmlNodePtr cur, assertionPtr Assertion)
{
#ifdef debug
  printf("NotBefore=%s\n", xmlGetProp(cur, (const xmlChar *) "NotBefore"));
  printf("NotOnOrAfter=%s\n", xmlGetProp(cur, (const xmlChar *) "NotOnOrAfter"));
#endif

/*
 * These two are optional.
 * So, if a field does not exist, NULL will be assigned.
 */
  Assertion->NotBefore = xmlGetProp(cur, (const xmlChar *) "NotBefore");
  Assertion->NotOnOrAfter = xmlGetProp(cur, (const xmlChar *) "NotOnOrAfter");
 
  /*
   * Reject any other conditions.
   */
  if (xmlGetProp(cur, (const xmlChar *) "Condition") ||
      xmlGetProp(cur, (const xmlChar *) "AudienceRestrictionCondition"))
  {
      gaa_set_callback_err("unrecognized condition in assertion");
      return(-1);
  }
  return 0;
}



assertionPtr
getADSattributes(xmlDocPtr doc, xmlNodePtr cur, assertionPtr Assertion)
{
  adsPtr cur_ads;
  
  cur_ads = Assertion->ads;
  
  while (cur_ads->next != NULL)
    cur_ads = cur_ads->next;
  
#ifdef debug
  printf("Decision=%s\n", xmlGetProp(cur, (const xmlChar *) "Decision"));
  printf("Resource=%s\n", xmlGetProp(cur, (const xmlChar *) "Resource"));
#endif

  
  cur_ads->decision = xmlGetProp(cur, (const xmlChar *) "Decision");
  cur_ads->resource = xmlGetProp(cur, (const xmlChar *) "Resource");  
  
  return Assertion;
}


assertionPtr
handleSubject(xmlDocPtr doc, xmlNodePtr cur, assertionPtr Assertion)
{
  adsPtr ads;

  ads = Assertion->ads;
  
  while (ads->next != NULL)
    ads = ads->next;
  
  if (!xmlStrcmp(cur->name, (const xmlChar *)"NameIdentifier")) {
#ifdef debug
    printf("NameIdentifier=%s\n", (cur->xmlChildrenNode)->content);
    /* This does the same thing as below line xmlNodeListGetString(). */
    printf("NameIDFormat=%s\n", xmlGetProp(cur, (const xmlChar *) "Format"));
    printf("NameQualifier=%s\n", xmlGetProp(cur, (const xmlChar *) "NameQualifier"));
#endif
    ads->NameID = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
    ads->NameIDformat = xmlGetProp(cur, (const xmlChar *) "Format");
    ads->NameIDNameQualifier =xmlGetProp(cur, (const xmlChar *) "NameQualifier");
  }
    
  cur = cur->next;

  if (!xmlStrcmp(cur->name, (const xmlChar *)"SubjectConfirmation")) {
    cur = cur->xmlChildrenNode;
#ifdef debug
    printf("ConfirmationMethod=%s\n", (cur->xmlChildrenNode)->content);
#endif
    ads->ConfirmationMethod = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
  }
  return Assertion;
}


assertionPtr
handleAction(xmlDocPtr doc, xmlNodePtr cur, assertionPtr Assertion)
{
  adsPtr cur_ads;
  actionPtr new_action, cur_action;
  
  new_action = (actionPtr) malloc(sizeof(action));
  if (new_action== NULL) {
    gaa_set_callback_err("out of memory\n");
    xmlFreeDoc(doc);
    return(NULL);
  }
  memset(new_action, 0, sizeof(action));
  
  if (!Assertion->ads) {
    gaa_set_callback_err("Error: NULL ads\n");
    xmlFreeDoc(doc);
    return(NULL);
  }

  cur_ads = Assertion->ads;

  while (cur_ads->next != NULL)
    cur_ads = cur_ads->next;

  cur_action = cur_ads->action;

  if (cur_action == NULL)
    cur_ads->action = new_action;
  else {
    while (cur_action->next != NULL)
      cur_action = cur_action->next;
    cur_action->next = new_action;
  }

  if (!xmlStrcmp(cur->name, (const xmlChar *)"Action")) {
#ifdef debug
    printf("Action=%s\n", (cur->xmlChildrenNode)->content);
#endif
    new_action->Action = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
  }
#ifdef debug
  printf("Namespace=%s\n", xmlGetProp(cur, (const xmlChar *) "Namespace"));
#endif
  new_action->ActionNS = xmlGetProp(cur, (const xmlChar *) "Namespace");

  return Assertion;
}

/* Parse <AuthorizationDecisionStatement> */
assertionPtr
parseADS(xmlDocPtr doc, xmlNsPtr ns, xmlNodePtr cur, assertionPtr Assertion)
{
  int isSubject = 0;
  int isAction = 0;

  Assertion = getADSattributes(doc, cur, Assertion);

  /* Work on Subject and Action */
  cur = cur->xmlChildrenNode;

  while (cur != NULL) {
    if ((!xmlStrcmp(cur->name, (const xmlChar*)"Subject")) && (cur->ns == ns)) {
      Assertion = handleSubject(doc, cur->xmlChildrenNode, Assertion);
      isSubject = 1;
    }
    else if  (!xmlStrcmp(cur->name, (const xmlChar *) "Action")) {
      Assertion = handleAction(doc, cur, Assertion);
      isAction = 1;
    }
    else {
	/* For now, we ignore the rest. */
    }
    cur = cur->next;
  }
  if (!(isSubject && isAction)) {
    gaa_set_callback_err("Wrong input: <Subject> and/or <Action> is not found\n");
#ifdef debug
    xmlDocDump ( stderr, doc );
    gaa_set_callback_err("xmlDocDump finished\n");
#endif
    xmlFreeDoc(doc);
    /*  XXX: todo -- Need to free the nested structures... */
    free(Assertion);
    return(NULL);
  }
  
  return(Assertion);
}


assertionPtr
parseSAMLassertion(char *saml_assertion, int verify_signature) {
  xmlDocPtr doc = 0;
  xmlNsPtr ns;
  xmlNodePtr cur;
  assertionPtr TheAssertion = 0;
  adsPtr new_ads, cur_ads;
  assertionPtr retval = 0;
  
  int isADS = 0;
  
  /* COMPAT: Do not generate nodes for formatting spaces */
  LIBXML_TEST_VERSION
/*    xmlKeepBlanksDefault(0); */

  
  /*
   * build an XML tree from a saml file;
   */
  xmlInitParser();
  xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
  xmlSubstituteEntitiesDefault(1);

  doc = xmlParseMemory(saml_assertion, strlen(saml_assertion));
  if (doc == NULL) goto end;

  if (verify_signature) {
      if (gaa_simple_i_verify_xml_sig(doc) != GAA_S_SUCCESS) {
	  goto end;
      }
  }

  /*
   * Check the document is of the right kind
   */
    
  cur = xmlDocGetRootElement(doc);
  if (cur == NULL) {
    gaa_set_callback_err("empty document\n");
    goto end;
  }
  ns = xmlSearchNsByHref(doc, cur, (const xmlChar *) SAML_NS_URN);
  if (ns == NULL) {
    gaa_set_callback_err( "Wrong input, SAML assertion Namespace not found\n");
    goto end;
  }

  if (xmlStrcmp(cur->name, (const xmlChar *) "Assertion")) {
    gaa_set_callback_err("Wrong input, root node must be Assertion");
    goto end;
  }
  
  /*
   * Allocate the structure to be returned.
   */
  TheAssertion = (assertionPtr) malloc(sizeof(assertion));
  if (TheAssertion == NULL) {
    gaa_set_callback_err("out of memory\n");
    goto end;
  }
  memset(TheAssertion, 0, sizeof(assertion));
  
  /*
   * Now, walk the tree.
   */

  cur = cur->xmlChildrenNode;
  while ( cur && xmlIsBlankNode ( cur ) )
  {
    cur = cur -> next;
  }

  /* At the first level we expect ADS.  Conditions are optional. */
  while (cur != NULL) {
    if (!xmlStrcmp(cur->name, (const xmlChar *) "Conditions"))
    {
	if (getConditions(cur, TheAssertion))
	{
	    goto end;
	}
    }
    else if  (!xmlStrcmp(cur->name, (const xmlChar *) ADS)) {
      new_ads = (adsPtr) malloc(sizeof(ads));
      if (new_ads== NULL) {
        gaa_set_callback_err("out of memory\n");
	goto end;
      }
      memset(new_ads, 0, sizeof(ads));

      cur_ads = TheAssertion->ads;

      if (cur_ads == NULL)
        TheAssertion->ads = new_ads;
      else {
        while (cur_ads->next != NULL)
          cur_ads = cur_ads->next;
        cur_ads->next = new_ads;
      }
      
      TheAssertion = parseADS(doc, ns, cur, TheAssertion);        
      isADS = 1;
    }
    else {
	/* For now, we ignore others. */
    }
    cur = cur->next;
  }
  
  if (!isADS) {
    gaa_set_callback_err("Wrong input: AuthorizationDecisionStatement is not found\n");
#ifdef debug
    xmlDocDump ( stderr, doc );
    gaa_set_callback_err("xmlDocDump finished\n");
#endif
    goto end;
  }

  retval = TheAssertion;

 end:

  if (retval == 0)
      free(TheAssertion);

  if (doc)
    xmlFreeDoc(doc);

  /* Clean up everything else before quitting. */
  xmlCleanupParser();
  
  return(retval);
}



void
printSAMLassertion(assertionPtr as) {
  adsPtr ads;
  actionPtr action;
  
  printf("\n=============== Assertion ================\n\n");
  
  printf("NotBefore=%s\n", as->NotBefore);
  printf("NotOnOrAfter=%s\n", as->NotOnOrAfter);

  ads = as->ads;

  while (ads != NULL) {
    printf("--------------- Authorization Decision Statement -----------\n");
    printf("Decision=%s\n", as->ads->decision);
    printf("Resource=%s\n", as->ads->resource);

    printf("NameIDformat=%s\n", as->ads->NameIDformat);
    printf("NameIDNameQualifier=%s\n", as->ads->NameIDNameQualifier);
    printf("NameID=%s\n", as->ads->NameID);

    action = ads->action;
    while (action != NULL) {
      
      printf("ActionNS=%s\n", as->ads->action->ActionNS);
      printf("Action=%s\n", as->ads->action->Action);
      action = action->next;
    }
    ads = ads->next;
    printf ("\n");
  }

  /****  Free will be done in gaa_simple_read_saml()  
  free (as->ads->action);
  free (as->ads);
  free (as);
  ****************************************/
}

