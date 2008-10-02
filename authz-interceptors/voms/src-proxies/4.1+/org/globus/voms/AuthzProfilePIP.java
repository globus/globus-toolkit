/*
 * Copyright 1999-2007 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package org.globus.voms;

import org.apache.axis.MessageContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.globus.security.authorization.Attribute;
import org.globus.security.authorization.AttributeCollection;
import org.globus.security.authorization.AttributeException;
import org.globus.security.authorization.AttributeIdentifier;
import org.globus.security.authorization.ChainConfig;
import org.globus.security.authorization.CloseException;
import org.globus.security.authorization.EntityAttributes;
import org.globus.security.authorization.InitializeException;
import org.globus.security.authorization.NonRequestEntities;
import org.globus.security.authorization.RequestEntities;
import org.globus.voms.impl.AuthzProfileConstants;
import org.globus.voms.impl.VomsCredentialInformation;
import org.globus.wsrf.impl.security.util.AttributeUtil;
import org.globus.wsrf.security.SecureContainerConfig;

import javax.security.auth.Subject;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Calendar;
import java.util.Iterator;
import java.util.Set;
import java.util.Vector;

import java.security.cert.X509Certificate;

/**
 * VOMS PIP that complies with Authz Interop XACML Profile.
 *
 * http://www.fnal.gov/docs/products/voprivilege/focus/AuthZInterop/documents/AuthZInterop%20XACML%20Profile%20v1.0.pdf
 *
 */
public class AuthzProfilePIP extends PIP {

    // FIXME: repetitive constants, need to use standard from some library.
    public static final String STRING_DATATYPE =
        "http://www.w3.org/2001/XMLSchema#string";

    private static Log logger =
        LogFactory.getLog(AuthzProfilePIP.class.getName());

    public void initialize(String chainName,
                           String prefix,
                           ChainConfig config)
                    throws InitializeException {

        super.initialize(chainName, prefix, config);
    }

    // PIP that this class extends from adds the VOMs
    public NonRequestEntities collectAttributes(RequestEntities requestEntities)
        throws AttributeException {

        super.collectAttributes(requestEntities);

        EntityAttributes requestor = requestEntities.getRequestor();

        /* container is the issuer of this decision */
        EntityAttributes issuerEntity =
            SecureContainerConfig.getSecurityDescriptor().getContainerEntity();

        /* Message context for impl */
        MessageContext msgCtx =
            AttributeUtil.getMessageContext(requestEntities, issuerEntity);

        Subject peerSubject = AttributeUtil.getPeerSubject(requestor);

        Set publicCreds =
            peerSubject.getPublicCredentials(X509Certificate[].class);

        if (publicCreds == null) {
            logger.warn("public credentials is null in peer subject.");
        }
        if (publicCreds.size() < 1) {
            logger.warn("No public credentials found in peer subject.");
        }
           
        logger.debug("Piblic creds look okay");

        Set vomsCredentials =
            peerSubject.getPublicCredentials(VomsCredentialInformation.class);

        if ((vomsCredentials == null) || (vomsCredentials.size() < 1)) {
            logger.warn("No VOMS credential found");
            return null;
        }

        logger.debug("VOMS credential found");

        // Going to add first credential
        Iterator iterator = vomsCredentials.iterator();
        VomsCredentialInformation vomsInformation =
            (VomsCredentialInformation) iterator.next();
        String vo = vomsInformation.getVO();
        logger.debug("VO is " + vo);
        String hostPort = vomsInformation.getHostport();
        logger.debug("Host/Port is " + hostPort);
        Vector attributes = vomsInformation.getAttrs();
        if (logger.isDebugEnabled()) {
            if (attributes != null) {
                Iterator attrIter = attributes.iterator();
                while (attrIter.hasNext()) {
                    logger.debug("attribtue is (role vector " +
                                 attrIter.next());
                }
            }
        }

        // Need to contruct relevant attribtues and add.
        // 1. VO as attribute
        AttributeIdentifier voAttrIden = null;
        try {
            voAttrIden = 
                new AttributeIdentifier(new URI(AuthzProfileConstants.
                                                VO_ATTRIBUTE),
                                        new URI(STRING_DATATYPE), false);
        } catch (URISyntaxException e) {
            throw new AttributeException(e);
        }
        // FIXME: Maybe add certificate expiration here?
        Attribute voAttribute = new Attribute(voAttrIden, issuerEntity,
                                              Calendar.getInstance(), null);
        voAttribute.addAttributeValue(vo);
        AttributeCollection attrColl = new AttributeCollection();
        attrColl.add(voAttribute);
        logger.debug("Added VO as attribute");

        // 2. VOMS issuer DN
        String issuerDN = vomsInformation.getIssuerDN();
        if (issuerDN != null) {
            AttributeIdentifier vomsIssuerIden = null;
            try {
                vomsIssuerIden =
                    new AttributeIdentifier(new URI(AuthzProfileConstants.
                                                    VO_SIGNING_SUBJECT), 
                                            new URI(STRING_DATATYPE), false);
            } catch (URISyntaxException e) {
                throw new AttributeException(e);
            }

            Attribute vomsIssuerAttribute =
                new Attribute(vomsIssuerIden, issuerEntity,
                              Calendar.getInstance(), null);
            vomsIssuerAttribute.addAttributeValue(issuerDN);
            attrColl.add(vomsIssuerAttribute);
        }

        // 3. VOMS issuer CA
        String issuerCA = vomsInformation.getIssuerCADN();
        if (issuerCA != null) {
            AttributeIdentifier vomsIssuerCAIden = null;
            try {
                vomsIssuerCAIden =
                    new AttributeIdentifier(new URI(AuthzProfileConstants.
                                                    VO_SIGNING_ISSUER), 
                                            new URI(STRING_DATATYPE), false);
            } catch (URISyntaxException e) {
                throw new AttributeException(e);
            }

            Attribute vomsIssuerCAAttribute =
                new Attribute(vomsIssuerCAIden, issuerEntity,
                              Calendar.getInstance(), null);
            vomsIssuerCAAttribute.addAttributeValue(issuerCA);
            attrColl.add(vomsIssuerCAAttribute);
        }

        //  4. VOMS primary FQAN
        AttributeIdentifier vomsPrimaryIden = null;
        try {
            vomsPrimaryIden =
                new AttributeIdentifier(new URI(AuthzProfileConstants.
                                                VOMS_PRIMARY_FQAN), 
                                        new URI(STRING_DATATYPE), false);
        } catch (URISyntaxException e) {
            throw new AttributeException(e);
        }
        Attribute vomsPrimaryAttribute =
            new Attribute(vomsPrimaryIden, issuerEntity,
                          Calendar.getInstance(), null);
        if ((attributes != null) && (attributes.size() > 0)) {
            vomsPrimaryAttribute.addAttributeValue(attributes.get(0));
        }
        attrColl.add(vomsPrimaryAttribute);

        // 5. VOMS FQAN
        AttributeIdentifier vomsAttrIden = null;
        try {
            vomsAttrIden =
                new AttributeIdentifier(new URI(AuthzProfileConstants.
                                                VOMS_FQAN), 
                                        new URI(STRING_DATATYPE), false);
        } catch (URISyntaxException e) {
            throw new AttributeException(e);
        }
        Attribute vomsAttribute = new Attribute(vomsAttrIden, issuerEntity,
                                                Calendar.getInstance(), null);

        if (attributes != null) {
            Iterator fqanIter = attributes.iterator();
            while (fqanIter.hasNext()) {
                vomsAttribute.addAttributeValue(fqanIter.next());
            }
        }
        attrColl.add(vomsAttribute);


        // optional
        // 6. VO host and port
        AttributeIdentifier hostIden = null;
        try {
            hostIden = 
                new AttributeIdentifier(new URI(AuthzProfileConstants.
                                                VOMS_DNS_PORT), 
                                        new URI(STRING_DATATYPE), false);
        } catch (URISyntaxException e) {
            throw new AttributeException(e);
        }
        Attribute hostAttribute =
            new Attribute(hostIden, issuerEntity, Calendar.getInstance(), null);
        hostAttribute.addAttributeValue(hostPort);
        attrColl.add(hostAttribute);

        // Add all attributes
        requestor.addAttributes(attrColl);
        return null;

    }

    public void close() throws CloseException {
    }
}
