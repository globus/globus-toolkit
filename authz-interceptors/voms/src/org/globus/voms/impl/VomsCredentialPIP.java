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

package org.globus.voms.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.glite.voms.VOMSAttribute;
import org.glite.voms.VOMSValidator;
import org.glite.voms.PKIVerifier;
import org.glite.voms.PKIStore;
import org.glite.voms.ac.ACCerts;
import org.glite.voms.ac.ACValidator;

import javax.security.auth.Subject;
import javax.xml.rpc.handler.MessageContext;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Vector;
import java.util.HashMap;

// FIXME: need to validate without certificate chain validation, nothing in API
// allows for that.
public class VomsCredentialPIP implements VomsConstants {

    static int defaultRefresh = 3600000;

    private static Log logger =
	LogFactory.getLog(VomsCredentialPIP.class.getName());

    private String caStoreDir = null;
    private String vomsStoreDir = null;
    // FIXME: how can this be used?
    //private PKIStore pkiStore = null;
    //private PKIStore vomsStore = null;
    private boolean validate = false;
    private String vald = null;
    private Integer refreshTime = null;

    public void initialize(HashMap configs, String name) throws Exception {

        if (vomsStoreDir == null) {
            vomsStoreDir =
                (String) configs.get(VOMS_TRUST_STORE_DIR_PROP);
            logger.debug("found voms truststore configuration: " +
                         vomsStoreDir);
        }

        if (vald == null) {
            vald = (String) configs.get(VALIDATE);
            if (vald == null) {
                vald = "";
            }
            if (vald.equalsIgnoreCase("true")) {
                validate = true;
            }
        }


        if (caStoreDir == null) {
            caStoreDir = (String) configs.get(CA_TRUST_STORE_DIR_PROP);
            logger.debug("ca store directory " + caStoreDir);
        }

        if (refreshTime == null) {
            refreshTime = (Integer) configs.get(REFRESH_TIME_PROP);
            if (refreshTime != null) {
                logger.debug("found refresh configuration: " +
                             refreshTime.intValue() + " milliseconds");
            }
        }
        
        try {
            // FIXME: no way to set this on validator as yet.
            /*
            logger.debug("PKI Store with trustStore " + caStoreDir
                         + " and type " + PKIStore.TYPE_CADIR);
            pkiStore = new PKIStore(caStoreDir, PKIStore.TYPE_CADIR);
            pkiStore.stopRefresh();
            if (refreshTime != null) {
                pkiStore.rescheduleRefresh(refreshTime.intValue());
            } else {
                pkiStore.rescheduleRefresh(defaultRefresh);
            }
              */

            logger.debug("VOMS Store with trustStore " + vomsStoreDir);
            System.setProperty("VOMSDIR", vomsStoreDir);
            System.setProperty("CADIR", caStoreDir);
            // FIXME: no way to set this on validator as yet
            /*
            vomsStore = new PKIStore(vomsStoreDir, PKIStore.TYPE_VOMSDIR);
            if (refreshTime != null) {
                vomsStore.rescheduleRefresh(refreshTime.intValue());
            } else {
                vomsStore.rescheduleRefresh(defaultRefresh);
            }
            */
        } catch (IllegalArgumentException e) {
            //vomsStore = null;
            logger.warn("VOMS trust store not enabled, VOMS cert parsing " +
                    "disabled");
        } catch (Exception e) {
            //vomsStore = null;
            logger.error("Problem configuring VOMS trust store, VOMS cert " +
                         "parsing disabled");
        }
        
        logger.debug("VOMS PIP initialize complete");
    }

    public void collectAttributes(Subject peerSubject,
                                  String peerIdentity,
                                  MessageContext context) throws Exception {

        /*
        if (vomsStore == null) {
            logger.debug("no VOMS trust store, VOMS cert parsing disabled");
            return;
        }
          */

        Set publicCreds =
            peerSubject.getPublicCredentials(X509Certificate[].class);
        Iterator iter = publicCreds.iterator();

        Vector rolesVector = new Vector();
        String VO = null;
        String hostport = null;
        String issuerDN = null;
        String issuerCADN = null;

        boolean parameterSet = false;
        while (iter.hasNext()) {
            X509Certificate certRev[] = (X509Certificate[])iter.next();
            int size = certRev.length;
            X509Certificate cert[] = new X509Certificate[size];
            for (int i=0; i<size; i++) {
                cert[i] = certRev[size-i-1];
            }
            logger.debug("Certificate reversed");

            VOMSValidator validator = new VOMSValidator(cert);
                        
            if (validate) {
                logger.debug("Validating");
                // this calls parse and validate
                validator = validator.validate();
                logger.debug("Verify completed");
            } else {
                logger.debug("No validation, parsing");
                validator = validator.parse();
            }

            // FIXME: assuming one VO, one VOMS server and bunch of roles
            // across all the certificates in the public certificates
            logger.debug("VOMSValidator.parse with certificate chain");

            List vector = validator.getVOMSAttributes();
            if (vector.size() != 0) {
                logger.debug("getVOMSAttributes(): "
                             + vector.size());
                for (int j=0; j<vector.size(); j++) {
                    VOMSAttribute attrib =
                        (VOMSAttribute)vector.get(j);

                    if (!parameterSet) {
                        issuerDN = attrib.getIssuer();
                        VO = attrib.getVO();
                        hostport = attrib.getHostPort();
                        ACCerts certs = attrib.getCertList();
                        Iterator certsIter = certs.getCerts().iterator();
                        X509Certificate lastCert = null;
                        while (certsIter.hasNext()) {
                            lastCert = (X509Certificate) certsIter.next();
                        }
                        issuerCADN = lastCert.getIssuerDN().getName();
                        parameterSet = true;
                    }
                    
                    List fqan = attrib.getFullyQualifiedAttributes();
                    for (int k=0; k<fqan.size(); k++) {
                        String str = (String)fqan.get(k);
                        rolesVector.add(str);
                    }
                }
            }
        }
        if (logger.isDebugEnabled()) {
            logger.debug("VO " + VO);
            logger.debug("hostport " + hostport);
            logger.debug("Issuer DN " + issuerDN);
            logger.debug("Issuer CA DN " + issuerCADN);
            for (int i=0; i<rolesVector.size(); i++) {
                logger.debug("\nRoles " + rolesVector.get(i));
            }
        }

        VomsCredentialInformation info =
                new VomsCredentialInformation(rolesVector, VO, hostport,
                                              issuerDN, issuerCADN);

        peerSubject.getPublicCredentials().add(info);
    }
}
