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

import org.globus.wsrf.security.authorization.attributes.AttributeInformation;

import java.util.Vector;

public class VomsCredentialInformation implements AttributeInformation {
    private Vector attrs = null;
    private String VO = null;
    private String hostport = null;
    // DN of the issuer of VOMS server certificae
    private String issuerDN = null;
    // DN of the VOMS server certificate CA
    private String issuerCADN = null;

    //no no-arg constructor

    public VomsCredentialInformation(Vector attrs,
                                     String VO,
                                     String hostport) {
        this(attrs, VO, hostport, null, null);
    }

    /**
     * @param attrs Vector of VOMS attributes
     * @param VO
     * @param hostport
     */
    public VomsCredentialInformation(Vector attrs,
                                     String VO,
                                     String hostport,
                                     String issuerDN_,
                                     String issuerCADN_) {
        this.attrs = attrs;
        this.VO = VO;
        this.hostport = hostport;
        this.issuerDN = issuerDN_;
        this.issuerCADN = issuerCADN_;
    }

    public Vector getAttrs() {
        return attrs;
    }

    public String getVO() {
        return VO;
    }

    public String getHostport() {
        return hostport;
    }

    public String getIssuerDN() {
        return this.issuerDN;
    }

    public String getIssuerCADN() {
        return this.issuerCADN;
    }

}
