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
package org.globus.voms.impl;

public class AuthzProfileConstants {

    public static final String VO_ATTRIBUTE =
        "http://authz-interop.org/xacml/subject/vo";

    public static final String VOMS_FQAN =
        "http://authz-interop.org/xacml/subject/voms-fqan";

    public static final String VOMS_PRIMARY_FQAN =
        "http://authz-interop.org/xacml/subject/voms-primary-fqan";

    public static final String VO_SIGNING_SUBJECT =
            "http://authz-interop.org/xacml/subject/voms-signing-subject";

    public static final String VO_SIGNING_ISSUER =
        "http://authz-interop.org/xacml/subject/voms-signing-issuer";

    // Optional
    public static final String VOMS_DNS_PORT =
        "http://authz-interop.org/xacml/subject/voms-dns-port";
}
