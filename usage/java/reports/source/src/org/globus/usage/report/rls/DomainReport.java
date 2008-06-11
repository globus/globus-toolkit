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
package org.globus.usage.report.rls;

public class DomainReport {
    public static void main(String[] args) throws Exception {
        String newargs[] = new String[args.length+6];

        newargs[0] = "-t";
        newargs[1] = "rls_packets";
        newargs[2] = "-c";
        newargs[3] = "ip_address";
        newargs[4] = "-r";
        newargs[5] = "rlsiphistogram";

        for (int i = 0 ; i < args.length; i++) {
            newargs[i+6] = args[i];
        }

        org.globus.usage.report.common.DomainReport.main(newargs);
    }
}
