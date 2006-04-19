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

package org.globus.usage.packets;

import java.net.InetAddress;

public class Util {

    public static String getAddressAsString(InetAddress address) {
        return getAddressAsString(address, 64);
    }
    
    public static String getAddressAsString(InetAddress address, int max) {
        String strAddr = null;
	if (address == null) {
            strAddr = "unknown";
        } else {
            strAddr = address.toString();
            if (strAddr.length() > max) {
                strAddr = "/" + address.getAddress();
                if (strAddr.length() > max) {
                    strAddr = strAddr.substring(0, max);
                }
            }
	}
        return strAddr;
    }

}
