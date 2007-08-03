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

import java.util.HashMap;
import java.util.StringTokenizer;

/*General-purpose parser for GridFTP, RLS, and C WS Core usage
packets, which contain text-formatted fields of the form KEY=VALUE
KEY=VALUE.  One gotcha is that VALUE may be a quoted string that may
contain spaces.*/

public class PacketFieldParser {

    HashMap pairs;

    public PacketFieldParser() {}

    public PacketFieldParser(String input) {
	parseString(input);
    }

    public void parseString(String input) {
        final int BEGIN = 0;
        final int ESCAPE = 1;
        final int EQUAL = 2;
        final int VAL = 3;
        final int QUOTED_VAL = 4;
        final int INVALID = 5;
        final int UNQUOTED_VAL = 6;

	this.pairs = new HashMap();

        StringTokenizer st = new StringTokenizer(input, " \\\"=", true);

        int state = BEGIN;
        String var = null;
        String val = null;

        while (state != INVALID && st.hasMoreTokens()) {
            String token = st.nextToken();

            switch (state) {
                case BEGIN:
                    var = null;
                    val = null;
                    if (token.equals(" ")) {
                        state = BEGIN;
                    } else if (token.equals("\"") || token.equals("=")) {
                        state = INVALID;
                    } else {
                        var = token;
                        state = EQUAL;
                    }
                    break;
                case EQUAL:
                    if (token.equals("=")) {
                        state = VAL;
                    } else {
                        state = INVALID;
                    }
                    break;
                case VAL:
                    if (token.equals("\"")) {
                        val = "";
                        state = QUOTED_VAL;
                    } else {
                        val = token;
                        state = UNQUOTED_VAL;
                    }
                    break;
                case UNQUOTED_VAL:
                    if (token.equals(" ")) {
                        this.pairs.put(var, val);
                        var = null;
                        val = null;
                        state = BEGIN;
                    } else {
                        val = val + token;
                        state = UNQUOTED_VAL;
                    }
                    break;
                case QUOTED_VAL:
                    if (token.equals("\\")) {
                        state = ESCAPE;
                    } else if (token.equals("\"")) {
                        state = BEGIN;
                        this.pairs.put(var, val);
                        var = null;
                        val = null;
                    } else {
                        /* Remain in QUOTED_VAL state */
                        val = val + token;
                    }
                    break;
                case ESCAPE:
                    if (token.equals("\\") || token.equals("\"")) {
                        val = val + token;
                    } else {
                        /* INVALID ESCAPE */
                        state = INVALID;
                    }
                    break;
            }
        }

        if (state == VAL || state == UNQUOTED_VAL)
        {
            this.pairs.put(var, val);
        }
    }

    public int countFields() {
	return this.pairs.size();
    }

    /*If the requested field doesn't exist, return a zero or the empty string instead
      of panicking.  Even if we lose some info, the best thing is to keep going and try
      to parse the rest.*/
    public int getInt(String key) {
	if (!this.pairs.containsKey(key)) {
	    return 0;
	}
	return Integer.parseInt((String)this.pairs.get(key));
    }

    public long getLong(String key) {
	if (!this.pairs.containsKey(key)) {
	    return 0L;
	}
	return Long.parseLong((String)this.pairs.get(key));
    }

    public double getDouble(String key) {
	if (!this.pairs.containsKey(key)) {
	    return (double)0.0;
	}
	return Double.parseDouble((String)this.pairs.get(key));
    }

    public String getString(String key)  {
	if (!this.pairs.containsKey(key)) {
	    return "";
	}
	return (String)this.pairs.get(key);
    }   
}
