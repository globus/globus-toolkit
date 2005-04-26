/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

package org.globus.usage.packets;

import java.util.HashMap;

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
	boolean containsQuotes = false;
	String[] fields;
	String[] substrings;
	int i, j;

	this.pairs = new HashMap();

	/*First, identify any quoted substrings.  Break the string up into
	  quoted and non-quoted substrings.  Parse each non-quoted section
	  separately.*/

	substrings = input.split("\"");

	for (i = 0; i < substrings.length; i += 2) {
	    String quoted;
	    String nonQuoted;

	    /*Odd-numbered substrings are unquoted, even-numbered are quoted.
	      That's why we're counting by twos.*/
	    nonQuoted = substrings[i];
	    if (i + 1 < substrings.length) {
		quoted = substrings[i + 1];
	    } else {
		quoted = null;
	    }

	    /*To parse a non-quoted section, first split on space, then split
	      each result of that on '=' to get key and value; store both
	      in a hash as strings.*/
	    
	    fields = nonQuoted.split(" ");
	    
	    for (j = 0; j< fields.length; j++) {
		String[] temp;
		
		temp = fields[j].split("=");
		//now temp[0] is key, temp[1] is value

		if (temp.length > 1) {
		    //the value is after the equals.
		    this.pairs.put(temp[0], temp[1]);
		} else
		if (j == fields.length - 1 && quoted != null) {
		    /*If this is the last field of a nonquoted substring
		      and there's a quoted substring after this, use the
		      whole quoted substring as the value:*/
		    this.pairs.put(temp[0], quoted);
		}
		else {
		    //Probably leftovers from the split; ignore.
		}
	    }
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
