package org.globus.usage.packets;

import java.util.HashMap;

/*General-purpose parser for GridFTP and C WS Core usage packets,
which contain text-formatted fields of the form KEY=VALUE KEY=VALUE.
One gotcha is that VALUE may be a quoted string that may contain
spaces.*/

class PacketFieldParser {

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

		if (j == fields.length - 1 && quoted != null) {
		    /*If this is the last field of a nonquoted substring
		      and there's a quoted substring after this, use the
		      whole quoted substring as the value:*/
		    this.pairs.put(temp[0], quoted);
		}
		else {
		    this.pairs.put(temp[0], temp[1]);
		}
	    }
	}
    }

    public int countFields() {
	return this.pairs.size();
    }

    public int getInt(String key) throws NumberFormatException, Exception {
	if (!this.pairs.containsKey(key)) {
	    throw new Exception("No field named " + key);
	}
	return Integer.parseInt((String)this.pairs.get(key));
    }

    public long getLong(String key) throws NumberFormatException, Exception {
	if (!this.pairs.containsKey(key)) {
	    throw new Exception("No field named " + key);
	}
	return Long.parseLong((String)this.pairs.get(key));
    }

    public double getDouble(String key) throws NumberFormatException, Exception {
	if (!this.pairs.containsKey(key)) {
	    throw new Exception("No field named " + key);
	}
	return Double.parseDouble((String)this.pairs.get(key));
    }

    public String getString(String key) throws Exception {
	if (!this.pairs.containsKey(key)) {
	    throw new Exception("No field named " + key);
	}
	return (String)this.pairs.get(key);
    }   
}
