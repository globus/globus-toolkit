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
 * Jonathan DiCarlo
 * Simple program which connects to the running Receiver through a control socket
 * and outputs status on whether receiver is running, how many packets have been logged, etc.
 * Or reports failure if there is no response.*/

import java.net.Socket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.io.IOException;
import java.net.SocketException;
import java.io.PrintWriter;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Babysitter {

    private static final int controlPort = 4811;

    public static void main(String[] args) throws IOException {

        Socket controlSocket = null;
        PrintWriter out = null;
        BufferedReader in = null;
	String result;

        try {
            controlSocket = new Socket(InetAddress.getLocalHost(), controlPort);
            out = new PrintWriter(controlSocket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(
                                        controlSocket.getInputStream()));


	    out.println(args[0]);
	    System.out.println("Got this from listener:");
	    do {
		result = in.readLine();
		if (result != null) {
		    System.out.println(result);
		}
	    } while (result != null);
        } catch (UnknownHostException e) {
            System.err.println("Can't resolve localhost, for some reason...");
        } catch (IOException e) {
            System.err.println("Couldn't open the socket; receiver may be down. ");
        }
	
	try {
	    out.close();
	    in.close();
	    controlSocket.close();
	}
	catch (Exception e) {}
    }

}

