/*
 * This file is licensed under the terms of the Globus Toolkit Public
 * License, found at http://www.globus.org/toolkit/download/license.html.
 */
package org.globus.ogsa.impl.base.multirft;

import org.globus.ogsa.GridServiceException;


/**
   Exception thrown by database access package
*/
public class RftDBException
    extends GridServiceException {
    public RftDBException() {
        super();
    }

    public RftDBException(String message) {
        super(message);
    }

    public RftDBException(String message, Exception e) {
        super(message);
    }

    public RftDBException(Exception e) {
        super(e);
    }
}
