/*
 * This file is licensed under the terms of the Globus Toolkit Public
 * License, found at http://www.globus.org/toolkit/download/license.html.
 */
package org.globus.ogsa.impl.base.streaming;

import java.util.ListResourceBundle;

public class Resources extends ListResourceBundle {
    public Object[][] getContents() {
        return contents;
    }
    static final Object[][] contents = {
        {
            "InvalidPathFault00",
            "Unable to open {0} for writing."
        },
        {
            "InvalidUrlFault00",
            "Malformed url \"{0}\"."
        },
        {
            "InvalidUrlFault01",
            "Unsupported URL scheme \"{0}\"."
        },
        {
            "FileTransferFault00",
            "Error accessing URL \"{0}\"."
        },
        {
            "CredentialsFault00",
            "Insufficient credentials to access URL \"{0}\"."
        }
    };
}
