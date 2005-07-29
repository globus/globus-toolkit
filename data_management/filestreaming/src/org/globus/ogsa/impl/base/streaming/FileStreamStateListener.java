/*
 * This file is licensed under the terms of the Globus Toolkit Public
 * License, found at http://www.globus.org/toolkit/download/license.html.
 */

package org.globus.ogsa.impl.base.streaming;

public interface FileStreamStateListener {
    public void fileStreamStarted();
    public void fileStreamStopped();
}
