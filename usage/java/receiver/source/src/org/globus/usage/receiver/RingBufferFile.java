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

package org.globus.usage.receiver;

import java.util.LinkedList;
import java.io.File;
import java.io.IOException;

import org.globus.usage.packets.CustomByteBuffer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class RingBufferFile implements RingBuffer {

    private static Log log = LogFactory.getLog(RingBufferFile.class);

    private RingBufferArray memoryPage;
    private RingBufferArray queuePage;
    private int queueSize;
    private int pageSize;
    private LinkedList pages;
    private File pageDir;

    public RingBufferFile(int size, File dir) {
        checkPageDirectory(dir);
        this.pageDir = dir;
        this.pageSize = size;
        this.pages = new LinkedList();
        this.memoryPage = new RingBufferArray(this.pageSize);
    }
        
    public RingBufferFile(int size) {
        this(size, new File("."));
    }
            
    private void checkPageDirectory(File dir) {
        if (!dir.exists()) {
            if (!dir.mkdirs()) {
                throw new IllegalArgumentException(
                                      "Failed to create page directory");
            }
        }
        
        if (!dir.exists() ||
            !dir.isDirectory() ||
            !dir.canRead() ||
            !dir.canWrite()) {
            throw new IllegalArgumentException("Invalid page directory");
        }
    }

    public synchronized CustomByteBuffer getNext() {
        while (this.queuePage == null || !this.queuePage.hasNext()) {
            try {
                this.queuePage = loadNextPage();
            } catch (InterruptedException e) {
                return null;
            }
        }
        CustomByteBuffer buf = this.queuePage.getNext();
        this.queueSize--;
        return buf;
    }

    private synchronized RingBufferArray loadNextPage() 
        throws InterruptedException {
        while(this.pages.isEmpty()) {
            wait();
        }
        File pageName = (File)this.pages.removeFirst();
        log.debug("Loading buffer page: " + pageName.getAbsolutePath());
        try {
            return RingBufferArray.read(pageName.getAbsolutePath());
        } catch (IOException e) {
            log.error("Failed to load buffer page", e);
        } finally {
            pageName.delete();
        }
        return null;
    }

    public synchronized boolean insert(CustomByteBuffer buff) {
        if (this.memoryPage.isFull()) {
            flush();
        } 
        return this.memoryPage.insert(buff);
    }

    public synchronized void flush() {
        try {
            // store current page
            File pageName = File.createTempFile(
                                   System.currentTimeMillis() + "-",
                                   ".tmp",
                                   this.pageDir);
            log.debug("Writting buffer page: " + pageName.getAbsolutePath());
            RingBufferArray.write(pageName.getAbsolutePath(), this.memoryPage);
            
            // add current page filename to list of pages
            this.pages.add(pageName);
            this.queueSize += this.memoryPage.getNumObjects();
            notify();
        } catch (IOException e) {
            log.error("Failed to flush buffer page", e);
        }
        
        // get a new page
        this.memoryPage = new RingBufferArray(this.pageSize);
    }

    public synchronized boolean isFull() {
        return false;
    }

    public synchronized boolean isEmpty() {
        return (this.pages.isEmpty() && this.memoryPage.isEmpty());
    }

    public synchronized int getCapacity() {
        return Integer.MAX_VALUE;
    }
    
    public synchronized int getNumObjects() {
        return this.memoryPage.getNumObjects() + this.queueSize;
    }
    
}
