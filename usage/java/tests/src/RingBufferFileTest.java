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

import java.util.LinkedList;
import java.io.IOException;

import junit.framework.TestCase;

import org.globus.usage.receiver.RingBufferFile;
import org.globus.usage.packets.CustomByteBuffer;

public class RingBufferFileTest extends TestCase {

    public void testPaging() {
        final RingBufferFile f = new RingBufferFile(300);

        Thread t = (new Thread() {
                public void run() {
                    for (int i=0;i<1600;i++) {
                        CustomByteBuffer b = new CustomByteBuffer(16);
                        b.putInt(i);
                        f.insert(b);
                        try {
                            Thread.sleep(10);
                        } catch (Exception e) {}
                    }
                    f.flush();
                    System.out.println(f.getNumObjects());
                }
            });
        t.start();

        for (int i=0;i<1600;i++) {
            CustomByteBuffer b = f.getNext();
            b.rewind();
            int ii = b.getInt();
            int size = f.getNumObjects();
            System.out.println("a: " + i + " " + ii + " " + size);
            assertEquals(i, ii);
            try {
                Thread.sleep(20);
            } catch (Exception e) {}
        }
        
        System.out.println(f.getNumObjects());
    }


}
