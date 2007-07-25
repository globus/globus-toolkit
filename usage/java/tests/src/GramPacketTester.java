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

import junit.framework.TestCase;
import junit.framework.Test;
import junit.framework.Assert;
import junit.framework.TestSuite;

import org.globus.usage.packets.GramUsageMonitorPacket;
import org.globus.usage.packets.CustomByteBuffer;

public class GramPacketTester extends TestCase {
    
    public GramPacketTester(String name) {
	super(name);
    }

    public void testGram() {
        GramUsageMonitorPacket gramPack;
        GramUsageMonitorPacket gramPack2;
        java.util.Date now = new java.util.Date();
        CustomByteBuffer buf = new CustomByteBuffer(1500);

        gramPack = new GramUsageMonitorPacket();
        gramPack.setCreationTime(now);
        Assert.assertEquals("setCreationTime Failed",
                            gramPack.getCreationTime(),
                            now);
        gramPack.setLocalResourceManager("Fork");
        Assert.assertEquals("setLocalResourceManager Failed",
                            gramPack.getLocalResourceManager(),
                            "Fork");
        gramPack.setJobCredentialEndpointUsed(true);
        Assert.assertEquals("setJobCredentialEndpointUsed Failed",
                            gramPack.getJobCredentialEndpointUsed(),
                            true);
        gramPack.setFileStageInUsed(false);
        Assert.assertEquals("setFileStageInUsed Failed",
                            gramPack.isFileStageInUsed(),
                            false);
        gramPack.setFileStageOutUsed(true);
        Assert.assertEquals("setFileStageOutUsed Failed",
                            gramPack.isFileStageOutUsed(),
                            true);
        gramPack.setFileCleanUpUsed(false);
        Assert.assertEquals("getFileCleanUpUsed Failed",
                            gramPack.isFileCleanUpUsed(),
                            false);
        gramPack.setCleanUpHoldUsed(true);
        Assert.assertEquals("isCleanUpHoldUsed Failed",
                            gramPack.isCleanUpHoldUsed(),
                            true);
        gramPack.setJobType((byte) 1);
        Assert.assertEquals("setJobType Failed",
                            gramPack.getJobType(),
                            (byte) 1);
        gramPack.setGt2ErrorCode(2);
        Assert.assertEquals("setGt2ErrorCode Failed",
                            gramPack.getGt2ErrorCode(),
                            2);
        gramPack.setFaultClass((byte) 3);
        Assert.assertEquals("setFaultClass Failed",
                            gramPack.getFaultClass(),
                            (byte) 3);
        try
        {
            gramPack.setHostIP(java.net.InetAddress.getLocalHost());
        }
        catch (java.net.UnknownHostException e)
        {
            Assert.fail(e.toString());
            return;
        }
        gramPack.packCustomFields(buf);

        buf.rewind();

        gramPack2 = new GramUsageMonitorPacket();
        gramPack2.unpackCustomFields(buf);

	Assert.assertEquals("Component codeshould be 1",
			    gramPack.getComponentCode(), 1);
        Assert.assertEquals("Creation Time Mismatch",
                gramPack.getCreationTime(),
                gramPack2.getCreationTime());

        /* Strings get padded to fixed length when packed */
        String rm1 = gramPack.getLocalResourceManager();
        String rm2 = gramPack2.getLocalResourceManager();

        Assert.assertEquals("Local Resource Manager Mismatch",
                rm1,
                rm2.substring(0, rm1.length()));
        Assert.assertEquals("Job Creation Endpoint Used Mismatch",
                            gramPack.getJobCredentialEndpointUsed(),
                            gramPack2.getJobCredentialEndpointUsed());
        Assert.assertEquals("FileStageInUsed Mismatch",
                            gramPack.isFileStageInUsed(),
                            gramPack2.isFileStageInUsed());
        Assert.assertEquals("FileStageOut Mismatch",
                            gramPack.isFileStageOutUsed(),
                            gramPack2.isFileStageOutUsed());
        Assert.assertEquals("FileCleanUpUsed Mismatch",
                            gramPack.isFileCleanUpUsed(),
                            gramPack2.isFileCleanUpUsed());
        Assert.assertEquals("CleanUpHoldUsed Mismatch",
                            gramPack.isCleanUpHoldUsed(),
                            gramPack2.isCleanUpHoldUsed());
        Assert.assertEquals("JobType Mismatch",
                            gramPack.getJobType(),
                            gramPack2.getJobType());
        Assert.assertEquals("Gt2ErrorCode Mismatch",
                            gramPack.getGt2ErrorCode(),
                            gramPack2.getGt2ErrorCode());
        Assert.assertEquals("FaultClass Mismatch",
                            gramPack.getFaultClass(),
                            gramPack2.getFaultClass());
    }
}
