package org.globus.usage.packets;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import java.util.Date;
import java.nio.ReadOnlyBufferException;
import java.sql.Timestamp;

/*GRAM usage monitor packets, in addition to the fields in IPTimeMonitorPacket,
include the following:
    - job created timestamp
    - scheduler type (Fork, PBS, LSF, Condor, SGE, etc...)
    - jobCredentialEndpoint present flag (i.e. do they use server-side user
     proxies)
    - fileStageIn present flag
    - fileStageOut present flag
    - fileCleanUp present flag
    - CleanUpHold flag
    - job type (Single, Multiple, MPI, Condor)
    - gt2 error code if present and Failed
    - fault class name or identifier if Failed
*/
public class GramUsageMonitorPacket extends IPTimeMonitorPacket {

    static Log logger = LogFactory.getLog(GramUsageMonitorPacket.class);

    private static byte FALSE   = 0;
    private static byte TRUE    = 1;

    //job created timestamp
    private Date creationTime;

    //scheduler type
    private final static int MAX_SCHEDULER_TYPE_SIZE = 20;
    private String schedulerType;

    //jobCredentialEndpoint present flag
    private boolean usedJobCredentialEndpoint;

    //fileStageIn present flag
    private boolean usedFileStageIn;

    //fileStageOut present flag
    private boolean usedFileStageOut;

    //fileCleanUp present flag
    private boolean usedFileCleanUp;

    //CleanUpHold flag
    private boolean usedCleanUpHold;

    //job type
    private static final byte JOB_TYPE_UNKOWN    = 0;
    private static final byte JOB_TYPE_SINGLE    = 1;
    private static final byte JOB_TYPE_MULTIPLE  = 2;
    private static final byte JOB_TYPE_MPI       = 3;
    private static final byte JOB_TYPE_CONDOR    = 4;
    private String jobType;     //not JobTypeEnumeration to avoid dependency

    //gt2 error
    private int gt2ErrorCode;

    //fault class name
    private static final byte FAULT_CLASS_UNKNOWN                   = 0
    private static final byte FAULT_CLASS_CREDENTIAL_SERIALIZATION  = 1;
    private static final byte FAULT_CLASS_EXECUTION_FAILED          = 2;
    private static final byte FAULT_CLASS_FAULT                     = 3;
    private static final byte FAULT_CLASS_FILE_PERMISSIONS          = 4;
    private static final byte FAULT_CLASS_INSUFFICIENT_CREDENTIALS  = 5;
    private static final byte FAULT_CLASS_INTERNAL                  = 6;
    private static final byte FAULT_CLASS_INVALID_CREDENTIALS       = 7;
    private static final byte FAULT_CLASS_INVALID_PATH              = 8;
    private static final byte FAULT_CLASS_SERVICE_LEVEL_AGREEMENT   = 9;
    private static final byte FAULT_CLASS_STAGING                   = 10;
    private static final byte FAULT_CLASS_UNSUPPORTED_FEATURE       = 11;
    private Class faultClass;

    public void setCreationTime(Date creationTime)
    {
        this.creationTime = creationTime;
    }

    public Date getCreationTime() {
        return this.creationTime;
    }

    public void setCreationTime(String schedulerType)
    {
        this.schedulerType = schedulerType;
    }

    public String getSchedulerType() {
        return this.schedulerType;
    }

    public void setUsedJobCredentialEndpoint(boolean usedJobCredentialEndpoint)
    {
        this.usedJobCredentialEndpoint = usedJobCredentialEndpoint;
    }

    public String getUsedJobCredentialEndpoint() {
        return this.usedJobCredentialEndpoint;
    }

    public void setUsedFileStageIn(boolean usedFileStageIn)
    {
        this.usedFileStageIn = usedFileStageIn;
    }

    public String getUsedFileStageIn() {
        return this.usedFileStageIn;
    }

    public void setUsedFileStageOut(boolean usedFileStageOut)
    {
        this.usedFileStageOut = usedFileStageOut;
    }

    public String getUsedFileStageOut() {
        return this.usedFileStageOut;
    }

    public void setUsedFileCleanUp(boolean usedFileCleanUp)
    {
        this.usedFileCleanUp = usedFileCleanUp;
    }

    public String getUsedFileCleanUp() {
        return this.usedFileCleanUp;
    }

    public void setUsedCleanUpHold(boolean usedCleanUpHold)
    {
        this.usedCleanUpHold = usedCleanUpHold;
    }

    public String getUsedCleanUpHold() {
        return this.usedCleanUpHold;
    }

    public void setJobType(String jobType)
    {
        this.jobType = jobType;
    }

    public String getJobType() {
        return this.jobType;
    }

    public void setGt2ErrorCode(int gt2ErrorCode)
    {
        this.gt2ErrorCode = gt2ErrorCode;
    }

    public int getGt2ErrorCode() {
        return this.gt2ErrorCode;
    }

    public void setFaultClass(Class faultClass)
    {
        this.faultClass = faultClass;
    }

    public Class getFaultClass() {
        return this.faultClass;
    }

    private short getIPVersion()
    {
        if (this.senderAddress instanceof Inet6Address)
            return 6;
        else
            return 4;
    }

    //TODO update everything bellow

    public void packCustomFields(CustomByteBuffer buf)
    {
        super.packCustomFields(buf);

        //creationTime
        buf.putLong(creationTime.getTime());

        //schedulerType
        int schedulerTypeActualLength = schedulerType.length();
        String schedulerTypeFixedLength = null;
        if (schedulerTypeActualLength > MAX_SCHEDULER_TYPE_SIZE)
        {
            //truncate schedulerType string
            schedulerTypeFixedLength
                = schedulerType.substring(0, MAX_SCHEDULER_TYPE_SIZE);
        }
        else if (schedulerTypeActualLength < MAX_SCHEDULER_TYPE_SIZE)
        {
            //pad schedulerType string
            schedulerTypeFixedLength
                = schedulerType
                + new char[MAX_SCHEDULER_TYPE_SIZE - schedulerTypeActualLength];
        }
        else
        {
            //do nothing to schedulerType string
            schedulerTypeFixedLength = schedulerType;
        }
        byte[] schedulerTypeFixedBytes = schedulerTypeFixedLength.getBytes();

        //usedJobCredentialEndpoint
        buf.pack(this.usedJobCredentialEndpoint?TRUE:FALSE);

        //usedFileStageIn
        buf.pack(this.usedFileStageIn?TRUE:FALSE);

        //usedFileStageOut
        buf.pack(this.usedFileStageOut?TRUE:FALSE);

        //usedFileCleanUp
        buf.pack(this.usedFileCleanUp?TRUE:FALSE);

        //usedCleanUpHold
        buf.pack(this.usedCleanUpHold?TRUE:FALSE);

        //jobType
        buf.pack(jobTypeToByte(this.jobType));

        //gt2ErrorCode
        buf.packInt(this.gt2ErrorCode);

        //faultClass
        buf.pack(GramUsageMonitorPacket.faultClassToByte(this.faultClass));
    }
   
    public void unpackCustomFields(CustomByteBuffer buf)
    {
        super.unpackCustomFields(buf);

        //creationTime
        this.creationTime = new Date(buf.getLong());

        //schedulerType
        byte[] schedulerTypeBytes = new byte[MAX_SCHEDULER_TYPE_SIZE];
        buf.get(schedulerTypeBytes);
        this.schedulerType = new String(schedulerTypeBytes);

        //usedJobCredentialEndpoint
        this.usedJobCredentialEndpoint = (buf.get()==1?true:false);

        //usedFileStageIn
        this.usedFileStageIn = (buf.get()==1?true:false);

        //usedFileStageOut
        this.usedFileStageOut = (buf.get()==1?true:false);

        //usedFileCleanUp
        this.usedFileCleanUp = (buf.get()==1?true:false);

        //usedCleanUpHold
        this.usedCleanUpHold = (buf.get()==1?true:false);

        //jobType
        this.jobType = byteToJobType(buf.get());

        //gt2ErrorCode
        this.gt2ErrorCode = buf.getInt();

        //faultClass
        this.faultClass = GramUsageMonitorPacket.byteToFaultClass(buf.get());
    }

    /**
     * Converts a GRAM job type to it's corresponding byte code.
     *
     * @returns The byte code associated with the given GRAM job type, or
     *          JOB_TYPE_UNKNOWN if the job type string isn't recognized.
     */
    private static byte jobTypeToByte(String jobType)
    {
        if (jobType.getName().equals("mpi"))
        {
            return JOB_TYPE_MPI;
        } else
        if (jobType.getName().equals("single"))
        {
            return JOB_TYPE_SINGLE;
        } else
        if (jobType.getName().equals("multiple"))
        {
            return JOB_TYPE_MULTIPLE;
        } else
        if (jobType.getName().equals("condor"))
        {
            return JOB_TYPE_CONDOR;
        } else
        {
            return JOB_TYPE_UNKNOWN;
        }
    }

    /**
     * Converts the byte code associated with the given GRAM job type
     * to the job type String representation.
     *
     * @returns The String representation of the job type assocated with the
     *          given byte code, or null if the byte code is JOB_TYPE_UNKONWN or
     *          unrecognized.
     */
    private static String byteToJobType(byte jobTypeByte)
    {
        switch (jobTypeByte)
        {
         case JOB_TYPE_UNKNOWN:
         {
            return null;
         }
         case JOB_TYPE_MPI:
         {
            return "mpi";
         }
         case JOB_TYPE_SINGLE:
         {
            return "single";
         }
         case JOB_TYPE_MULTIPLE:
         {
            return "multiple";
         }
         case JOB_TYPE_CONDOR:
         {
            return "condor";
         }
         default:
         {
            return null;
         }
        }
    }

    /**
     * Converts a GRAM fault Class object to it's associated byte code.
     *
     * @returns The byte code associated with the given GRAM fault class, or
     *          FAULT_CLASS_UNKOWN if the given Class object is not a
     *          recognized GRAM fault class.
     */
    private static byte faultClassToByte(Class faultClass)
    {
        if (faultClass.getName().equals(
                "org.globus.exec.generated.CredentialSerializationFaultType"))
        {
            return FAULT_CLASS_CREDENTIAL_SERIALIZATION;
        } else
        if (faultClass.getName().equals(
            "org.globus.exec.generated.ExecutionFailedFaultType"))
        {
            return FAULT_CLASS_EXECUTION_FAILED;
        } else
        if (faultClass.getName().equals(
            "org.globus.exec.generated.FaultType"))
        {
            return FAULT_CLASS_FAULT;
        } else
        if (faultClass.getName().equals(
            "org.globus.exec.generated.FilePermissionsFaultType"))
        {
            return FAULT_CLASS_FILE_PERMISSIONS;
        } else
        if (faultClass.getName().equals(
                "org.globus.exec.generated.InsufficientCredentialsFaultType"))
        {
            return FAULT_CLASS_INSUFFICIENT_CREDENTIALS;
        } else
        if (faultClass.getName().equals(
                "org.globus.exec.generated.InternalFaultType"))
        {
            return FAULT_CLASS_INTERNAL;
        } else
        if (faultClass.getName().equals(
                "org.globus.exec.generated.InvalidCredentialsFaultType"))
        {
            return FAULT_CLASS_INVALID_CREDENTIALS;
        } else
        if (faultClass.getName().equals(
                "org.globus.exec.generated.InvalidPathFaultType"))
        {
            return FAULT_CLASS_INVALID_PATH;
        } else
        if (faultClass.getName().equals(
                "org.globus.exec.generated.ServiceLevelAgreementFaultType"))
        {
            return FAULT_CLASS_SERVICE_LEVEL_AGREEMENT;
        } else
        if (faultClass.getName().equals(
                "org.globus.exec.generated.StagingFaultType"))
        {
            return FAULT_CLASS_STAGING;
        } else
        if (faultClass.getName().equals(
                "org.globus.exec.generated.UnsupportedFeatureFaultType"))
        {
            return FAULT_CLASS_UNSUPPORTED_FEATURE;
        } else
        {
            return FAULT_CLASS_UNKNOWN;
        }
    }

    /**
     * Converts the byte code associated with a GRAM fault class to a
     * class instance.
     *
     * @returns a GRAM fault Class object or null if a FAULT_CLASS_UNKNOWN
     *          or unrecognized byte was received.
     */
    private static Class byteToFaultClass(byte faultClassByte)
    {
        try {
            switch (faultClassByte)
            {
            case FAULT_CLASS_UNKNOWN:
            {
                return null;
            }
            case FAULT_CLASS_CREDENTIAL_SERIALIZATION:
            {
                return Class.forName(
                "org.globus.exec.generated.CredentialSerializationFaultType");
            }
            case FAULT_CLASS_EXECUTION_FAILED:
            {
                return Class.forName(
                "org.globus.exec.generated.ExecutionFailedFaultType");
            }
            case FAULT_CLASS_FAULT:
            {
                return Class.forName(
                "org.globus.exec.generated.FaultType");
            }
            case FAULT_CLASS_FILE_PERMISSIONS:
            {
                return Class.forName(
                "org.globus.exec.generated.FilePermissionsFaultType");
            }
            case FAULT_CLASS_INSUFFICIENT_CREDENTIALS:
            {
                return Class.forName(
                "org.globus.exec.generated.InsufficientCredentialsFaultType");
            }
            case FAULT_CLASS_INTERNAL:
            {
                return Class.forName(
                "org.globus.exec.generated.InternalFaultType");
            }
            case FAULT_CLASS_INVALID_CREDENTIALS:
            {
                return Class.forName(
                "org.globus.exec.generated.InvalidCredentialsFaultType");
            }
            case FAULT_CLASS_INVALID_PATH:
            {
                return Class.forName(
                "org.globus.exec.generated.InvalidPathFaultType");
            }
            case FAULT_CLASS_SERVICE_LEVEL_AGREEMENT:
            {
                return Class.forName(
                "org.globus.exec.generated.ServiceLevelAgreementFaultType");
            }
            case FAULT_CLASS_STAGING:
            {
                return Class.forName(
                "org.globus.exec.generated.StagingFaultType");
            }
            case FAULT_CLASS_UNSUPPORTED_FEATURE:
            {
                return Class.forName(
                "org.globus.exec.generated.UnsupportedFeatureFaultType");
            }
            default:
            {
                return null;
            }
            }
        } catch (Exception e)
        {
            return null;
        }
    }

    public void display()
    {
        super.display();

        logger.info("creationTime = "+creationTime);
        logger.info("schedulerType = "+schedulerType);
        logger.info("usedJobCredentialEndpoint = "+usedJobCredentialEndpoint);
        logger.info("usedFileStageIn = "+usedFileStageIn);
        logger.info("usedFileStageOut = "+usedFileStageOut);
        logger.info("usedFileCleanUp = "+usedFileCleanUp);
        logger.info("usedCleanUpHold = "+usedCleanUpHold);
        logger.info("jobType = "+jobType);
        logger.info("gt2ErrorCode = "+gt2ErrorCode);
        logger.info("faultClass = "+faultClass);
    }

    public String toSQL()
    {
        StringBuffer sqlCommand = new StringBuffer("(");
        sqlCommand.append("creation_time,");
        sqlCommand.append("scheduler_type,");
        sqlCommand.append("used_job_credential_endpoint,");
        sqlCommand.append("used_stage_in,");
        sqlCommand.append("used_file_stage_out,");
        sqlCommand.append("used_file_clean_up,");
        sqlCommand.append("used_clean_up_hold,");
        sqlCommand.append("job_type,");
        sqlCommand.append("gt2_error_code,");
        sqlCommand.append("fault_class");
        sqlCommand.append(") VALUES ('");
        sqlCommand.append("'").append(this.creationTime).append("'");
        sqlCommand.append("'").append(this.schedulerType).append("'");
        sqlCommand.append("'").append(this.usedJobCredentialEndpoint)
                  .append("'");
        sqlCommand.append("'").append(this.usedFileStageIn).append("'");
        sqlCommand.append("'").append(this.usedFileStageOut).append("'");
        sqlCommand.append("'").append(this.usedFileCleanUp).append("'");
        sqlCommand.append("'").append(this.usedCleanUpHold).append("'");
        sqlCommand.append("'").append(this.jobType).append("'");
        sqlCommand.append("'").append(this.gt2ErrorCode).append("'");
        sqlCommand.append("'").append(this.faultClass).append("'");
        sqlCommand.append("')");

        return sqlCommand.toString();
    }
}
