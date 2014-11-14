
// Messages should not end with newline
#define MESSAGE_BUFFER_SIZE 1024

#define SomeError(hdfs_handle, msg) \
    char * formatted_msg = (char *)globus_malloc(MESSAGE_BUFFER_SIZE); \
    char * user = hdfs_handle ? hdfs_handle->username : NULL; \
    char * path = hdfs_handle ? hdfs_handle->pathname : NULL; \
    char * host = hdfs_handle ? hdfs_handle->local_host : NULL; \
    snprintf(formatted_msg, MESSAGE_BUFFER_SIZE, "%s (host=%s, user=%s, path=%s)", msg, host, user, path); \
    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "%s\n", formatted_msg);
    

#define GenericError(hdfs_handle, msg, rc) \
    SomeError(hdfs_handle, msg) \
    rc = GlobusGFSErrorGeneric(formatted_msg); \
    globus_free(formatted_msg);


#define SystemError(hdfs_handle, msg, rc) \
    SomeError(hdfs_handle, msg) \
    rc = GlobusGFSErrorSystemError(formatted_msg, errno); \
    globus_free(formatted_msg);


#define MemoryError(hdfs_handle, msg, rc) \
    SomeError(hdfs_handle, msg) \
    rc = GlobusGFSErrorMemory(formatted_msg); \
    globus_free(formatted_msg);

