CREATE TABLE  unknown_packets(
    id BIGSERIAL,
    componentcode SMALLINT NOT NULL,
    versioncode SMALLINT NOT NULL,
    contents BYTEA NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE rft_packets(
    id BIGSERIAL,
    component_code SMALLINT NOT NULL,
    version_code SMALLINT NOT NULL,
    send_time TIMESTAMP,
    ip_address VARCHAR(64) NOT NULL,
    request_type SMALLINT NOT NULL,
    number_of_files BIGINT,
    number_of_bytes BIGINT,
    number_of_resources BIGINT,
    creation_time BIGINT,
    factory_start_time BIGINT,
    PRIMARY KEY (id)
);
CREATE INDEX rft_send_time_index ON rft_packets(DATE(send_time));

CREATE TABLE java_ws_core_packets(
    id BIGSERIAL,
    component_code SMALLINT NOT NULL,
    version_code SMALLINT NOT NULL,
    send_time TIMESTAMP,
    ip_address VARCHAR(64) NOT NULL,
    container_id INT,
    container_type SMALLINT,
    event_type SMALLINT,
    service_list TEXT,
    optional_val INT,
    version_major SMALLINT,
    version_minor SMALLINT,
    version_micro SMALLINT,
    port_number INT,
    thread_pool_size SMALLINT,
    thread_count SMALLINT,
    max_threads SMALLINT,
    threads_high_water_mark SMALLINT,
    service_request_count INT,
    jvm_info VARCHAR(64)
);
CREATE INDEX java_ws_core_send_time_index ON java_ws_core_packets(DATE(send_time));

CREATE TABLE gram_packets(
    id BIGSERIAL,
    component_code SMALLINT NOT NULL,
    version_code SMALLINT NOT NULL,
    send_time TIMESTAMP,
    ip_address VARCHAR(64) NOT NULL,
    creation_time TIMESTAMP,
    scheduler_type VARCHAR(20),
    job_credential_endpoint_used BOOLEAN,
    file_stage_in_used BOOLEAN,
    file_stage_out_used BOOLEAN,
    file_clean_up_used BOOLEAN,
    clean_up_hold_used BOOLEAN,
    job_type SMALLINT,
    gt2_error_code INT,
    fault_class SMALLINT,
    PRIMARY KEY(id)
);

CREATE INDEX gram_send_time_index ON gram_packets(DATE(send_time));

CREATE TABLE c_ws_core_packets(
    id BIGSERIAL,
    component_code SMALLINT NOT NULL,
    version_code SMALLINT NOT NULL,
    send_time TIMESTAMP,
    ip_address VARCHAR(64) NOT NULL,
    container_id INT,
    event_type SMALLINT,
    service_list TEXT,
    PRIMARY KEY(id)
);
CREATE INDEX c_ws_core_send_time_index ON c_ws_core_packets(DATE(send_time));

CREATE TABLE rls_packets(
    id BIGSERIAL,
    component_code SMALLINT NOT NULL,
    version_code SMALLINT NOT NULL,
    send_time TIMESTAMP,
    ip_address VARCHAR(64) NOT NULL,
    rls_version VARCHAR(64),
    uptime BIGINT,
    lrc BOOLEAN,
    rli BOOLEAN,
    lfn INT,
    pfn INT,
    mappings INT,
    rli_lfns INT,
    rli_lrcs INT,
    rli_senders INT,
    rli_mappings INT,
    threads INT,
    connections INT,
    PRIMARY KEY(id)	
);
CREATE INDEX rls_send_time_index ON rls_packets(DATE(send_time));

CREATE TABLE mpig_packets(
    id BIGSERIAL,
    component_code SMALLINT NOT NULL,
    version_code SMALLINT NOT NULL,
    send_time TIMESTAMP,
    ip_address VARCHAR(64) NOT NULL,
    hostname VARCHAR(64),
    mpichver VARCHAR(20),
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    nprocs INT,
    bytes_sent BIGINT,
    vendor_bytes_sent BIGINT,
    test INT,
    function_map TEXT,
    PRIMARY KEY(id)
);
CREATE INDEX mpig_send_time_index ON mpig_packets(DATE(send_time));

CREATE TABLE ogsadai_packets(
    id BIGSERIAL,
    component_code SMALLINT NOT NULL,
    version_code SMALLINT NOT NULL,
    send_time TIMESTAMP,
    ip_address VARCHAR(64) NOT NULL,
    activity TEXT,
    PRIMARY KEY(id)
);
CREATE INDEX ogsadai_send_time_index ON ogsadai_packets(DATE(send_time));

CREATE TABLE mds_packets(
    id BIGSERIAL,
    component_code SMALLINT NOT NULL,
    version_code SMALLINT NOT NULL,
    send_time TIMESTAMP,
    ip_address VARCHAR(64) NOT NULL,
    service_name VARCHAR(40),
    lifetime_reg_count INT,
    current_reg_count INT,
    resource_creation_time TIMESTAMP,
    PRIMARY KEY(id)
);
CREATE INDEX mds_send_time_index ON mds_packets(DATE(send_time));

CREATE TABLE drs_packets(
    id BIGSERIAL,
    component_code SMALLINT NOT NULL,
    version_code SMALLINT NOT NULL,
    send_time TIMESTAMP,
    ip_address VARCHAR(64) NOT NULL,
    number_of_files BIGINT,
    number_of_resources BIGINT,
    PRIMARY KEY (id)
);
CREATE INDEX drs_send_time_index ON drs_packets(DATE(send_time));


CREATE TABLE dns_cache(
    id BIGSERIAL,
    ip_address INET NOT NULL,
    hostname VARCHAR(256) NOT NULL,
    domain VARCHAR(256),
    UNIQUE(ip_address, hostname),
   PRIMARY KEY (id)
);

CREATE TABLE gftp_versions(
   id SERIAL,
   major INT NOT NULL,
   minor INT NOT NULL,
   flavor varchar(32) NOT NULL,
   dirt_timestamp TIMESTAMP NOT NULL,
   dirt_branch INT NOT NULL,
   distro_string varchar(64),
   UNIQUE(major, minor, flavor, dirt_timestamp, dirt_branch, distro_string),
   PRIMARY KEY (id)
);

CREATE TABLE gftp_server(
    id BIGSERIAL,

    host_id INT REFERENCES dns_cache(id),
    toolkit_version INT REFERENCES gftp_versions(id),
    gftp_version INT REFERENCES gftp_versions(id),
    event_modules TEXT,
    conf_id TEXT,
    UNIQUE(host_id, gftp_version, conf_id),
    PRIMARY KEY (id)
);

CREATE TABLE gftp_users(
    id BIGSERIAL,
    name VARCHAR(32),
    dn VARCHAR(256),
    UNIQUE(name, dn),
    PRIMARY KEY (id)
);

CREATE TABLE gftp_clients(
    id SERIAL,
    appname VARCHAR(128),
    appver VARCHAR(128),
    unique(appname, appver),
    PRIMARY KEY(id)
);

CREATE TABLE gftp_scheme(
    id SERIAL,
    name VARCHAR(64),
    unique(name),
    PRIMARY KEY (id)
);

CREATE TABLE gftp_dsi(
    id SERIAL,
    name VARCHAR(64),
    unique(name),
    PRIMARY KEY (id)
);

CREATE TABLE gftp_xio_stack(
    id SERIAL,
    name VARCHAR(256),
    unique(name),
    PRIMARY KEY (id)
);

CREATE TABLE gftp_xfer_type(
    id SERIAL,
    command char(4) unique,
    PRIMARY KEY(id));

COPY gftp_xfer_type(command) FROM STDIN;
STOR
RETR
ESTO
ERET
LIST
NLST
MLST
MLSD
\.


CREATE TABLE gftp_transfer_sizes(
    id SERIAL,
    minimum_size BIGINT,
    unique(minimum_size),
    PRIMARY KEY(id)
);
COPY gftp_transfer_sizes(minimum_size) FROM STDIN;
0
102400
1048576
5242880
10485760
104857600
524288000
1073741824
10737418240
\.

CREATE TABLE gftp_block_sizes(
    id SERIAL,
    minimum_size INT unique,
    PRIMARY KEY(id));
COPY gftp_block_sizes(minimum_size) FROM STDIN;
0
10240
102400
1048576
2097152
5242880
10485760
\.

CREATE TABLE gftp_buffer_sizes(
    id SERIAL,
    minimum_size INT unique,
    PRIMARY KEY(id));
COPY gftp_buffer_sizes(minimum_size) FROM STDIN;
0
10240
102400
1048576
2097152
5242880
10485760
\.

CREATE TABLE gftp_transfer_rate_sizes(
    id SERIAL,
    minimum_size INT unique,
    PRIMARY KEY(id));
COPY gftp_transfer_rate_sizes(minimum_size) FROM STDIN;
0
512000
1048576
2097152
10485760
52428800
104857600
\.

CREATE TABLE gftp_transfers(
    id BIGSERIAL,
    send_time TIMESTAMP,

    scheme INT REFERENCES gftp_scheme(id),
    dsi INT REFERENCES gftp_dsi(id),

    server_id INT REFERENCES gftp_server(id),
    client_id INT REFERENCES gftp_clients(id),
    user_id INT REFERENCES gftp_users(id),
    client_ip INET,
    remote_data_ip INET,
    session_id VARCHAR(64),

    data_channel_stack INT REFERENCES gftp_xio_stack(id),
    file_system_stack INT REFERENCES gftp_xio_stack(id),

    start_time TIMESTAMP,
    -- XXX should we bucket transfer time too ?
    transfer_time INTERVAL,

    trans_type INT REFERENCES gftp_xfer_type(id),
    num_stripes INT,
    num_streams INT,
    buffer_size INT,
    block_size  INT,
    ftp_return_code INT,
    num_bytes BIGINT,
    file_name TEXT,

    transfer_size_id INT REFERENCES gftp_transfer_sizes(id),
    block_size_id INT REFERENCES gftp_block_sizes(id),
    buffer_size_id INT REFERENCES gftp_buffer_sizes(id),
    transfer_rate_size_id INT REFERENCES gftp_transfer_sizes(id),

    PRIMARY KEY (id)
);

CREATE INDEX gftp_packets_send_time_index on gftp_transfers (DATE(send_time));
CREATE INDEX gftp_packets_start_time_index on gftp_transfers (start_time);

-- This table contains information about unique versions of GRAM5 that are
-- deployed. This table is referenced by the gram5_job_managers table to
-- associate a version with a particular service deployment.
CREATE TABLE gram5_versions (
    -- Integer id for quick version lookups / uniqueness checks
    id SERIAL PRIMARY KEY,
    -- Job Manager package major version
    major INTEGER NOT NULL,
    -- Job Manager package minor version
    minor INTEGER NOT NULL,
    -- Job Manager package flavor
    flavor VARCHAR(32) NOT NULL,
    -- Job Manager package dirt timestamp
    dirt_timestamp TIMESTAMP NOT NULL,
    -- Job Manager package dirt branch
    dirt_branch INTEGER NOT NULL,
    -- Toolkit Version or VDT version string
    distro_string VARCHAR(64),
    UNIQUE(major, minor, flavor, dirt_timestamp, dirt_branch, distro_string)
);

-- This table contains a mapping of unique LRM names to an integer key.
-- This table is referenced by the gram5_job_managers table to associate the
-- configured LRM with a particular service deployment.
CREATE TABLE gram5_lrms (
    -- integer id for quick LRM name lookup / uniqueness checks
    id SERIAL PRIMARY KEY,
    -- LRM name
    lrm VARCHAR(16) NOT NULL UNIQUE
);

-- This table contains information about a job manager
-- deployment (a unique version of the software on a particular host configured
-- in a particular way. This table is referenced by the
-- gram5_job_manager_instances table to associate a session of a job manager
-- with its configuration
CREATE TABLE gram5_job_managers(
    -- integer id for quick job manager lookup / uniqueness checks
    id SERIAL PRIMARY KEY,
    -- reference to the host
    host_id INTEGER REFERENCES dns_cache(id) NOT NULL,
    -- reference to the version
    version INTEGER REFERENCES gram5_versions(id) NOT NULL,
    -- reference to the lrm
    lrm_id INTEGER REFERENCES gram5_lrms(id) NOT NULL,
    -- was seg used for job status
    seg_used BOOLEAN NOT NULL,
    -- was poll used for job status
    poll_used BOOLEAN NOT NULL,
    -- was audit used
    audit_used BOOLEAN NOT NULL,
    UNIQUE(host_id, version, lrm_id, seg_used, poll_used, audit_used)
);

-- This table contains information about a particular job manager session.
-- An entry in this table is generated for each active job manager.
-- This table is referenced by the gram5_jobs table to associate a job
-- with the job manager that executed it, as well as by the
-- gram5_job_manager_status table to associate runtime statistics about the job
-- manager with a session.
CREATE TABLE gram5_job_manager_instances(
    -- unique key
    id SERIAL PRIMARY KEY,
    -- reference to the job manager configuration
    job_manager_id INTEGER REFERENCES gram5_job_managers(id),
    -- server process uuid
    uuid VARCHAR(36) UNIQUE NOT NULL,
    -- Time when the job manager started
    start_time TIMESTAMP
);

-- This table contains information about the status of a job manager
-- session. There may be multiple status packets for that instance depending
-- on the length of time the job manager is alive.  One is sent every hour
-- that the job manager is running, as well as at job manager initialization
-- and termination
CREATE TABLE gram5_job_manager_status(
    -- status packet id
    id SERIAL NOT NULL,
    -- Reference to the job manager instance
    job_manager_instance_id INTEGER references gram5_job_manager_instances(id),
    -- Number of jobs restarted by this job manager instance
    restarted_jobs INTEGER NOT NULL,
    -- Time when the status was collected
    status_time TIMESTAMP NOT NULL,
    -- Lifetime of the job manager
    lifetime INTERVAL NOT NULL,
    -- Total number of submitted job requests
    total_jobs INTEGER NOT NULL,
    -- Total number of jobs which hit the failed state (except dryruns and user
    -- canceled jobs)
    total_failed INTEGER NOT NULL,
    -- Total number of jobs which were user-canceled
    total_canceled INTEGER NOT NULL,
    -- Total number of jobs which hit the done state
    total_done INTEGER NOT NULL,
    -- total number of jobs which hit the failed with dryrun state
    total_dry_run INTEGER NOT NULL,
    -- Maximum number of jobs handled concurrently
    peak_jobs INTEGER NOT NULL,
    -- Total number of managed jobs by this process
    current_jobs INTEGER NOT NULL,
    -- Number of jobs currently in the UNSUBMITTED state
    unsubmitted INTEGER NOT NULL,
    -- Number of jobs currently in the STAGE_IN state
    stage_in INTEGER NOT NULL,
    -- Number of jobs currently in the PENDING state
    pending INTEGER NOT NULL,
    -- Number of jobs currently in the ACTIVE state
    active INTEGER NOT NULL,
    -- Number of jobs currently in the STAGE_OUT state
    stage_out INTEGER NOT NULL,
    -- Number of jobs currently in the FAILED state
    failed INTEGER NOT NULL,
    -- Number of jobs currently in the DONE state
    done INTEGER NOT NULL
);

CREATE INDEX gram5_job_manager_status_date_index
ON gram5_job_manager_status(DATE(status_time));

-- This table contains a mapping of RSL attributes to ids. The value of the
-- rsl_bitfield in the gram5_jobs table is a bitwise or of 2^id of the RSL
-- attributes in this table. The standard RSL attributes defined in
-- globus-job-manager.rvf are given standard numbers in this table from 35.
-- Higher-numbered values are generated by the usage stats collector for
-- non-standard extension attributes.
CREATE TABLE gram5_rsl_attributes(
    -- RSL attribute id
    id SERIAL PRIMARY KEY,
    -- RSL attribute name
    attribute VARCHAR(32) UNIQUE NOT NULL,
    extension BOOLEAN NOT NULL
);

COPY gram5_rsl_attributes(attribute, extension) FROM STDIN;
directory	0
executable	0
arguments	0
stdin	0
stdout	0
stderr	0
count	0
environment	0
maxtime	0
maxwalltime	0
maxcputime	0
jobtype	0
grammyjob	0
queue	0
project	0
hostcount	0
dryrun	0
minmemory	0
maxmemory	0
savestate	0
twophase	0
remoteiourl	0
scratchdir	0
rslsubstitution	0
restart	0
stdoutposition	0
stderrposition	0
filestagein	0
filestageinshared	0
filestageout	0
filecleanup	0
gasscache	0
proxytimeout	0
librarypath	0
username	0
\.

-- This table contains mappings of RSL bitfields to unique lists of RSL
-- attributes. This information could be computed from other tables, but
-- having this table simplifies queries quite a bit.
CREATE TABLE gram5_rsl_attribute_groups(
    -- Bitwise or of 2^(rsl attribute id)
    bitfield NUMERIC(64),
    -- String containing comma-separated list of attributes
    attributes VARCHAR(512) NOT NULL,
    PRIMARY KEY(bitfield));

-- The bitwise operations didn't work to well in practice with > 62 RSL
-- attributes + extension attributes defined. Replacing with this new
-- way of deciding what's in an attribute bundle
CREATE TABLE gram5_rsl_attribute_group_membership(
    bitfield NUMERIC(64),
    member_attribute INT REFERENCES gram5_rsl_attributes(id),
    UNIQUE(bitfield, member_attribute));

-- This table contains sensitive information about the GRAM executable.
-- This data is not collected by default.
CREATE TABLE gram5_executable(
    id SERIAL PRIMARY KEY,
    executable VARCHAR(256) NOT NULL,
    arguments VARCHAR(256)
);

-- This table contains sensitive information about the GRAM client.
-- This data is not collected by default. The gram5_jobs table references
-- this information when it is available
CREATE TABLE gram5_client(
    id SERIAL PRIMARY KEY,
    -- host information for the client which submitted the job
    host_id INTEGER REFERENCES dns_cache(id),
    -- credential DN of the job submitter
    dn VARCHAR(256),
    UNIQUE(host_id, dn)
);


-- This table contains all the protocol-specific staging-related statistics
-- for a particular GRAM job. The gram5_jobs table references this table.
CREATE TABLE gram5_job_file_info(
    id BIGSERIAL PRIMARY KEY,
    -- number of file_clean_up entries
    file_clean_up INTEGER NOT NULL,
    -- number of file_stage_in entries for http URLs
    file_stage_in_http INTEGER NOT NULL,
    -- number of file_stage_in entries for https URLs
    file_stage_in_https INTEGER NOT NULL,
    -- number of file_stage_in entries for ftp URLs
    file_stage_in_ftp INTEGER NOT NULL,
    -- number of file_stage_in entries for gsiftp URLs
    file_stage_in_gsiftp INTEGER NOT NULL,
    -- number of file_stage_in_shared entries for http URLs
    file_stage_in_shared_http INTEGER NOT NULL,
    -- number of file_stage_in_shared entries for https URLs
    file_stage_in_shared_https INTEGER NOT NULL,
    -- number of file_stage_in_shared entries for ftp URLs
    file_stage_in_shared_ftp INTEGER NOT NULL,
    -- number of file_stage_in_shared entries for gsiftp URLs
    file_stage_in_shared_gsiftp INTEGER NOT NULL,
    -- number of file_stage_out entries for http URLs
    file_stage_out_http INTEGER NOT NULL,
    -- number of file_stage_out entries for https URLs
    file_stage_out_https INTEGER NOT NULL,
    -- number of file_stage_out entries for ftp URLs
    file_stage_out_ftp INTEGER NOT NULL,
    -- number of file_stage_out entries for gsiftp URLs
    file_stage_out_gsiftp INTEGER NOT NULL);

-- This table contains the GRAM5 job types selected via the jobtype RSL
-- attribute. This table is referenced by the gram5_jobs table
CREATE TABLE gram5_job_types(
    -- Job type id
    id SERIAL PRIMARY KEY,
    -- Job type name
    jobtype VARCHAR(16) UNIQUE);

-- This table contains information about a job request. For some key RSL
-- attributes, we record specific values, for others, it track of whether they
-- are present in the job request.
CREATE TABLE gram5_jobs(
    id BIGSERIAL PRIMARY KEY,
    -- time when the job packet was sent
    send_time TIMESTAMP NOT NULL,
    -- job manager instance which processed this job
    job_manager_id INTEGER REFERENCES gram5_job_manager_instances(id) NOT NULL,
    -- count RSL attribute value
    count INTEGER NOT NULL,
    -- host_count RSL attribute value
    host_count INTEGER NOT NULL,
    -- dryrun RSL attribute value
    dryrun BOOLEAN NOT NULL,
    -- GRAM5 client which submitted the job
    client_id INTEGER REFERENCES gram5_client(id),
    -- executable name
    executable_id INTEGER REFERENCES gram5_executable(id),
    -- bitwise-or of 2^(each gram5_rsl_attributes value present)
    rsl_bitfield NUMERIC(64) NOT NULL,
    -- GRAM5 Job Type
    jobtype INTEGER NOT NULL references gram5_job_types(id),
    -- information about transfers associated with the job (if any transfers
    -- were done
    gram5_job_file_info BIGINT REFERENCES gram5_job_file_info(id)
);

CREATE INDEX gram5_job_send_time_index on gram5_jobs(DATE(send_time));

-- This table contains information about the execution of the job
-- including any errors that occurred.
CREATE TABLE gram5_job_status(
    -- job index
    job_id BIGINT PRIMARY KEY REFERENCES gram5_jobs(id) ON DELETE CASCADE,
    -- time when the job packet was sent
    send_time TIMESTAMP NOT NULL,
    -- Timestamp for when the job was created by the job manager
    unsubmitted_timestamp TIMESTAMP,
    -- Timestamp for when the job began staging in files
    file_stage_in_timestamp TIMESTAMP,
    -- Timestamp for when the job was pending to the scheduler
    pending_timestamp TIMESTAMP,
    -- Timestamp for when the job was active to the scheduler
    active_timestamp TIMESTAMP,
    -- Timestamp for when the job was failed
    failed_timestamp TIMESTAMP,
    -- Timestamp for when the job began staging out files
    file_stage_out_timestamp TIMESTAMP,
    -- Timestamp for when the job was complete
    done_timestamp TIMESTAMP,
    -- Number of times the status operation was called
    status_count INTEGER NOT NULL,
    -- Number of times the register operation was called
    register_count INTEGER NOT NULL,
    -- Number of times the unregister operation was called
    unregister_count INTEGER NOT NULL,
    -- Number of times the signal operation was called
    signal_count INTEGER NOT NULL,
    -- Number of times the job proxy was refreshed
    refresh_count INTEGER NOT NULL,
    -- Job failure code if the final disposition was FAILED
    failure_code INTEGER,
    -- Number of times a job manager restarted this job
    restart_count INTEGER NOT NULL,
    -- Number of job state callbacks sent for this job
    callback_count INTEGER NOT NULL
);

-- This table contains the static mapping of GRAM5 error codes to their
-- symbolic error name for better presentation in query results.
CREATE TABLE gram5_error_codes(
    -- error code number
    error_code INTEGER PRIMARY KEY,
    -- error name
    name VARCHAR(64));

COPY gram5_error_codes(error_code, name) FROM STDIN;
1	GLOBUS_GRAM_PROTOCOL_ERROR_PARAMETER_NOT_SUPPORTED
2	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_REQUEST
3	GLOBUS_GRAM_PROTOCOL_ERROR_NO_RESOURCES
4	GLOBUS_GRAM_PROTOCOL_ERROR_BAD_DIRECTORY
5	GLOBUS_GRAM_PROTOCOL_ERROR_EXECUTABLE_NOT_FOUND
6	GLOBUS_GRAM_PROTOCOL_ERROR_INSUFFICIENT_FUNDS
7	GLOBUS_GRAM_PROTOCOL_ERROR_AUTHORIZATION
8	GLOBUS_GRAM_PROTOCOL_ERROR_USER_CANCELLED
9	GLOBUS_GRAM_PROTOCOL_ERROR_SYSTEM_CANCELLED
10	GLOBUS_GRAM_PROTOCOL_ERROR_PROTOCOL_FAILED
11	GLOBUS_GRAM_PROTOCOL_ERROR_STDIN_NOT_FOUND
12	GLOBUS_GRAM_PROTOCOL_ERROR_CONNECTION_FAILED
13	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_MAXTIME
14	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_COUNT
15	GLOBUS_GRAM_PROTOCOL_ERROR_NULL_SPECIFICATION_TREE
16	GLOBUS_GRAM_PROTOCOL_ERROR_JM_FAILED_ALLOW_ATTACH
17	GLOBUS_GRAM_PROTOCOL_ERROR_JOB_EXECUTION_FAILED
18	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_PARADYN
19	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_JOBTYPE
20	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_GRAM_MYJOB
21	GLOBUS_GRAM_PROTOCOL_ERROR_BAD_SCRIPT_ARG_FILE
22	GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED
23	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_JOBSTATE
24	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_REPLY
25	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_STATUS
26	GLOBUS_GRAM_PROTOCOL_ERROR_JOBTYPE_NOT_SUPPORTED
27	GLOBUS_GRAM_PROTOCOL_ERROR_UNIMPLEMENTED
28	GLOBUS_GRAM_PROTOCOL_ERROR_TEMP_SCRIPT_FILE_FAILED
29	GLOBUS_GRAM_PROTOCOL_ERROR_USER_PROXY_NOT_FOUND
30	GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_USER_PROXY
31	GLOBUS_GRAM_PROTOCOL_ERROR_JOB_CANCEL_FAILED
32	GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED
33	GLOBUS_GRAM_PROTOCOL_ERROR_DUCT_INIT_FAILED
34	GLOBUS_GRAM_PROTOCOL_ERROR_DUCT_LSP_FAILED
35	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_HOST_COUNT
36	GLOBUS_GRAM_PROTOCOL_ERROR_UNSUPPORTED_PARAMETER
37	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_QUEUE
38	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_PROJECT
39	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_EVALUATION_FAILED
40	GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL_ENVIRONMENT
41	GLOBUS_GRAM_PROTOCOL_ERROR_DRYRUN
42	GLOBUS_GRAM_PROTOCOL_ERROR_ZERO_LENGTH_RSL
43	GLOBUS_GRAM_PROTOCOL_ERROR_STAGING_EXECUTABLE
44	GLOBUS_GRAM_PROTOCOL_ERROR_STAGING_STDIN
45	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_JOB_MANAGER_TYPE
46	GLOBUS_GRAM_PROTOCOL_ERROR_BAD_ARGUMENTS
47	GLOBUS_GRAM_PROTOCOL_ERROR_GATEKEEPER_MISCONFIGURED
48	GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL
49	GLOBUS_GRAM_PROTOCOL_ERROR_VERSION_MISMATCH
50	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_ARGUMENTS
51	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_COUNT
52	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_DIRECTORY
53	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_DRYRUN
54	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_ENVIRONMENT
55	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_EXECUTABLE
56	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_HOST_COUNT
57	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_JOBTYPE
58	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_MAXTIME
59	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_MYJOB
60	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_PARADYN
61	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_PROJECT
62	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_QUEUE
63	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_STDERR
64	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_STDIN
65	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_STDOUT
66	GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_JOBMANAGER_SCRIPT
67	GLOBUS_GRAM_PROTOCOL_ERROR_CREATING_PIPE
68	GLOBUS_GRAM_PROTOCOL_ERROR_FCNTL_FAILED
69	GLOBUS_GRAM_PROTOCOL_ERROR_STDOUT_FILENAME_FAILED
70	GLOBUS_GRAM_PROTOCOL_ERROR_STDERR_FILENAME_FAILED
71	GLOBUS_GRAM_PROTOCOL_ERROR_FORKING_EXECUTABLE
72	GLOBUS_GRAM_PROTOCOL_ERROR_EXECUTABLE_PERMISSIONS
73	GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_STDOUT
74	GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_STDERR
75	GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_CACHE_USER_PROXY
76	GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_CACHE
77	GLOBUS_GRAM_PROTOCOL_ERROR_INSERTING_CLIENT_CONTACT
78	GLOBUS_GRAM_PROTOCOL_ERROR_CLIENT_CONTACT_NOT_FOUND
79	GLOBUS_GRAM_PROTOCOL_ERROR_CONTACTING_JOB_MANAGER
80	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_JOB_CONTACT
81	GLOBUS_GRAM_PROTOCOL_ERROR_UNDEFINED_EXE
82	GLOBUS_GRAM_PROTOCOL_ERROR_CONDOR_ARCH
83	GLOBUS_GRAM_PROTOCOL_ERROR_CONDOR_OS
84	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_MIN_MEMORY
85	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_MAX_MEMORY
86	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_MIN_MEMORY
87	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_MAX_MEMORY
88	GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_FRAME_FAILED
89	GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNFRAME_FAILED
90	GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_PACK_FAILED
91	GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED
92	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_JOB_QUERY
93	GLOBUS_GRAM_PROTOCOL_ERROR_SERVICE_NOT_FOUND
94	GLOBUS_GRAM_PROTOCOL_ERROR_JOB_QUERY_DENIAL
95	GLOBUS_GRAM_PROTOCOL_ERROR_CALLBACK_NOT_FOUND
96	GLOBUS_GRAM_PROTOCOL_ERROR_BAD_GATEKEEPER_CONTACT
97	GLOBUS_GRAM_PROTOCOL_ERROR_POE_NOT_FOUND
98	GLOBUS_GRAM_PROTOCOL_ERROR_MPIRUN_NOT_FOUND
99	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_START_TIME
100	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_RESERVATION_HANDLE
101	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_MAX_WALL_TIME
102	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_MAX_WALL_TIME
103	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_MAX_CPU_TIME
104	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_MAX_CPU_TIME
105	GLOBUS_GRAM_PROTOCOL_ERROR_JM_SCRIPT_NOT_FOUND
106	GLOBUS_GRAM_PROTOCOL_ERROR_JM_SCRIPT_PERMISSIONS
107	GLOBUS_GRAM_PROTOCOL_ERROR_SIGNALING_JOB
108	GLOBUS_GRAM_PROTOCOL_ERROR_UNKNOWN_SIGNAL_TYPE
109	GLOBUS_GRAM_PROTOCOL_ERROR_GETTING_JOBID
110	GLOBUS_GRAM_PROTOCOL_ERROR_WAITING_FOR_COMMIT
111	GLOBUS_GRAM_PROTOCOL_ERROR_COMMIT_TIMED_OUT
112	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_SAVE_STATE
113	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_RESTART
114	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_TWO_PHASE_COMMIT
115	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_TWO_PHASE_COMMIT
116	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_STDOUT_POSITION
117	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_STDOUT_POSITION
118	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_STDERR_POSITION
119	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_STDERR_POSITION
120	GLOBUS_GRAM_PROTOCOL_ERROR_RESTART_FAILED
121	GLOBUS_GRAM_PROTOCOL_ERROR_NO_STATE_FILE
122	GLOBUS_GRAM_PROTOCOL_ERROR_READING_STATE_FILE
123	GLOBUS_GRAM_PROTOCOL_ERROR_WRITING_STATE_FILE
124	GLOBUS_GRAM_PROTOCOL_ERROR_OLD_JM_ALIVE
125	GLOBUS_GRAM_PROTOCOL_ERROR_TTL_EXPIRED
126	GLOBUS_GRAM_PROTOCOL_ERROR_SUBMIT_UNKNOWN
127	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_REMOTE_IO_URL
128	GLOBUS_GRAM_PROTOCOL_ERROR_WRITING_REMOTE_IO_URL
129	GLOBUS_GRAM_PROTOCOL_ERROR_STDIO_SIZE
130	GLOBUS_GRAM_PROTOCOL_ERROR_JM_STOPPED
131	GLOBUS_GRAM_PROTOCOL_ERROR_USER_PROXY_EXPIRED
132	GLOBUS_GRAM_PROTOCOL_ERROR_JOB_UNSUBMITTED
133	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_COMMIT
134	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_SCHEDULER_SPECIFIC
135	GLOBUS_GRAM_PROTOCOL_ERROR_STAGE_IN_FAILED
136	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRATCH
137	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_CACHE
138	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SUBMIT_ATTRIBUTE
139	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_STDIO_UPDATE_ATTRIBUTE
140	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_RESTART_ATTRIBUTE
141	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_FILE_STAGE_IN
142	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_FILE_STAGE_IN_SHARED
143	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_FILE_STAGE_OUT
144	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_GASS_CACHE
145	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_FILE_CLEANUP
146	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_SCRATCH
147	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCHEDULER_SPECIFIC
148	GLOBUS_GRAM_PROTOCOL_ERROR_UNDEFINED_ATTRIBUTE
149	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_CACHE
150	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SAVE_STATE
151	GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_VALIDATION_FILE
152	GLOBUS_GRAM_PROTOCOL_ERROR_READING_VALIDATION_FILE
153	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_PROXY_TIMEOUT
154	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_PROXY_TIMEOUT
155	GLOBUS_GRAM_PROTOCOL_ERROR_STAGE_OUT_FAILED
156	GLOBUS_GRAM_PROTOCOL_ERROR_JOB_CONTACT_NOT_FOUND
157	GLOBUS_GRAM_PROTOCOL_ERROR_DELEGATION_FAILED
158	GLOBUS_GRAM_PROTOCOL_ERROR_LOCKING_STATE_LOCK_FILE
159	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_ATTR
160	GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER
161	GLOBUS_GRAM_PROTOCOL_ERROR_STILL_STREAMING
162	GLOBUS_GRAM_PROTOCOL_ERROR_AUTHORIZATION_DENIED
163	GLOBUS_GRAM_PROTOCOL_ERROR_AUTHORIZATION_SYSTEM_FAILURE
164	GLOBUS_GRAM_PROTOCOL_ERROR_AUTHORIZATION_DENIED_JOB_ID
165	GLOBUS_GRAM_PROTOCOL_ERROR_AUTHORIZATION_DENIED_EXECUTABLE
166	GLOBUS_GRAM_PROTOCOL_ERROR_RSL_USER_NAME
167	GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_USER_NAME
168	GLOBUS_GRAM_PROTOCOL_ERROR_LAST
\.

CREATE TABLE myproxy_packets(
    id SERIAL,
    component_code SMALLINT NOT NULL,
    version_code SMALLINT NOT NULL,
    send_time TIMESTAMP,
    ip_address INET,
    hostname VARCHAR(64) NOT NULL,
    myproxy_major_version SMALLINT,
    myproxy_minor_version SMALLINT,
    task_code SMALLINT, -- 0=Get, 1=Put, 2=Info, 3=Destroy, 4=ChPasswd, 5=StoreEntCred, 6=RetrEntCred, 7=GetTrustRoots
    task_return_code BOOLEAN,
    req_lifetime INTERVAL, -- the LIFETIME= value in the protocol request
    cred_lifetime INTERVAL, -- the actual lifetime of the credential
    info_bits BIT VARYING(32), -- Bits 1=PAM, 2=SASL, 3=Credential passphrase, 4=trusted retriever (this is a certificate-based authentication), 5=trusted renewer (this is the certificate authorization in the authorization challenge), 6=pubcookie_used, 7=trustroots_requested, 8=trustroots_requested, 9=ca_used_for_GET
    client_ip INET,
    user_name VARCHAR(128),
    user_dn VARCHAR(128),
    PRIMARY KEY (id)
);

CREATE TABLE gsissh_packets(
    id SERIAL,
    component_code SMALLINT NOT NULL,
    version_code SMALLINT NOT NULL,
    send_time TIMESTAMP,
    ip_address INET,
    hostname VARCHAR(64) NOT NULL,
    openssh_version VARCHAR(128) NOT NULL,
    openssl_version VARCHAR(64) NOT NULL,
    method VARCHAR(32) NOT NULL,
    mechanism VARCHAR(32),
    client_ip INET,
    user_name VARCHAR(128),
    user_dn VARCHAR(128),
    PRIMARY KEY (id)
);

CREATE TABLE usage_community(
    community_name                      TEXT,
    dns_pattern                         TEXT,
    UNIQUE(community_name, dns_pattern));

COPY usage_community(community_name, dns_pattern) FROM STDIN;
LHC	%.cern.ch
LHC	%cms%
LHC	%atl%
LHC	%lhc%
LHC	%lcg%
LHC	%hep%
LHC	%qmul%
LHC	%particle%
LHC	%physik%
LHC	%gridka%
OSG	%osg%
XSEDE	%.teragrid.org
XSEDE	%.xsede.org
LIGO	%ligo%
LIGO	%ldr%
DES	des%
D0	d0%
EDU	%.edu
ESA	%.esa.int
ESA	%terradue%
ESA	%unina%
ESA	%sissa%
ESA	%inaf%
ESA	%fatebenefratelli%
DOE	%.gov
DOE	%.lbl.gov
DOE	%.anl.gov
DOE	%.pnl.gov
DOE	%.lanl.gov
DOE	%.ornl.gov
DOE	%.bnl.gov
DOE	%.fnal.gov
DOE	%.pnnl.gov
DOE	%.pppl.gov
DOE	%.inl.gov
DOE	%.slac.stanford.edu
DOE	%.doe.gov
DOE	%.snl.gov
DOE	%.jlab.org
\.

