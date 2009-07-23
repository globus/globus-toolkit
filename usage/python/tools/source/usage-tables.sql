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

CREATE TABLE c_ws_core_packets(
    id BIGSERIAL,
    component_code SMALLINT NOT NULL,
    version_code SMALLINT NOT NULL,
    send_time TIMESTAMP,
    ip_address VARCHAR(64) NOT NULL,
    container_id INT,
    event_type SMALLINT,
    service_list TEXT
);

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

CREATE TABLE ogsadai_packets(
    id BIGSERIAL,
    component_code SMALLINT NOT NULL,
    version_code SMALLINT NOT NULL,
    send_time TIMESTAMP,
    ip_address VARCHAR(64) NOT NULL,
    activity TEXT,
    PRIMARY KEY(id)
);

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


CREATE TABLE dns_cache(
    id BIGSERIAL,
    ip_address INET NOT NULL,
    hostname VARCHAR(256) UNIQUE NOT NULL,
    domain VARCHAR(256),
    unique(ip_address, hostname),
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
-- XXX do we want to index the buckets?


