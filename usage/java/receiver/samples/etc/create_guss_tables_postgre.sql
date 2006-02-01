USE guss;

CREATE TABLE  unknown_packets(
    id SERIAL,
    componentcode SMALLINT NOT NULL,
    versioncode SMALLINT NOT NULL,
    contents BYTEA NOT NULL,  
    PRIMARY KEY (id)
);

CREATE TABLE gftp_packets(
    id SERIAL,
    component_code SMALLINT NOT NULL,
    version_code SMALLINT NOT NULL,
    send_time DATETIME,
    ip_version SMALLINT,
    ip_address VARCHAR(64) NOT NULL,
    gftp_version VARCHAR(64),
    stor_or_retr SMALLINT,
    start_time BIGINT NOT NULL,
    end_time BIGINT NOT NULL,
    num_bytes BIGINT,
    num_stripes INT,
    num_streams INT,
    buffer_size INT,
    block_size  INT,
    ftp_return_code INT,
    sequence_number BIGINT,
    src_id BIGINT,
    dest_id BIGINT,
    reserved BIGINT,
    PRIMARY KEY (id)
);

CREATE TABLE rft_packets(
    id SERIAL,
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

CREATE TABLE gftp_summaries(
    id SERIAL,
    start_time BIGINT NOT NULL,
    end_time BIGINT NOT NULL,
    label VARCHAR(32), 
    num_transfers BIGINT,
    total_bytes BIGINT,
    num_hosts INT,
    avg_size BIGINT,
    avg_time BIGINT,
    avg_speed BIGINT,
    size_stddev DOUBLE PRECISION,
    time_stddev DOUBLE PRECISION,
    speed_stddev DOUBLE PRECISION,
    PRIMARY KEY (id)
);

CREATE TABLE java_ws_core_packets(
    id SERIAL,
    component_code SMALLINT NOT NULL,
    version_code SMALLINT NOT NULL,
    send_time TIMESTAMP,
    ip_address VARCHAR(64) NOT NULL,
    container_id INT,
    container_type SMALLINT,
    event_type SMALLINT,
    service_list TEXT
);

CREATE TABLE gram_packets( 
    id SERIAL,
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
    id SERIAL,
    component_code SMALLINT NOT NULL,
    version_code SMALLINT NOT NULL,
    send_time TIMESTAMP,
    ip_address VARCHAR(64) NOT NULL
);

CREATE TABLE rls_packets(
    id SERIAL,
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

CREATE TABLE graph_image_files(
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    granularity INT,
    graph_type INT,
    graph_quant INT,
    filter VARCHAR(16),
    file_url TEXT
);