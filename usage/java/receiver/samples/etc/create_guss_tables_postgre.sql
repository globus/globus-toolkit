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
    send_time DATETIME,
    ip_address VARCHAR(64) NOT NULL,
    request_type SMALLINT NOT NULL,
    number_of_files BIGINT,
    number_of_bytes BIGINT,
    number_of_resources BIGINT,
    creation_time BIGINT,
    factory_start_time BIGINT,
    PRIMARY KEY (id)
);