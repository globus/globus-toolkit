USE guss;

CREATE TABLE  unknown_packets(
    id SERIAL,
    componentcode SMALLINT NOT NULL,
    versioncode SMALLINT NOT NULL,
    contents OID,  
    PRIMARY KEY (id)
);

CREATE TABLE gftp_packets(
    id SERIAL,
    component_code SMALLINT NOT NULL,
    version_code SMALLINT NOT NULL,
    send_time DATETIME,
    ip_version SMALLINT,
    ip_address VARCHAR(32),
    gftp_version VARCHAR(20),
    stor_or_retr SMALLINT,
    start_time DATETIME,
    end_time DATETIME,
    num_bytes BIGINT,
    num_stripes BIGINT,
    num_streams BIGINT,
    buffer_size BIGINT,
    block_size BIGINT,
    ftp_return_code BIGINT,
    sequence_number BIGINT,
    PRIMARY KEY (id)
);
