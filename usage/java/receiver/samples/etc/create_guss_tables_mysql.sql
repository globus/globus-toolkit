CREATE TABLE  unknown_packets(
    id BIGINT NOT NULL AUTO_INCREMENT,
    componentcode SMALLINT NOT NULL,
    versioncode SMALLINT NOT NULL,
    contents BLOB,
    PRIMARY KEY (id)
);

CREATE TABLE gftp_packets(
    id BIGINT NOT NULL AUTO_INCREMENT,
    component_code SMALLINT NOT NULL,
    version_code SMALLINT NOT NULL,
    send_time DATETIME,
    ip_version TINYINT,
    ip_address TINYTEXT,
    gftp_version VARCHAR(20),
    stor_or_retr TINYINT,
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
