CREATE TYPE aggregation_time_range_type
    AS ENUM('hourly', 'daily', 'monthly', 'yearly');

/* 
 Table: gftp_server_histogram_aggregations
 Purpose:
     This aggregation is populated hourly by the globus-usage-uploader command.
     The data is rolled up per day and month as it accumulates.

     It uses as a non-unique key, the (aggregation_time,
     aggregation_time_range, server_id, log10_transfer_size_bytes,
     log10_transfer_rate_bps) tuple. The reason it
     is non-unique is that packets may be received around the hourly upload
     cutoff or with odd timestamps in them, so multiple entries with the
     aggregation_time may be added in subsequent inserts, so in general, you'll
     need to SUM the transfer_count and byte_count values with whatever
     selection criteria you are using for the aggregation_time,
     aggregation_time_range, server_id, log10_transfer_size_bytes, or
     log10_transfer_rate_bps values

    This table can be used to answer questions like:

    * How many transfers were handled overall, or by server x (or combinations
      of servers as makes sense).  Querying other tables will get to this
      info faster

    * What order of magnitude sizes of transfers are handled by overall or by
      server x (or combinations of servers as makes sense). The
      log10_transfer_size_bytes value contains the log base 10 of the number of
      bytes in a transfer, truncated to an integer, with 0 meaning a 0 byte
      transfer. 

    * What order of magnitude transfer rates are handled by overall or by
      server x (or combinations of servers as makes sense). The
      log10_transfer_rate_bps value contains the log base 10 of the transfer
      rate in bits per second, with 0 meaning a negligible transfer rate.
      In some cases the duration of the transfer might be sent as negative or
      zero, so these may need to be taken with a grain of salt. 

    * What is the distribution of (order of magnitude) file sizes and (order of
      magnitude) transfer rates overall (or combination so of servers as makes
      sense). You could see at what order of magnitude size file you see
      transfer rates reach some speed threshold  overall or for a particular
      server
*/
CREATE TABLE gftp_server_histogram_aggregations(
    aggregation_time                    TIMESTAMP,
    aggregation_time_range              aggregation_time_range_type,
    server_id                           INT         REFERENCES gftp_server(id),

    log10_transfer_size_bytes           INT,
    log10_transfer_rate_bps             INT,

    transfer_count                      BIGINT,
    byte_count                          BIGINT
);

/* 
 Table: gftp_server_xfer_type_aggregations
 Purpose:
     This aggregation is populated hourly by the globus-usage-uploader command.
     The data is rolled up per day and month as it accumulates.

     It uses as a non-unique key, the (aggregation_time,
     aggregation_time_range, server_id, trans_type) tuple. The reason it
     is non-unique is that packets may be received around the hourly upload
     cutoff or with odd timestamps in them, so multiple entries with the
     aggregation_time may be added in subsequent inserts, so in general, you'll
     need to SUM the transfer_count and byte_count values with whatever
     selection criteria you are using for the aggregation_time,
     aggregation_time_range, server_id, trans_type values.

    This table can be used to answer questions like:

    * How many transfers were handled overall, or by server x (or combinations
      of servers as makes sense).  This is probably quicker to resolve than
      with the previous table.

    * What type of transfers are being handled by server x (or combinations
      of servers as makes sense).

    * How many transfers or bytes where transferred into our out of a server
      (or combinations of servers as makes sense).
*/
CREATE TABLE gftp_server_xfer_type_aggregations(
    aggregation_time                    TIMESTAMP,
    aggregation_time_range              aggregation_time_range_type,
    server_id                           INT         REFERENCES gftp_server(id),
    trans_type                          INTEGER REFERENCES gftp_xfer_type(id),
    transfer_count                      BIGINT,
    byte_count                          BIGINT);

/* 
 Table: gftp_server_stream_aggregations
 Purpose:
     This aggregation is populated hourly by the globus-usage-uploader command.
     The data is rolled up per day and month as it accumulates.

     It uses as a non-unique key, the (aggregation_time,
     aggregation_time_range, server_id, num_streams) tuple. The reason it
     is non-unique is that packets may be received around the hourly upload
     cutoff or with odd timestamps in them, so multiple entries with the
     aggregation_time may be added in subsequent inserts, so in general, you'll
     need to SUM the transfer_count and byte_count values with whatever
     selection criteria you are using for the aggregation_time,
     aggregation_time_range, server_id, num_streams.

    This table can be used to answer questions like:

    * How many transfers per server are using parallel streams.

    * How many streams does a particular server handle on an average file
      transfer.
*/
CREATE TABLE gftp_server_stream_aggregations(
    aggregation_time                    TIMESTAMP,
    aggregation_time_range              aggregation_time_range_type,
    server_id                           INTEGER REFERENCES gftp_server(id),
    num_streams                         INTEGER,
    transfer_count                      BIGINT,
    byte_count                          BIGINT);

/* 
 Table: gftp_client_server_aggregations
 Purpose:
     This aggregation is populated hourly by the globus-usage-uploader command.
     The data is rolled up per day and month as it accumulates.

     It uses as a non-unique key, the (aggregation_time,
     aggregation_time_range, client_id, server_id) tuple. The reason it
     is non-unique is that packets may be received around the hourly upload
     cutoff or with odd timestamps in them, so multiple entries with the
     aggregation_time may be added in subsequent inserts, so in general, you'll
     need to SUM the transfer_count and byte_count values with whatever
     selection criteria you are using for the aggregation_time,
     aggregation_time_range, server_id, num_streams.

    This table can be used to answer questions like:

    * Which client applications are being used to do transfers overall or
      for a interesting group of servers
*/
CREATE TABLE gftp_client_server_aggregations(
    aggregation_time                    TIMESTAMP,
    aggregation_time_range              aggregation_time_range_type,
    server_id                           INTEGER REFERENCES gftp_server(id),
    client_id                           INTEGER REFERENCES gftp_clients(id),
    transfer_count                      BIGINT,
    byte_count                          BIGINT);


CREATE INDEX gftp_server_histogram_aggregations_hourly_index
    ON gftp_server_histogram_aggregations(aggregation_time)
    WHERE aggregation_time_range = 'hourly';

CREATE INDEX gftp_server_histogram_aggregations_hourly_server_index
    ON gftp_server_histogram_aggregations(aggregation_time, server_id)
    WHERE aggregation_time_range = 'hourly';

CREATE INDEX gftp_server_histogram_aggregtions_daily_index
    ON gftp_server_histogram_aggregations (DATE(aggregation_time))
    WHERE aggregation_time_range = 'daily';

CREATE INDEX gftp_server_histogram_aggregations_daily_server_index
    ON gftp_server_histogram_aggregations
            (DATE(aggregation_time),
            server_id)
    WHERE aggregation_time_range = 'daily';

CREATE INDEX gftp_server_histogram_aggregations_monthly_index
    ON gftp_server_histogram_aggregations(DATE(aggregation_time))
    WHERE aggregation_time_range = 'monthly';

CREATE INDEX gftp_server_histogram_aggregations_monthly_server_index
    ON gftp_server_histogram_aggregations
            (DATE(aggregation_time),
            server_id)
    WHERE aggregation_time_range = 'monthly';

CREATE INDEX gftp_server_histogram_aggregations_yearly_index
    ON gftp_server_histogram_aggregations(DATE(aggregation_time))
    WHERE aggregation_time_range = 'yearly';

CREATE INDEX gftp_server_histogram_aggregations_yearly_server_index
    ON gftp_server_histogram_aggregations(
            DATE(aggregation_time),
            server_id)
    WHERE aggregation_time_range = 'yearly';

CREATE INDEX gftp_server_xfer_type_aggregations_hourly_index
    ON gftp_server_xfer_type_aggregations (DATE(aggregation_time))
    WHERE aggregation_time_range = 'hourly';

CREATE INDEX gftp_server_xfer_type_aggregations_daily_index
    ON gftp_server_xfer_type_aggregations (DATE(aggregation_time))
    WHERE aggregation_time_range = 'daily';

CREATE INDEX gftp_server_xfer_type_aggregations_monthly_index
    ON gftp_server_xfer_type_aggregations (DATE(aggregation_time))
    WHERE aggregation_time_range = 'monthly';

CREATE INDEX gftp_server_xfer_type_aggregations_yearly_index
    ON gftp_server_xfer_type_aggregations (DATE(aggregation_time))
    WHERE aggregation_time_range = 'yearly';

CREATE INDEX gftp_client_server_aggregations_hourly_index
    ON gftp_client_server_aggregations (aggregation_time)
    WHERE aggregation_time_range = 'hourly';

CREATE INDEX gftp_client_server_aggregations_daily_index
    ON gftp_client_server_aggregations (DATE(aggregation_time))
    WHERE aggregation_time_range = 'daily';

CREATE INDEX gftp_client_server_aggregations_monthly_index
    ON gftp_client_server_aggregations (DATE(aggregation_time))
    WHERE aggregation_time_range = 'monthly';

CREATE INDEX gftp_client_server_aggregations_yearly_index
    ON gftp_client_server_aggregations (DATE(aggregation_time))
    WHERE aggregation_time_range = 'yearly';

CREATE TABLE gram5_aggregations_hourly(
    aggregation_time                    TIMESTAMP,
    job_manager_instance_id             INT         REFERENCES gram5_job_manager_instances(id),
    failure_code INTEGER,
    job_count                           BIGINT);

CREATE INDEX gram5_aggregations_hourly_index
    ON gram5_aggregations_hourly(aggregation_time);
CREATE INDEX gram5_aggregations_hourly_server_index
    ON gram5_aggregations_hourly(aggregation_time, job_manager_instance_id);

CREATE TABLE gram5_aggregations_daily(
    aggregation_time                    DATE,
    job_manager_id                      INTEGER     REFERENCES gram5_job_managers(id),
    failure_code                        INTEGER,
    job_count                           BIGINT);

CREATE INDEX gram5_aggregations_daily_index
    ON gram5_aggregations_daily(aggregation_time);

