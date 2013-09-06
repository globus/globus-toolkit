-- Overall Overviews --
CREATE VIEW gftp_transfer_overview(
    aggregation_time, aggregation_time_range, 
    transfers_in, transfers_out, transfers_other,
    bytes_in, bytes_out, bytes_other)
AS
    SELECT
        aggregation_time,
        aggregation_time_range,
        SUM(
            CASE
                WHEN trans_type IN
                    (SELECT id
                        FROM gftp_xfer_type
                        WHERE command = 'STOR' or command = 'ESTO')
                    THEN transfer_count
                ELSE
                    0
            END
        ) AS transfers_in,
        SUM (
            CASE
                WHEN trans_type IN
                    (SELECT id
                        FROM gftp_xfer_type
                        WHERE command = 'ERET' or command = 'RETR')
                    THEN transfer_count
                ELSE
                    0
            END
        ) AS transfers_out,
        SUM (
            CASE 
                WHEN trans_type NOT IN
                    (SELECT id
                        FROM gftp_xfer_type
                        WHERE command = 'STOR' OR command = 'ESTO' OR 
                              command = 'ERET' OR command = 'RETR')
                    THEN transfer_count
                ELSE
                    0
            END
        ) AS other_commands,
        SUM(
            CASE
                WHEN trans_type IN
                    (SELECT id
                        FROM gftp_xfer_type
                        WHERE command = 'STOR' or command = 'ESTO')
                    THEN byte_count
                ELSE
                    0
            END
        ) AS bytes_in,
        SUM (
            CASE
                WHEN trans_type IN
                    (SELECT id
                        FROM gftp_xfer_type
                        WHERE command = 'ERET' or command = 'RETR')
                    THEN byte_count
                ELSE
                    0
            END
        ) AS bytes_out,
        SUM (
            CASE
                WHEN trans_type NOT IN
                    (SELECT id
                        FROM gftp_xfer_type
                        WHERE command = 'STOR' OR command = 'ESTO' OR 
                              command = 'ERET' OR command = 'RETR')
                    THEN byte_count
                ELSE
                    0
            END
        ) AS other_bytes
        FROM gftp_server_xfer_type_aggregations
        GROUP BY aggregation_time, aggregation_time_range;

CREATE VIEW gftp_client_overview(
    aggregation_time, aggregation_time_range, client,
    transfer_count, byte_count)
AS
    SELECT
        aggregation_time,
        aggregation_time_range,
        CASE
            WHEN appname IS NOT NULL 
                THEN appname
            ELSE
                'Unknown'
        END AS client,
        SUM(transfer_count) AS transfer_count,
        SUM(byte_count) AS byte_count
        FROM gftp_client_server_aggregations
        LEFT OUTER JOIN gftp_clients on gftp_clients.id = client_id
        GROUP BY aggregation_time, aggregation_time_range, client;

CREATE VIEW gftp_distinct_server_overview(
    aggregation_time, aggregation_time_range, server_count)
AS
    SELECT
        aggregation_time,
        aggregation_time_range,
        COUNT(DISTINCT ip_address) AS server_count
        FROM gftp_server_stream_aggregations
        INNER JOIN gftp_server ON server_id = gftp_server.id
        INNER JOIN dns_cache ON host_id = dns_cache.id
        GROUP BY aggregation_time, aggregation_time_range;
    

CREATE VIEW gftp_server_stream_overview(
    aggregation_time, aggregation_time_range, number_of_streams, transfer_count, byte_count)
AS
    SELECT
        aggregation_time,
        aggregation_time_range,
        num_streams AS number_of_streams,
        SUM(transfer_count) AS transfer_count,
        SUM(byte_count) AS byte_count
        FROM gftp_server_stream_aggregations
        GROUP BY aggregation_time, aggregation_time_range, number_of_streams;


CREATE VIEW gftp_transfer_size_overview(
    aggregation_time, aggregation_time_range,
    transfer_size, transfer_count, byte_count)
AS
    SELECT
        aggregation_time,
        aggregation_time_range,
        CASE 
            WHEN log10_transfer_size_bytes = 0
                THEN 0
            ELSE
                10^log10_transfer_size_bytes
        END AS transfer_size,
        SUM(transfer_count) AS transfer_count,
        SUM(byte_count) AS byte_count
        FROM gftp_server_histogram_aggregations
        GROUP BY aggregation_time, aggregation_time_range, transfer_size;

CREATE VIEW gftp_transfer_rate_overview(
    aggregation_time, aggregation_time_range, 
    transfer_rate_bps, transfer_count, byte_count)
AS
    SELECT
        aggregation_time,
        aggregation_time_range,
        CASE 
            WHEN log10_transfer_rate_bps = 0
                THEN 0
            ELSE
                10^log10_transfer_rate_bps
        END AS transfer_rate_bps,
        SUM(transfer_count) AS transfer_count,
        SUM(byte_count) AS byte_count
        FROM gftp_server_histogram_aggregations
        GROUP BY aggregation_time, aggregation_time_range, transfer_rate_bps;

CREATE VIEW gftp_transfer_rate_size_overview(
    aggregation_time, aggregation_time_range, 
    transfer_rate_bps, transfer_size, transfer_count, byte_count)
AS
    SELECT
        aggregation_time,
        aggregation_time_range,
        CASE 
            WHEN log10_transfer_rate_bps = 0
                THEN 0
            ELSE
                10^log10_transfer_rate_bps
        END AS transfer_rate_bps,
        CASE 
            WHEN log10_transfer_size_bytes = 0
                THEN 0
            ELSE
                10^log10_transfer_size_bytes
        END AS transfer_size,
        SUM(transfer_count) AS transfer_count,
        SUM(byte_count) AS byte_count
        FROM gftp_server_histogram_aggregations
        GROUP BY aggregation_time, aggregation_time_range, transfer_rate_bps, transfer_size;
-- Community Overview
CREATE VIEW gftp_transfer_community_overview(
    aggregation_time, aggregation_time_range, community,
    transfers_in, transfers_out, transfers_other,
    bytes_in, bytes_out, bytes_other)
AS
    SELECT
        aggregation_time,
        aggregation_time_range,
        CASE
            WHEN community_name is NULL THEN 'Other'
            ELSE community_name 
        END AS community,
        SUM(
            CASE
                WHEN trans_type IN
                    (SELECT id
                        FROM gftp_xfer_type
                        WHERE command = 'STOR' or command = 'ESTO')
                    THEN transfer_count
                ELSE
                    0
            END
        ) AS transfers_in,
        SUM (
            CASE
                WHEN trans_type IN
                    (SELECT id
                        FROM gftp_xfer_type
                        WHERE command = 'ERET' or command = 'RETR')
                    THEN transfer_count
                ELSE
                    0
            END
        ) AS transfers_out,
        SUM (
            CASE 
                WHEN trans_type NOT IN
                    (SELECT id
                        FROM gftp_xfer_type
                        WHERE command = 'STOR' OR command = 'ESTO' OR 
                              command = 'ERET' OR command = 'RETR')
                    THEN transfer_count
                ELSE
                    0
            END
        ) AS other_commands,
        SUM(
            CASE
                WHEN trans_type IN
                    (SELECT id
                        FROM gftp_xfer_type
                        WHERE command = 'STOR' or command = 'ESTO')
                    THEN byte_count
                ELSE
                    0
            END
        ) AS bytes_in,
        SUM (
            CASE
                WHEN trans_type IN
                    (SELECT id
                        FROM gftp_xfer_type
                        WHERE command = 'ERET' or command = 'RETR')
                    THEN byte_count
                ELSE
                    0
            END
        ) AS bytes_out,
        SUM (
            CASE
                WHEN trans_type NOT IN
                    (SELECT id
                        FROM gftp_xfer_type
                        WHERE command = 'STOR' OR command = 'ESTO' OR 
                              command = 'ERET' OR command = 'RETR')
                    THEN byte_count
                ELSE
                    0
            END
        ) AS other_bytes
        FROM gftp_server_xfer_type_aggregations
        INNER JOIN gftp_server ON server_id = gftp_server.id
        INNER JOIN dns_cache ON host_id = dns_cache.id
        LEFT OUTER JOIN usage_community ON hostname LIKE dns_pattern
        GROUP BY aggregation_time, aggregation_time_range, community;

CREATE VIEW gftp_client_community_overview(
    aggregation_time, aggregation_time_range, community, client,
    transfer_count, byte_count)
AS
    SELECT
        aggregation_time,
        aggregation_time_range,
        CASE
            WHEN community_name IS NOT NULL THEN
                community_name
            ELSE
                'Other'
        END AS community,
        CASE
            WHEN appname IS NOT NULL 
                THEN appname
            ELSE
                'Unknown'
        END AS client,
        SUM(transfer_count) AS transfer_count,
        SUM(byte_count) AS byte_count
        FROM gftp_client_server_aggregations
        INNER JOIN gftp_server ON server_id = gftp_server.id
        INNER JOIN dns_cache ON host_id = dns_cache.id
        LEFT OUTER JOIN usage_community ON hostname LIKE dns_pattern
        LEFT OUTER JOIN gftp_clients ON client_id = gftp_clients.id
        GROUP BY aggregation_time, aggregation_time_range, community, client;

CREATE VIEW gftp_distinct_server_community_overview(
    aggregation_time, aggregation_time_range, community, server_count)
AS
    SELECT
        aggregation_time,
        aggregation_time_range,
        CASE
            WHEN community_name is NULL THEN 'Other'
            ELSE community_name
        END AS community,
        COUNT(DISTINCT ip_address) AS server_count
        FROM gftp_server_stream_aggregations
        INNER JOIN gftp_server ON server_id = gftp_server.id
        INNER JOIN dns_cache ON host_id = dns_cache.id
        LEFT OUTER JOIN usage_community ON hostname LIKE dns_pattern
        GROUP BY aggregation_time, aggregation_time_range, community;
    

CREATE VIEW gftp_server_stream_community_overview(
    aggregation_time, aggregation_time_range, community, number_of_streams, transfer_count, byte_count)
AS
    SELECT
        aggregation_time,
        aggregation_time_range,
        CASE
            WHEN community_name IS NULL THEN 'Other'
            ELSE community_name
        END AS community,
        num_streams AS number_of_streams,
        SUM(transfer_count) AS transfer_count,
        SUM(byte_count) AS byte_count
        FROM gftp_server_stream_aggregations
        INNER JOIN gftp_server ON server_id = gftp_server.id
        INNER JOIN dns_cache ON host_id = dns_cache.id
        LEFT OUTER JOIN usage_community ON hostname LIKE dns_pattern
        GROUP BY aggregation_time, aggregation_time_range, community, number_of_streams;


CREATE VIEW gftp_transfer_size_community_overview(
    aggregation_time, aggregation_time_range, community,
    transfer_size, transfer_count, byte_count)
AS
    SELECT
        aggregation_time,
        aggregation_time_range,
        CASE
            WHEN community_name IS NULL THEN 'Other'
            ELSE community_name
        END AS community,
        CASE 
            WHEN log10_transfer_size_bytes = 0
                THEN 0
            ELSE
                10^log10_transfer_size_bytes
        END AS transfer_size,
        SUM(transfer_count) AS transfer_count,
        SUM(byte_count) AS byte_count
        FROM gftp_server_histogram_aggregations
        INNER JOIN gftp_server ON server_id = gftp_server.id
        INNER JOIN dns_cache ON host_id = dns_cache.id
        LEFT OUTER JOIN usage_community ON hostname LIKE dns_pattern
        GROUP BY aggregation_time, aggregation_time_range, community, transfer_size;

CREATE VIEW gftp_transfer_rate_community_overview(
    aggregation_time, aggregation_time_range, community,
    transfer_rate_bps, transfer_count, byte_count)
AS
    SELECT
        aggregation_time,
        aggregation_time_range,
        CASE
            WHEN community_name IS NULL THEN 'Other'
            ELSE community_name
        END AS community,
        CASE 
            WHEN log10_transfer_rate_bps = 0
                THEN 0
            ELSE
                10^log10_transfer_rate_bps
        END AS transfer_rate_bps,
        SUM(transfer_count) AS transfer_count,
        SUM(byte_count) AS byte_count
        FROM gftp_server_histogram_aggregations
        INNER JOIN gftp_server ON server_id = gftp_server.id
        INNER JOIN dns_cache ON host_id = dns_cache.id
        LEFT OUTER JOIN usage_community ON hostname LIKE dns_pattern
        GROUP BY aggregation_time, aggregation_time_range, community, transfer_rate_bps;

CREATE VIEW gftp_transfer_rate_size_community_overview(
    aggregation_time, aggregation_time_range, community,
    transfer_rate_bps, transfer_size, transfer_count, byte_count)
AS
    SELECT
        aggregation_time,
        aggregation_time_range,
        CASE
            WHEN community_name IS NULL THEN 'Other'
            ELSE community_name
        END AS community,
        CASE 
            WHEN log10_transfer_rate_bps = 0
                THEN 0
            ELSE
                10^log10_transfer_rate_bps
        END AS transfer_rate_bps,
        CASE 
            WHEN log10_transfer_size_bytes = 0
                THEN 0
            ELSE
                10^log10_transfer_size_bytes
        END AS transfer_size,
        SUM(transfer_count) AS transfer_count,
        SUM(byte_count) AS byte_count
        FROM gftp_server_histogram_aggregations
        INNER JOIN gftp_server ON server_id = gftp_server.id
        INNER JOIN dns_cache ON host_id = dns_cache.id
        LEFT OUTER JOIN usage_community ON hostname LIKE dns_pattern
        GROUP BY aggregation_time, aggregation_time_range, community, transfer_rate_bps, transfer_size;
