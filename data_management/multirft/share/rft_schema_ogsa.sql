

-- schema for multi file reliable file transfer service
-- one transfer request can contain more than one transfer
-- if concurrency is not specified it is assumed to be '1'
create sequence transfer_seq;

create sequence request_seq;

create table request
(
    id                  int     primary key default nextval('request_seq'),
    concurrency         int     default 1
);

-- status = 0 = transfer FINISHED
-- status = 1 = transfer RETRYING 
-- status = 2 = transfer FAILED
-- status = 3 = transfer ACTIVE
-- status = 4 = transfer PENDING
-- status = 5 = transfer CANCELLED

create table transfer
(
	id					int primary key default nextval('transfer_seq'),
    request_id          int             default 0,
	source_url			text			not null,
	dest_url			text			not null,
	status				int 			default	4,
	attempts			int 			default 0,
	dcau				boolean			default FALSE,
    parallel_streams    int             default 1,
    tcp_buffer_size     int             default 0,
    block_size          integer                    ,
    notpt               boolean         default FALSE,
    binary_mode         boolean         default TRUE,
    source_subject      text,
    dest_subject        text
);

create table restart
(
	transfer_id 		int,
	marker				text
);

create table proxyinfo
(
    transfer_id int,
    proxy_loc   text
);

