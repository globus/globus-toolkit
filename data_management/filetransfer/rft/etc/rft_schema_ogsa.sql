create sequence transfer_seq;

create table transfer
(
	id					int primary key default nextval('transfer_seq'),
	source_url			text			not null,
	dest_url			text			not null,
	status				int 			default	0,
	attempts			int 			default 0,
	dcau				boolean			default FALSE,
    parallel_streams    int             default 1,
    tcp_buffer_size     int             
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

