void
test_parse_args(int argc, 
		char *argv[],
		globus_ftp_client_handleattr_t    * handleattr,
		globus_ftp_client_operationattr_t * operationattr,
		char **src,
		char **dst);

void
test_remove_arg(int *argc, char **argv, int *start, int num_of_options);

extern int test_abort_count;

