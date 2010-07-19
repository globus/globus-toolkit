/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

