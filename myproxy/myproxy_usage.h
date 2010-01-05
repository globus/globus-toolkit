/*
 * Copyright 2009 The Board of Trustees of the University
 * of Illinois.  See the LICENSE file for detailed license information.
 *
 * Portions, specifically myproxy_usage_stats_init(), myproxy_usage_stats_close()
 * were based on those from: gridftp/server/source/globus_i_gfs_log.h
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

#ifndef __MYPROXY_USAGE_H
#define __MYPROXY_USAGE_H

#ifdef HAVE_GLOBUS_USAGE

#include "globus_usage.h"

struct myproxy_socket_attrs_s;
struct myproxy_server_context_s;

#define CILOGON_COLLECTOR "usage-stats.cilogon.org:4810"

globus_result_t
myproxy_usage_stats_init(struct myproxy_server_context_s *context);

void
myproxy_usage_stats_close(struct myproxy_server_context_s *context);

#endif /* GLOBUS_USAGE */

void
myproxy_send_usage_metrics(struct myproxy_socket_attrs_s *attrs,
                           myproxy_server_peer_t *client,
                           struct myproxy_server_context_s *context,
                           myproxy_request_t *request,
                           myproxy_creds_t *creds,
                           myproxy_response_t *response,
                           int success_flag);

#endif /* __MYPROXY_USAGE_H */
