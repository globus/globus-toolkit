/*
 * Copyright 2009 The Board of Trustees of the University
 * of Illinois.  See the LICENSE file for detailed license information.
 *
 * Portions, specifically ssh_usage_stats_init(), ssh_usage_stats_close()
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

#ifndef __SSH_GLOBUS_USAGE_H
#define __SSH_GLOBUS_USAGE_H

#include "includes.h"

#ifdef HAVE_GLOBUS_USAGE

#include "globus_usage.h"

#define CILOGON_COLLECTOR "usage-stats.cilogon.org:4810"

globus_result_t
ssh_usage_stats_init(int disable_usage_stats, char *usage_stats_targets);

void
ssh_usage_stats_close(int disable_usage_stats);

#endif /* HAVE_GLOBUS_USAGE */

void
ssh_globus_send_usage_metrics(char *ssh_release, const char *ssl_release,
                           char *method, char *mechanism, const char *client_ip,
                           char *username, char *userdn);

#endif /* __SSH_GLOBUS_USAGE_H */
