/* ========================================================================
 * Copyright 2005 University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================================
 */

/* Modified version of pubcookie/src/pubcookie.h
 * (pubcookie version: 3.2.1a - Sept 29, 2005)
 * to get the needed struct cookie_data defined for MyProxy.
 */

#ifndef PUBCOOKIE_MAIN
#define PUBCOOKIE_MAIN

#define PBC_USER_LEN 42
#define PBC_VER_LEN 4
#define PBC_APPSRV_ID_LEN 40
#define PBC_APP_ID_LEN 128

struct cookie_data
{
  unsigned char user[PBC_USER_LEN];
  unsigned char version[PBC_VER_LEN];
  unsigned char appsrvid[PBC_APPSRV_ID_LEN];
  unsigned char appid[PBC_APP_ID_LEN];
  unsigned char type;
  unsigned char creds;
  uint32_t pre_sess_token;
  uint32_t create_ts;
  uint32_t last_ts;
};

#endif /* !PUBCOOKIE_MAIN */
