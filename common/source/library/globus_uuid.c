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

#include "globus_common_include.h"
#include "globus_libc.h"
#include "globus_uuid.h"
#include "globus_hashtable.h"
#include GLOBUS_THREAD_INCLUDE

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif
#ifdef HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif
#ifdef HAVE_NET_IF_ARP_H
#include <net/if_arp.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef WIN32
#define l_getpid() ((int) GetCurrentProcessId())
#define l_getuid() ((int) globus_hashtable_string_hash(                     \
    getenv("USERNAME") ? getenv("USERNAME") : "noonespecial", INT_MAX))
#elif defined(TARGET_ARCH_NETOS)
#define l_getpid() 1
#define l_getuid() 0
#else
#define l_getpid() ((int) getpid())
#define l_getuid() ((int) getuid())
#endif

static globus_thread_once_t             globus_l_uuid_once = 
    GLOBUS_THREAD_ONCE_INIT;
static unsigned char                    globus_l_uuid_mac[6];
static globus_abstime_t                 globus_l_uuid_last_time;
static globus_mutex_t                   globus_l_uuid_lock;
static uint16_t                         globus_l_uuid_sequence;

static
int
globus_l_uuid_get_mac(
    unsigned char                       mac[6])
{
#if defined SIOCGIFHWADDR
    /* linux systems */
    
    struct ifreq                        interface;
    int                                 sock;
    
    if((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
    {
        return GLOBUS_FAILURE;
    }
    
    /* should probably try multiple interfaces here */
    memset(&interface, 0, sizeof(interface));
    strcpy(interface.ifr_name, "eth0");
    if(ioctl(sock, SIOCGIFHWADDR, &interface) < 0)
    {
        close(sock);
        return GLOBUS_FAILURE;
    }
    memcpy(mac, interface.ifr_addr.sa_data, 6);
    close(sock);
    return GLOBUS_SUCCESS;
    
#elif defined SIOCGARP
    /* solaris systems */
    
    int                                 sock;
    struct arpreq                       req;
    
    /* XXX this probably won't work right on an ipv6 machine */
    memset(&req, 0, sizeof(req));
    if(globus_libc_gethostaddr(
        (globus_sockaddr_t *)&req.arp_pa) != GLOBUS_SUCCESS)
    {
        return GLOBUS_FAILURE;
    }
    
    if((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
        return GLOBUS_FAILURE;
    }
    
    if(ioctl(sock, SIOCGARP, &req) < 0)
    {
        close(sock);
        return GLOBUS_FAILURE;
    }
    
    memcpy(mac, req.arp_ha.sa_data, 6);
    close(sock);
    return GLOBUS_SUCCESS;

#elif defined HAVE_IFADDRS_H
    /* other bsd systems */
    
    struct ifaddrs *                    interface;
    struct ifaddrs *                    save;
    int                                 rc = GLOBUS_FAILURE;

    if(getifaddrs(&save) < 0 || !save)
    {
        return GLOBUS_FAILURE;
    }

    for(interface = save; interface; interface = interface->ifa_next)
    {
        if(interface->ifa_addr && interface->ifa_addr->sa_family == AF_LINK)
        {
            struct sockaddr_dl *        sdl;
        
            sdl = (struct sockaddr_dl *)interface->ifa_addr;
            if(sdl->sdl_alen == 6)
            {
                memcpy(mac, sdl->sdl_data + sdl->sdl_nlen, 6);
                rc = GLOBUS_SUCCESS;
                break;
            }
        }
    }
    
    freeifaddrs(save);
    return rc;

#elif defined WIN32
    /* windows */
    
    IP_ADAPTER_INFO *                   interfaces;
    ULONG                               len = 0L;
    int                                 i;
    
    if(GetAdaptersInfo(NULL, &len) == ERROR_BUFFER_OVERFLOW)
    {
        interfaces = (IP_ADAPTER_INFO *) alloca(len);
    
        if(GetAdaptersInfo(interfaces, &len) == ERROR_SUCCESS)
        {
            len /= sizeof(IP_ADAPTER_INFO);
            for(i = 0; i < len; i++)
            {
                if(interfaces[i].AddressLength == 6)
                {
                    memcpy(mac, interfaces[i].Address, 6);
                    return GLOBUS_SUCCESS;
                }
            }
        }
    }
    
    return GLOBUS_FAILURE;
#else
    return GLOBUS_FAILURE;
#endif
}

static
void
globus_l_uuid_init(void)
{
    globus_mutex_init(&globus_l_uuid_lock, NULL);
    globus_mutex_lock(&globus_l_uuid_lock);
    
    GlobusTimeAbstimeGetCurrent(globus_l_uuid_last_time);
    srand(((l_getpid() << 16) | (l_getuid() & 0xffff)) ^
        globus_l_uuid_last_time.tv_sec);
    
    /* setup sequence and set variant to uuid urn (10 in upper two bits) */
    globus_l_uuid_sequence = ((uint16_t) rand() & 0x3fff) | 0x8000;
    if(globus_l_uuid_get_mac(globus_l_uuid_mac) != GLOBUS_SUCCESS)
    {
        /* create random mac */
        unsigned char *                 p;
        uint32_t                        tmp_rand;
        
        p = &globus_l_uuid_mac[0];
        tmp_rand = (uint32_t) rand();
        memcpy(p, &tmp_rand, sizeof(uint32_t));

        p = &globus_l_uuid_mac[2];
        tmp_rand = (uint32_t) rand();
        memcpy(p, &tmp_rand, sizeof(uint32_t));

        /** Set IEEE 802 multicast bit */
        globus_l_uuid_mac[0] |= 0x01;
    }
    
    globus_mutex_unlock(&globus_l_uuid_lock);
}

int
globus_uuid_create(
    globus_uuid_t *                     uuid)
{
    globus_uuid_fields_t *              fields;
    globus_abstime_t                    current_time;
    uint16_t                            sequence;
    uint64_t                            timestamp;
    uint32_t                            upper;
    
    globus_thread_once(&globus_l_uuid_once, globus_l_uuid_init);
    
    globus_mutex_lock(&globus_l_uuid_lock);
    {
        GlobusTimeAbstimeGetCurrent(current_time);
        if(globus_abstime_cmp(&current_time, &globus_l_uuid_last_time) <= 0)
        {
            sequence = globus_l_uuid_sequence;
            do
            {
                /* either we're generating these too fast or someone changed
                 * clock on us, get new sequence number */
                globus_l_uuid_sequence = ((uint16_t) rand() & 0x3fff) | 0x8000;
            } while(globus_l_uuid_sequence == sequence);
            memcpy(&globus_l_uuid_last_time,
                &current_time, sizeof(current_time));
        }
        sequence = globus_l_uuid_sequence;
    }
    globus_mutex_unlock(&globus_l_uuid_lock);
    
    timestamp = (uint64_t) current_time.tv_sec * 10000000;
    timestamp += (uint64_t) current_time.tv_nsec / 100;
    /* offset to gregorian time */
    timestamp += (uint64_t) 0x01b21dd2 << 32;
    timestamp += 0x13814000;
    upper = timestamp >> 32;
    
    fields = &uuid->binary.fields;
    fields->time_low = timestamp;
    fields->time_mid = upper;
    fields->time_hi_and_version = ((upper >> 16) & 0x0fff) | 0x1000;
    fields->clock_seq_low = sequence;
    fields->clock_seq_hi_and_reserved = sequence >> 8;
    memcpy(fields->node, globus_l_uuid_mac, 6);
    
    snprintf(uuid->text, sizeof(uuid->text),
        "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        (unsigned long) fields->time_low,
        fields->time_mid,
        fields->time_hi_and_version,
        fields->clock_seq_hi_and_reserved,
        fields->clock_seq_low,
        fields->node[0],
        fields->node[1],
        fields->node[2],
        fields->node[3],
        fields->node[4],
        fields->node[5]);
    
    fields->time_low = htonl(fields->time_low);
    fields->time_mid = htons(fields->time_mid);
    fields->time_hi_and_version = htons(fields->time_hi_and_version);

    return GLOBUS_SUCCESS;
}

int
globus_uuid_import(
    globus_uuid_t *                     uuid,
    const char *                        str)
{
    globus_uuid_fields_t *              fields;
    int                                 i;
    uint16_t                            hilow;
    char                                buf[3];
    
    /* skip leading uuid:, if it exists */
    if(strncmp("uuid:", str, 5) == 0)
    {
        str += 5;
    }
    
    /**
     * 1b4e28ba-2fa1-11d2-883f-b9a761bde3fb
     * 012345678901234567890123456789012345
     * 0         1         2         3     
     */
    for(i = 0; i < GLOBUS_UUID_TEXTLEN; i++)
    {
        if(i == 8 || i == 13 || i == 18 || i == 23)
        {
            if(str[i] != '-')
            {
                return GLOBUS_FAILURE;
            }
        }
        else if(!isxdigit(str[i]))
        {
            return GLOBUS_FAILURE;
        }
    }
    
    memcpy(uuid->text, str, GLOBUS_UUID_TEXTLEN);
    uuid->text[GLOBUS_UUID_TEXTLEN] = 0;
    
    fields = &uuid->binary.fields;
    fields->time_low = htonl(strtoul(str, NULL, 16));
    fields->time_mid = htons(strtoul(str + 9, NULL, 16));
    fields->time_hi_and_version = htons(strtoul(str + 14, NULL, 16));
    hilow = strtoul(str + 19, NULL, 16);
    fields->clock_seq_low = hilow;
    fields->clock_seq_hi_and_reserved = hilow >> 8;

    str += 24;
    buf[2] = '\0';
    for(i = 0; i < 6; i++)
    {
        buf[0] = *str++;
        buf[1] = *str++;
        fields->node[i] = strtoul(buf, NULL, 16);
    }
    
    return GLOBUS_SUCCESS;
}

int
globus_uuid_fields(
    globus_uuid_t *                     uuid,
    globus_uuid_fields_t *              uuid_fields)
{
    globus_uuid_fields_t *              fields;
    
    fields = &uuid->binary.fields;
    uuid_fields->time_low = ntohl(fields->time_low);
    uuid_fields->time_mid = ntohs(fields->time_mid);
    uuid_fields->time_hi_and_version = ntohs(fields->time_hi_and_version);
    uuid_fields->clock_seq_low = fields->clock_seq_low;
    uuid_fields->clock_seq_hi_and_reserved = fields->clock_seq_hi_and_reserved;
    memcpy(uuid_fields->node, fields->node, 6);
    
    return GLOBUS_SUCCESS;
}
