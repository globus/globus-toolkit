/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#include "globus_common.h"

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifndef IP_TCP
#define IP_TCP IPPROTO_TCP
#endif

#ifndef IP_UDP
#define IP_UDP IPPROTO_UDP
#endif

#ifdef GLOBUS_IMPLEMENT_GETADDRINFO
int
getaddrinfo(
    const char *                        node,
    const char *                        service,
    const struct addrinfo *             hints,
    struct addrinfo **                  res)
{
    /* Version of getaddrinfo for hosts without IPV6 */
    struct hostent *                    hostent = NULL;
    struct hostent                      hostent_res;
    char                                buffer[256];
#ifdef HAVE_GETSERVBYNAME
    struct servent *                    servent;
    struct protoent *                   proto;
#endif
    char *                              proto_name = NULL;
    int                                 h_errno;
    struct addrinfo *                   addrinfo;
    int                                 service_port = 0;
    static char *                       aliases = NULL;
    static char *                       addr_any = NULL;
    static struct hostent               localhostent = {
        "localhost",
        &aliases,
        AF_INET,
        sizeof(struct sockaddr_in),
        &addr_any
    };
    globus_result_t                     result = GLOBUS_SUCCESS;

    if (hints != NULL)
    {
        if (hints->ai_family != AF_UNSPEC && hints->ai_family != AF_INET)
        {
            /* Unsupported by this implementation */
            result = globus_error_put(
                globus_error_wrap_errno_error(
                    GLOBUS_COMMON_MODULE,
                    0,
                    0 + GLOBUS_EAI_ERROR_OFFSET,
                    __FILE__,
                    "globus_libc_getaddrinfo",
                    __LINE__,
                    "%s",
                    "Unsupported family\n"));
            goto error_out;
        }
    }

    if (node != NULL)
    {
        if (hints != NULL && (hints->ai_flags & AI_NUMERICHOST))
        {
            struct sockaddr_in          addr;

            addr.sin_addr.s_addr = inet_addr(node);

            if ((int) addr.sin_addr.s_addr != -1)
            {
                    hostent = globus_libc_gethostbyaddr_r(
                        (void *) &addr,
                        sizeof(addr),
                        AF_INET,
                        &hostent_res,
                        buffer,
                        sizeof(buffer),
                        &h_errno);
            }
            else
            {
                hostent = &localhostent;
            }
        }
        else
        {
            hostent = globus_libc_gethostbyname_r(
                    (char *) node,
                    &hostent_res,
                    buffer,
                    sizeof(buffer),
                    &h_errno);
        }
        if (hostent == NULL)
        {
            result = globus_error_put(
                globus_error_wrap_errno_error(
                    GLOBUS_COMMON_MODULE,
                    h_errno,
                    0 + GLOBUS_EAI_ERROR_OFFSET,
                    __FILE__,
                    "globus_libc_getaddrinfo",
                    __LINE__,
                    "%s",
                    "gethostbyname_r failed\n"));

            goto error_out;
        }
    }

    if (hints != NULL && hints->ai_protocol != 0)
    {
#ifdef HAVE_GETPROTOBYNUMBER
        proto = getprotobynumber(hints->ai_protocol);

        if (proto != NULL)
        {
            proto_name = proto->p_name;

            if (hints->ai_socktype != 0)
            {
                if ((proto->p_proto == IP_TCP &&
                    hints->ai_socktype != SOCK_STREAM) ||
                    (proto->p_proto == IP_UDP &&
                    hints->ai_socktype != SOCK_DGRAM))
                {
                    result = globus_error_put(
                        globus_error_wrap_errno_error(
                            GLOBUS_COMMON_MODULE,
                            0,
                            0 + GLOBUS_EAI_ERROR_OFFSET,
                            __FILE__,
                            "globus_libc_getaddrinfo",
                            __LINE__,
                            "%s",
                            "mismatch of proto and sock type\n"));
                }
            }
        }
        else
        {
            result = globus_error_put(
                globus_error_wrap_errno_error(
                    GLOBUS_COMMON_MODULE,
                    errno,
                    GLOBUS_EAI_ERROR_OFFSET,
                    __FILE__,
                    "globus_libc_getaddrinfo",
                    __LINE__,
                    "%s",
                    "getprotobynumber failed\n"));
            goto error_out;
        }
#else
        if (hints->ai_protocol == IP_TCP)
        {
            proto_name = "tcp";
        }
        else if (hints->ai_protocol == IP_UDP)
        {
            proto_name = "udp";
        }
#endif
    }
    else if (hints != NULL && hints->ai_socktype != 0)
    {
        if (hints->ai_socktype == SOCK_STREAM)
        {
            proto_name = "tcp";
        }
        else if (hints->ai_socktype == SOCK_DGRAM)
        {
            proto_name = "udp";
        }

        if (proto_name == NULL)
        {
            result = globus_error_put(
                globus_error_wrap_errno_error(
                    GLOBUS_COMMON_MODULE,
                    errno,
                    GLOBUS_EAI_ERROR_OFFSET,
                    __FILE__,
                    "globus_libc_getaddrinfo",
                    __LINE__,
                    "%s",
                    "unknown socket type\n"));
            goto error_out;
        }
    }

    if (service != NULL)
    {
#ifdef HAVE_GETSERVBYNAME
        servent = getservbyname(service, proto_name);

        if (servent != NULL)
        {
            service_port = servent->s_port;
        }
#else
        service_port = atoi(service);
#endif
    }

    addrinfo = calloc(1, sizeof(struct addrinfo));

    if (addrinfo == NULL)
    {

        result = globus_error_put(
            globus_error_construct_error(
                GLOBUS_COMMON_MODULE,
                GLOBUS_NULL,
                0,
                __FILE__,
                "globus_libc_addr_to_contact_string",
                __LINE__,
                "malloc failed"));
        goto error_out;
    }

    addrinfo->ai_family = AF_INET;

    if (strcmp(proto_name, "tcp") == 0)
    {
        addrinfo->ai_socktype = SOCK_STREAM;
        addrinfo->ai_protocol = IP_TCP;
    }
    else if (strcmp(proto_name, "udp") == 0)
    {
        addrinfo->ai_socktype = SOCK_DGRAM;
        addrinfo->ai_protocol = IP_UDP;
    }

    if (node != NULL && hints != NULL && (hints->ai_flags & AI_CANONNAME))
    {
        addrinfo->ai_canonname = globus_libc_strdup(hostent->h_name);
    }

    if (node == NULL)
    {
        if (hints != NULL && (hints->ai_flags & AI_PASSIVE))
        {
            /* Unspecified if node is null and AI_PASSIVE is set */
            struct sockaddr_in *        a;

            addrinfo->ai_addrlen = sizeof(struct sockaddr_in);
            addrinfo->ai_addr = a = calloc(1, addrinfo->ai_addrlen);
            if (a == NULL)
            {
                result = globus_error_put(
                    globus_error_construct_error(
                        GLOBUS_COMMON_MODULE,
                        GLOBUS_NULL,
                        0,
                        __FILE__,
                        "getaddrinfo",
                        __LINE__,
                        "malloc failed"));

                goto free_addrinfo_out;
            }
            a->sin_addr.s_addr = INADDR_ANY;
            a->sin_family = AF_INET;
            a->sin_port = service_port;
        }
        else
        {
            /* Set to loopback if node is null and AI_PASSIVE is not set */
            struct sockaddr_in *        a;

            addrinfo->ai_addrlen = sizeof(struct sockaddr_in);
            a = malloc(addrinfo->ai_addrlen);

            if (a == NULL)
            {
                result = globus_error_put(
                    globus_error_construct_error(
                        GLOBUS_COMMON_MODULE,
                        GLOBUS_NULL,
                        0,
                        __FILE__,
                        "getaddrinfo",
                        __LINE__,
                        "malloc failed"));

                goto free_addrinfo_out;
            }

            a->sin_family = AF_INET;
#ifdef INADDR_LOOPBACK
            a->sin_addr.s_addr = INADDR_LOOPBACK;
#else
            a->sin_addr.s_addr = INADDR_ANY;
#endif
            a->sin_port = service_port;

            addrinfo->ai_addr = (struct sockaddr *) a;
        }
    }
    else
    {
        int                             i;
        struct addrinfo *               tmp = addrinfo;

        for (i = 0; hostent->h_addr_list[i] != NULL; i++)
        {
            struct sockaddr_in *        a;
            if (i != 0)
            {
                tmp->ai_next = malloc(sizeof(struct addrinfo));

                if (tmp->ai_next == NULL)
                {
                    result = globus_error_put(
                        globus_error_construct_error(
                            GLOBUS_COMMON_MODULE,
                            GLOBUS_NULL,
                            0,
                            __FILE__,
                            "getaddrinfo",
                            __LINE__,
                            "malloc failed"));
                    goto free_addrinfo_out;
                }

                memcpy(tmp->ai_next, addrinfo, sizeof(struct addrinfo));

                tmp = tmp->ai_next;
                tmp->ai_next = NULL;
            }

            if (hostent->h_addrtype != AF_INET)
            {
                result = globus_error_put(
                    globus_error_wrap_errno_error(
                        GLOBUS_COMMON_MODULE,
                        errno,
                        GLOBUS_EAI_ERROR_OFFSET,
                        __FILE__,
                        "getaddrinfo",
                        __LINE__,
                        "%s",
                        "unknown address type\n"));
                goto free_addrinfo_out;
            }
            tmp->ai_addrlen = sizeof(struct sockaddr_in);
            tmp->ai_addr = a = malloc(tmp->ai_addrlen);
            if (a == NULL)
            {
                result = globus_error_put(
                    globus_error_construct_error(
                        GLOBUS_COMMON_MODULE,
                        GLOBUS_NULL,
                        0,
                        __FILE__,
                        "getaddrinfo",
                        __LINE__,
                        "malloc failed"));
                goto free_addrinfo_out;
            }
            a->sin_family = AF_INET;
            memcpy(&a->sin_addr,
                   hostent->h_addr_list[i],
                   tmp->ai_addrlen);
            a->sin_port = service_port;
        }
    }
    *res = addrinfo;

    return result;

free_addrinfo_out:
    globus_libc_freeaddrinfo(addrinfo);
error_out:
    return result;
}
#endif /* GLOBUS_IMPLEMENT_GETADDRINFO */
