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

#ifndef GLOBUS_I_GFS_IPC_H
#define GLOBUS_I_GFS_IPC_H

#include "globus_i_gridftp_server.h"

/************************************************************************
 *   packing macros
 *   --------------
 ***********************************************************************/
#define GFSEncodeUInt32(_start, _len, _buf, _w)                         \
do                                                                      \
{                                                                       \
    globus_size_t                       _ndx;                           \
    uint32_t                            _cw;                            \
    _ndx = (globus_byte_t *)_buf - (globus_byte_t *)_start;             \
    /* verify buffer size */                                            \
    if(_ndx + 4 > _len)                                                 \
    {                                                                   \
        _len *= 2;                                                      \
        _start = globus_libc_realloc(_start, _len);                     \
        _buf = _start + _ndx;                                           \
    }                                                                   \
    _cw = htonl((uint32_t)_w);                                          \
    memcpy(_buf, &_cw, 4);                                              \
    _buf += 4;                                                          \
} while(0)

#define GFSDecodeUInt32P(_buf, _len, _w)                                \
do                                                                      \
{                                                                       \
    uint32_t                            _cw;                            \
    /* verify buffer size */                                            \
    if(_len - 4 < 0)                                                    \
    {                                                                   \
        goto decode_err;                                                \
    }                                                                   \
    memcpy(&_cw, _buf, 4);                                              \
    _w = (void *) htonl((uint32_t)_cw);                                 \
    _buf += 4;                                                          \
    _len -= 4;                                                          \
} while(0)

#define GFSDecodeUInt32(_buf, _len, _w)                                 \
do                                                                      \
{                                                                       \
    uint32_t                            _cw;                            \
    /* verify buffer size */                                            \
    if(_len - 4 < 0)                                                    \
    {                                                                   \
        goto decode_err;                                                \
    }                                                                   \
    memcpy(&_cw, _buf, 4);                                              \
    _w = htonl((uint32_t)_cw);                                          \
    _buf += 4;                                                          \
    _len -= 4;                                                          \
} while(0)


/*
 *  if architecture is big endian already
 */
#if defined(WORDS_BIGENDIAN)

#define GFSEncodeUInt64(_start, _len, _buf, _w)                         \
do                                                                      \
{                                                                       \
    globus_size_t                       _ndx;                           \
    _ndx = (globus_byte_t *)_buf - (globus_byte_t *)_start;             \
    if(_ndx + 8 > _len)                                                 \
    {                                                                   \
        _len *= 2;                                                      \
        _start = globus_libc_realloc(_start, _len);                     \
        _buf = _start + _ndx;                                           \
    }                                                                   \
    memcpy(_buf, &_w, 8);                                               \
    _buf += 8;                                                          \
} while(0)

#define GFSDecodeUInt64(_buf, _len, _w)                                 \
do                                                                      \
{                                                                       \
    if(_len - 8 < 0)                                                    \
    {                                                                   \
        goto decode_err;                                                \
    }                                                                   \
                                                                        \
    memcpy(&_w, _buf, 8);                                               \
    _buf += 8;                                                          \
    _len -= 8;                                                          \
} while(0)

#else                                                                
/* not a big indian arch */
#define GFSEncodeUInt64(_start, _len, _buf, _w)                         \
do                                                                      \
{                                                                       \
    globus_size_t                       _ndx;                           \
    uint64_t                            _cw;                            \
    uint32_t                            _lo = _w & 0xffffffff;          \
    uint32_t                            _hi = _w >> 32U;                \
                                                                        \
    _ndx = (globus_byte_t *)_buf - (globus_byte_t *)_start;             \
    if(_ndx + 8 > _len)                                                 \
    {                                                                   \
        _len *= 2;                                                      \
        _start = globus_libc_realloc(_start, _len);                     \
        _buf = _start + _ndx;                                           \
    }                                                                   \
                                                                        \
    _lo = ntohl(_lo);                                                   \
    _hi = ntohl(_hi);                                                   \
    _cw = ((uint64_t) _lo) << 32U | _hi;                                \
    memcpy(_buf, &_cw, 8);                                              \
    _buf += 8;                                                          \
} while(0)

#define GFSDecodeUInt64(_buf, _len, _w)                                 \
do                                                                      \
{                                                                       \
    uint64_t                            _cw;                            \
    uint32_t                            _lo;                            \
    uint32_t                            _hi;                            \
                                                                        \
    if(_len - 8 < 0)                                                    \
    {                                                                   \
        goto decode_err;                                                \
    }                                                                   \
                                                                        \
    memcpy(&_cw, _buf, 8);                                              \
    _lo = _cw & 0xffffffff;                                             \
    _hi = _cw >> 32U;                                                   \
    _lo = ntohl(_lo);                                                   \
    _hi = ntohl(_hi);                                                   \
    _w = ((uint64_t) _lo) << 32U | _hi;                                 \
    _buf += 8;                                                          \
    _len -= 8;                                                          \
} while(0)
#endif                                                               

#define GFSEncodeChar(_start, _len, _buf, _w)                           \
do                                                                      \
{                                                                       \
    globus_size_t                       _ndx;                           \
    _ndx = (globus_byte_t *)_buf - (globus_byte_t *)_start;             \
    if(_ndx >= _len)                                                    \
    {                                                                   \
        _len *= 2;                                                      \
        _start = globus_libc_realloc(_start, _len);                     \
        _buf = _start + _ndx;                                           \
    }                                                                   \
    *_buf = (char)_w;                                                   \
    _buf++;                                                             \
} while(0)

#define GFSDecodeChar(_buf, _len, _w)                                   \
do                                                                      \
{                                                                       \
    if(_len - 1 < 0)                                                    \
    {                                                                   \
        goto decode_err;                                                \
    }                                                                   \
    _w = (char)*_buf;                                                   \
    _buf++;                                                             \
    _len--;                                                             \
} while(0)

#define GFSEncodeString(_start, _len, _buf, _w)                         \
do                                                                      \
{                                                                       \
    char *                              _str=(char*)_w;                 \
    if(_str == NULL)                                                    \
    {                                                                   \
        GFSEncodeUInt32(_start, _len, _buf, 0);                         \
    }                                                                   \
    else                                                                \
    {                                                                   \
        GFSEncodeUInt32(_start, _len, _buf, strlen(_str)+1);            \
        for(_str = (char *)_w; *_str != '\0'; _str++)                   \
        {                                                               \
            GFSEncodeChar(_start, _len, _buf, *_str);                   \
        }                                                               \
    }                                                                   \
} while(0)

#define GFSDecodeString(_buf, _len, _w)                                 \
do                                                                      \
{                                                                       \
    int                                 _ctr;                           \
    uint32_t                            _sz;                            \
    /* make sure that strip in terminated properly */                   \
    GFSDecodeUInt32(_buf, _len, _sz);                                   \
    if(_sz > 0)                                                         \
    {                                                                   \
        _w = malloc(_sz);                                               \
        for(_ctr = 0; _ctr < _sz - 1; _ctr++)                           \
        {                                                               \
            GFSDecodeChar(_buf, _len, _w[_ctr]);                        \
        }                                                               \
        _w[_ctr] = '\0';                                                \
    }                                                                   \
    else                                                                \
    {                                                                   \
        _w = NULL;                                                      \
    }                                                                   \
} while(0)

typedef struct globus_i_gfs_community_s
{
    char *                              root;
    char *                              name;
    int                                 cs_count;
    char **                             cs;
    int                                 next_ndx;
} globus_i_gfs_community_t;

extern globus_xio_stack_t               globus_i_gfs_ipc_xio_stack;
extern globus_i_gfs_community_t *       globus_i_gfs_ipc_community_default;
extern globus_xio_driver_t              globus_i_gfs_tcp_driver;

#endif
