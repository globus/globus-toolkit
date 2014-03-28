#ifndef GLOBUS_LIBNICE_MINGW_H
#define GLOBUS_LIBNICE_MINGW_H

    #ifdef __MINGW32__

        #ifndef _SSIZE_T_ 
            #define _SSIZE_T_ 1
        #endif /* _SSIZE_T_ */

        #ifndef IN6_ARE_ADDR_EQUAL
            #define IN6_ARE_ADDR_EQUAL(a, b) \
                (memcmp(&(a)->s6_addr[0], &(b)->s6_addr[0], \
                    sizeof(struct in6_addr)) == 0)
        #endif /* IN6_ARE_ADDR_EQUAL */
    #endif /* __MINGW32__ */

#endif /* GLOBUS_LIBNICE_MINGW_H */
