/**
 *  Defines the macros and typedefs common to all globus_common
 *  components.
 */
#if !defined(GLOBUS_COMMON_TYPES_H)


/*
 *  common macros
 */
#define GLOBUS_TRUE	    1
#define GLOBUS_FALSE	0
#define GLOBUS_NULL  	0
#define GLOBUS_FAILURE  1
#define GLOBUS_SUCCESS  0

/******************************************************************************
				 Define macros
******************************************************************************/

/*
 * Various macro definitions for assertion checking
 */
#if defined(BUILD_DEBUG)
#   define globus_assert(assertion)					\
    do {								\
        if (!(assertion))						\
        {								\
            fprintf(stderr, "Assertion " #assertion			\
		    " failed in file %s at line %d\n",			\
		    __FILE__, __LINE__);				\
	    abort();							\
         }								\
    } while(0)

#   define globus_assert_string(assertion, string)			\
    do {								\
    	if (!(assertion))						\
    	{								\
    	    fprintf(stderr, "Assertion " #assertion			\
		    " failed in file %s at line %d: %s",		\
		    __FILE__, __LINE__, string);			\
	    abort();							\
    	}								\
    } while(0)
#else /* BUILD_DEBUG */
#   define globus_assert(assertion)
#   define globus_assert_string(assertion, string)
#endif /* BUILD_DEBUG */

#define GLOBUS_MAX(V1,V2) (((V1) > (V2)) ? (V1) : (V2))
#define GLOBUS_MIN(V1,V2) (((V1) < (V2)) ? (V1) : (V2))


#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

typedef unsigned char	                           globus_byte_t;
typedef int		                                   globus_bool_t;
typedef void *                                     globus_result_t;


#if !defined(TARGET_ARCH_WIN32)
typedef size_t                                     globus_size_t;
#else
typedef long                                       globus_size_t;
#endif

#endif  /* GLOBUS_COMMON_TYPES_H */

/* WTF */