#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_url.h URL Parsing.
 *
 */
#endif

/**
 * @defgroup globus_url URL String Parser
 *
 * The Globus URL functions provide a simple mechanism for parsing
 * a URL string into a data structure, and for determining the scheme
 * of an URL string.
 *
 * These functions are part of the Globus common library. The GLOBUS_COMMON
 * module must be activated in order to use them.
 */
#ifndef GLOBUS_INCLUDE_GLOBUS_URL_H_
#define GLOBUS_INCLUDE_GLOBUS_URL_H_

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

EXTERN_C_BEGIN

/* Supported URL Schemes */
/**
 * URL Schemes.
 *
 * The Globus URL library supports a set of URL schemes (protocols).
 * The globus_url_t's scheme_type member is set to one of these.
 */
typedef enum
{
    GLOBUS_URL_SCHEME_FTP=0,
    GLOBUS_URL_SCHEME_GSIFTP,
    GLOBUS_URL_SCHEME_HTTP,
    GLOBUS_URL_SCHEME_HTTPS,
    GLOBUS_URL_SCHEME_LDAP,
    GLOBUS_URL_SCHEME_FILE,
    GLOBUS_URL_SCHEME_X_NEXUS,
    GLOBUS_URL_SCHEME_X_GASS_CACHE,
    GLOBUS_URL_SCHEME_UNKNOWN, /* anything of the form 
        				       <scheme>://<something> */
    GLOBUS_URL_NUM_SCHEMES
} globus_url_scheme_t;

/*
  Other schemes defined in RFCs but _not_ supported here are 
 'news', 'nntp', 'telnet', 'gopher', 'wais', 'mailto', and 'prospero'
*/

/**
 * @struct globus_url_t Parsed URLs.
 * @ingroup globus_url
 *
 * This structure contains the fields which were parsed from an string
 * representation of an URL. There are no methods to access fields of this
 * structure. 
 */
typedef struct
{
    char *scheme;		/* scheme (http, ftp, etc) name in RFC 1738 */
    globus_url_scheme_t scheme_type;
    /* 
      ftp://[user[:password]@]host[:port]/[url_path]
      gsiftp://[user[:password]@]host[:port]/[url_path]
      http://host[:port]/url_path
      x-nexus://host:port
      x-gass-cache://url_path
      ldap://host[:port]/dn?attributes?scope?filter
      otherurl://host[:port]/url_path or
      otherurl://url_specific_part
    */
    char *user;			/* ftp, gsiftp */
    char *password;		/* ftp, gsiftp */
    char *host;			/* ftp, gsiftp, http, https, ldap, x-nexus */
    unsigned short port;	/* ftp, gsiftp, http, https, ldap, x-nexus */
    char *url_path;		/* ftp, gsiftp, http, https  */

    char *dn;			/* ldap */
    char *attributes;		/* ldap */
    char *scope;		/* ldap */
    char *filter;		/* ldap */
    
    char *url_specific_part;	/* x-gass-cache and for unknown url schemes */
} globus_url_t;

/* Fill in the data structure pointed to by url */
int globus_url_parse(const char *url_string, globus_url_t *url);

/* Destroy the fields of the data structure pointed to by url */
int globus_url_destroy(globus_url_t *url);

/* Create a copy of a globus_url_t structure */
int globus_url_copy(globus_url_t * dest, const globus_url_t * src);

/* Find out the URL scheme type */
int globus_url_get_scheme(const char *url_string,
			  globus_url_scheme_t *scheme_type);

/* Return conditions */
#define GLOBUS_URL_SUCCESS 0
#define GLOBUS_URL_ERROR_NULL_STRING -1
#define GLOBUS_URL_ERROR_NULL_URL -2
#define GLOBUS_URL_ERROR_BAD_SCHEME -3
#define GLOBUS_URL_ERROR_BAD_USER -4
#define GLOBUS_URL_ERROR_BAD_PASSWORD -5
#define GLOBUS_URL_ERROR_BAD_HOST -6
#define GLOBUS_URL_ERROR_BAD_PORT -7
#define GLOBUS_URL_ERROR_BAD_PATH -8

/* for ldap URLs */
#define GLOBUS_URL_ERROR_BAD_DN -9
#define GLOBUS_URL_ERROR_BAD_ATTRIBUTES -10
#define GLOBUS_URL_ERROR_BAD_SCOPE -11
#define GLOBUS_URL_ERROR_BAD_FILTER -12

/* when malloc fails */
#define GLOBUS_URL_ERROR_OUT_OF_MEMORY -13

/* for nexus errors/former assertion failures */
#define GLOBUS_URL_ERROR_INTERNAL_ERROR -14

#define GLOBUS_URL_TRUE 1
#define GLOBUS_URL_FALSE 0

EXTERN_C_END
#endif
