/*
 * secure_ext.c
 *
 * RFC 2228 Security extensions
 */

#include "config.h"
#include "proto.h"

#ifdef FTP_SECURITY_EXTENSIONS

#include "secure_ext.h"

#ifdef GSSAPI
#   include "gssapi-local.h"
#endif

#include "radix.h"

#include <unistd.h>		/* For syslog() */
#include <errno.h>
#include <netdb.h>
#include <string.h>
#ifdef HAVE_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif
#if defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H))
#include <syslog.h>
#endif

extern int debug;		/* From ftpd.c */

/* Succeed authentication mechanism */
char *auth_type = NULL; 

/* Authentication mechanism client is in process of attempting */
char *attempting_auth_type = NULL;

/* Protection level: PROT_C, PROT_S, PROT_P, PROT_E */
int protection_level = PROT_C;

char *protection_levelnames[] =  {"Undefined",		/* Undefined */
				  "Clear",
				  "Safe",
				  "Private",
				  "Confidential" };

/* Reply codes for the different protection levels */
int protection_level_reply_codes[] = { 0,		/* Undefined */
				       0,	/* Clear makes no sense */
				       631,	/* Safe */
				       632,	/* Private */
				       633 };	/* Confidential */

/* Protected buffer size */
unsigned int max_pbuf_size = 0;			/* Used in secure.c */
static unsigned int actual_pbuf_size = 0;

static unsigned char *cleartext_buffer = NULL;


#if USE_GLOBUS_DATA_CODE
#   define DATA_CHANNEL_PROTECTION 1
#endif
/*
 * setlevel()
 *
 * Set our protection level.
 *
 * XXX - No data encryption is currently supported. So I'm using
 * the fact that DATA_CHANNEL_PROTECTION is not defined here to
 * implement this.
 */
int
set_prot_level(int prot_level)
{
    if (debug)
	syslog(LOG_DEBUG, "Attempting to set protection level to %s",
	       protection_levelnames[prot_level]);
    
    if (max_pbuf_size == 0) {
	reply(504, "Must first set PBSZ");
	return -1;
    }
    
    switch (prot_level) {
    case PROT_S:
#ifdef DATA_CHANNEL_PROTECTION
	if (auth_type)
	    protection_level = prot_level;
#endif /* DATA_CHANNEL_PROTECTION */
	break;
	

    case PROT_P:

#ifdef DATA_CHANNEL_PROTECTION
#ifdef GSSAPI
	if (strcmp(auth_type, "GSSAPI") == 0) {
	    if (!gssapi_can_encrypt()) {
		if (debug) {
		    
		    syslog(LOG_INFO,
			   "gss_wrap_size_limit() called fail testing protection level %s",
			   protection_levelnames[prot_level]);
		}
		break;
	    }

	}
#endif /* GSSAPI */
			
	if (auth_type)
	    protection_level = prot_level;
#endif /* DATA_CHANNEL_PROTECTION */
	break;


    case PROT_C:
	protection_level = prot_level;
	break;

    default:
	/* Unknown or unsupported level */
	break;
    }

    if (protection_level == prot_level) {
	/* Success */
	reply(200, "Protection level set to %s.",
	      protection_levelnames[protection_level]);

    } else {
	/* Failure */
	reply(536, "%s protection level not supported.",
	      protection_levelnames[prot_level]);
    }
    return(0);
}


int
clear_cmd_channel()
{
    reply(534, "CCC not supported");
    return -1;
}



int
auth(char * type)
{
	if (auth_type)
		reply(534, "Authentication type already set to %s", auth_type);
	else

#ifdef GSSAPI
	if (strcmp(type, "GSSAPI") == 0) {
		
	    reply(334, "Using authentication type %s; ADAT must follow",
		  type);
	
	    attempting_auth_type = type;
	}
	else
#endif /* GSSAPI */

	/* Other auth types go here ... */
	    {
		reply(504, "Unknown authentication type: %s", type);
	    }
	return(0);
}

int
pbsz(char * size_string)
{
    unsigned int requested_pbuf_size;
    
    if (debug)
	syslog(LOG_DEBUG, "Received command PBSZ %s", size_string);
    
    if (!auth_type) {
	reply(503, "Must first perform authentication");
	return -1;
    }
    if (strlen(size_string) > 10 ||
	strlen(size_string) == 10 && strcmp(size_string, "4294967296") >= 0) {
	reply(501, "Bad value for PBSZ: %s", size_string);
	return -1;
    }
    requested_pbuf_size = (unsigned int) atol(size_string);
    
    if (actual_pbuf_size >= requested_pbuf_size) {
	if (debug)
	    syslog(LOG_DEBUG, "Actual pbuf size is already %u",
		   actual_pbuf_size);
	
	max_pbuf_size = requested_pbuf_size;
	    
	reply(200, "PBSZ=%u", actual_pbuf_size);
	return 0;
    }

    if (cleartext_buffer) {
	(void) free(cleartext_buffer);
	cleartext_buffer = NULL;
    }

    actual_pbuf_size = requested_pbuf_size;
    
    /* I attempt what is asked for first, and if that
       fails, I try dividing by 4 */
    while ((cleartext_buffer =
	    (unsigned char *)malloc(actual_pbuf_size)) == NULL) {

	if (actual_pbuf_size) {
	    lreply(200, "Trying %u", actual_pbuf_size >>= 2);
	} else {
	    perror_reply(421,
			 "Local resource failure: malloc");
	    dologout(1);
	}
    }
    max_pbuf_size = actual_pbuf_size;
    
    if (debug)
	syslog(LOG_DEBUG, "Replying with pbuf size == %u", max_pbuf_size);
    
    reply(200, "PBSZ=%u", max_pbuf_size);
    return 0;
}


int
auth_data(char * data)
{
    int radix_err;
    char decoded_data[LARGE_BUFSIZE];
    int length = sizeof(decoded_data);
    int adat_result = -1;	/* 0 == conintinue needed, 1 = success */


    if (debug)
	syslog(LOG_DEBUG, "ADAT message received (%d bytes)", strlen(data));
    
    if (auth_type) {
	reply(503, "Authentication already established");
	syslog(LOG_ERR, "ADAT received after authentication complete");
	return(-1);
    }
    if (!attempting_auth_type) {
	reply(503, "Must identify AUTH type before ADAT");
	syslog(LOG_ERR, "ADAT received before AUTH");
	return(-1);
    }
    radix_err = radix_encode(data, decoded_data, &length, 1);
    if (radix_err < 0) {
	reply(501, "Couldn't decode ADAT (%s)", radix_error(radix_err));
	syslog(LOG_ERR, "Couldn't decode ADAT (%s)", radix_error(radix_err));
	return(-1);
    }

#ifdef GSSAPI
    if (strcmp(attempting_auth_type, "GSSAPI") == 0) {
	adat_result = gssapi_handle_auth_data(decoded_data, length);
    }
#endif /* GSSAPI */
    /* Other auth types go here ... */
    else {
	syslog(LOG_ERR,
	       "ADAT received with no authentication mechanism in place");
	return(-1);
    }
    
    if (adat_result == 1) {
	/* Successful authentication */

	/* Record that authentication was successful */
	auth_type = attempting_auth_type;
	attempting_auth_type = NULL;

	if (debug)
	    syslog(LOG_DEBUG, "%s authentication successful.",
		   auth_type);
    }

    return (adat_result == -1) ? -1 : 0;
}

int
send_adat_reply(int code, unsigned char * data, int length)
{
    int radix_err;
    unsigned char encoded_data[LARGE_BUFSIZE];
    

    radix_err = radix_encode(data, encoded_data, &length, 0);

    if (radix_err < 0) {
	reply(535, "Couldn't encode ADAT reply (%s)",
	      radix_error(radix_err));
	syslog(LOG_ERR, "couldn't encode ADAT reply");
	return(-1);
    }
    reply(code, "ADAT=%s", encoded_data);
    return 0;
}



/*
 * Decode a securely transmitted message.
 *
 * message and smessage buffer may be the same.
 */
int
decode_secure_message(char *smessage, char *message, int message_size)
{
    char out[LARGE_BUFSIZE];
    char *data;		/* Start of encoded data */
    char *tmp;		/* Temporary pointer */
    int len;
    int radix_err;
    int msg_prot_level = PROT_C;
    

    if (auth_type == NULL) {
	/*
	 * Don't secure messages until authentication has completed.
	 */
	if (smessage != message)
	    strncpy(message, smessage, message_size);
	return 0;
    }

    /* Get and examine the first token to see if this is MIC, ENC, etc. */
    if ((data = strpbrk(smessage, " \r\n")))
	*data++ = '\0';
    upper(smessage);

    if (strcmp(smessage, "MIC") == 0) {
	msg_prot_level = PROT_S;
	
    } else if (strcmp(smessage, "ENC") == 0) {
	msg_prot_level = PROT_P;

    } else if (strcmp(smessage, "CONF") == 0) {
	msg_prot_level = PROT_E;
    }
    
    if (msg_prot_level == PROT_E) {
	reply(533, "All commands must be protected.");
	syslog(LOG_ERR, "Unprotected command received");
	*message = '\0';
	return(-1);
    }

    if (debug)
	syslog(LOG_DEBUG, "command %s received", smessage);

    /* Some paranoid sites may want to require that commands be encrypted. */
#ifdef PARANOID
    if (!PROT_ENCRYPTION(msg_prot_level)) {
	reply(533, "All commands must be encryption protected. Retry command under ENC.");
	*message = '\0';
	return(-1);
    }
#endif /* PARANOID */

#ifdef NOENCRYPTION
    if (PROT_ENCRYPTION(msg_prot_level)) {
	reply(533, "Encryption not supported. Retry command under MIC.");
	*message = '\0';
	return(-1);
    }
#endif /* NOENCRYPTION */

    if ((tmp = strpbrk(data, " \r\n")))
	*tmp = '\0';

    radix_err = radix_encode(data, out, &len, 1 /* == DECODE */);
    if (radix_err < 0) {
	reply(501, "Can't base 64 decode argument to %s command (%s)",
	      smessage, radix_error(radix_err));
	*message = '\0';
	return(-1);
    }
    if (debug)
	syslog(LOG_DEBUG, "Decoded %s buffer to %d bytes\n", 
	       smessage, len);

#ifdef GSSAPI
    if (strcmp(auth_type, "GSSAPI") == 0) {
	if (msg_prot_level == PROT_E) {
	    reply(537, "CONF protected commands not supported with GSSAPI.");
	    *message = '\0';
	    return(-1);
	}

	if (gssapi_unwrap_message(out, len, message, &message_size,
				  msg_prot_level) < 0) {
	    *message = '\0';
	    return -1;
	}
    }
#endif /* GSSAPI */
    /* Other auth types go here ... */

    return 0;
}



/*
 * Encode a message for secure transmission.
 *
 * Input and output buffer may be the same.
 */
int
encode_secure_message(char *message, char *smessage, int smessage_size)
{
    char unwrapped_buf[LARGE_BUFSIZE];	/* Message with \r\n */
    char wrapped_buf[LARGE_BUFSIZE];	/* Wrapped data */
    int wrapped_buf_size = sizeof(wrapped_buf);
    char encoded_buf[LARGE_BUFSIZE];	/* Wrapped and radix encoded data */
    int encoded_buf_size = sizeof(encoded_buf);
    char continue_char;		/* Continue character? */
    int radix_err;
    int msg_prot_level = protection_level;

    if (auth_type == NULL) {
	/*
	 * Don't secure messages until authentication has completed
	 */
	if (message != smessage)
	    strncpy(smessage, message, smessage_size);
	return 0;
    }

    /*
     * Don't send things in the clear, use safe.
     * NOTE that if we ever support CCC this will change.
     */
    if (msg_prot_level == PROT_C)
	msg_prot_level = PROT_S;

    if (debug)
	syslog(LOG_DEBUG,
	       "Encoding secure %s message",
	       protection_levelnames[msg_prot_level]);
    
    /*
     * First three characters of message are reply code, followed
     * by a possible continuation character (-). Grab the continuation
     * character before encoding so we can use it ourselves.
     */
    continue_char = message[3];

    if (debug)
	syslog(LOG_DEBUG, "Continuation character is \"%c\"",
	       continue_char);
    
    /*
     * Append \r\n to message. Yes, we could use encoded_buf here, but
     * let's just keep things orderly.
     */
    sprintf(unwrapped_buf, "%s\r\n", message);
    
    /*
     * Do authentication type specific protection and then radix encoding.
     * If we get an error, don't bother to try to send it to the client
     * since we probably can't for the same reason we got an error.
     */
#ifdef GSSAPI
    if (strcmp(auth_type, "GSSAPI") == 0) {

	/* Always wrap messages with integrity checking */
	if (gssapi_wrap_message(unwrapped_buf, wrapped_buf, &wrapped_buf_size,
				PROT_S) < 0) {
	    *smessage = '\0';
	    return -1;
	}

	if (debug)
	    syslog(LOG_DEBUG, "GSSAPI wrapped message is %d bytes",
		   wrapped_buf_size);
	
    }
#endif /* GSSAPI */

    encoded_buf_size = wrapped_buf_size;
    radix_err = radix_encode(wrapped_buf, encoded_buf, &encoded_buf_size,
			     0 /* Encode */);
    
    if (radix_err) {
	syslog(LOG_ERR, "Couldn't radix encode %s reply: %s",
	       protection_levelnames[msg_prot_level],
	       radix_error(radix_err));
	return -1;
    }

    if (debug)
	syslog(LOG_DEBUG, "Radix encoded message is %d bytes",
	       encoded_buf_size);
    
    /* Ok, now write our secure message with code and continuation character */
    if (snprintf(smessage, smessage_size, "%3d%c%s",
		 protection_level_reply_codes[msg_prot_level],
		 continue_char,
		 encoded_buf) < 0) {
	syslog(LOG_ERR,
	       "Output buffer size for %s message not large enough (is %d bytes)",
	       protection_levelnames[msg_prot_level],
	       smessage_size);
	
	*smessage = '\0';
	return -1;
    }

    if (debug) {
	char buf[20];
	
	strncpy(buf, smessage, sizeof(buf));
	buf[sizeof(buf) - 1] = '\0';

	syslog(LOG_DEBUG, "Secure encoded reply is %s...", buf);
    }
    
    return 0;
}

#endif /* FTP_SECURITY_EXTENSIONS */
