#ifndef GLOBUS_UUID_INCLUDE
#define GLOBUS_UUID_INCLUDE

#define GLOBUS_UUID_TEXTLEN 36

#define GLOBUS_UUID_VERSION(uuid) ((uuid)->binary.bytes[6] >> 4)
#define GLOBUS_UUID_VERSION_TIME 1
#define GLOBUS_UUID_VERSION_DCE 2
#define GLOBUS_UUID_VERSION_NAME 3
#define GLOBUS_UUID_VERSION_RANDOM 4

/* all multibyte fields in network byte order */
typedef struct
{
    uint32_t                    time_low;
    uint16_t                    time_mid;
    uint16_t                    time_hi_and_version;
    uint8_t                     clock_seq_hi_and_reserved;
    uint8_t                     clock_seq_low;
    uint8_t                     node[6];
} globus_uuid_fields_t;

typedef struct
{
    union
    {
        uint8_t                         bytes[16];
        globus_uuid_fields_t            fields;
    } binary;
    
    char                                text[GLOBUS_UUID_TEXTLEN + 1];
} globus_uuid_t;

int
globus_uuid_create(
    globus_uuid_t *                     uuid);

/* str must be at least GLOBUS_UUID_TEXTLEN long and be in the following format
 * 1b4e28ba-2fa1-11d2-883f-b9a761bde3fb
 */
int
globus_uuid_import(
    globus_uuid_t *                     uuid,
    const char *                        str);
    
#endif
