
#include "voms_utils.h"

#define DEFAULT_CAPACITY (10)
#define LINE_BUFF_SIZE   (1024)
#define TOKEN_SIZE       (512)

#define ACSEQ_OID        "1.3.6.1.4.1.8005.100.100.5"


/*
 * Internal Structures
 */
/* 
 * array of string
 */
typedef struct {
    size_t size;
    size_t capacity;
    char ** elements;
} voms_string_array;

/*
 * Internal Functions 
 */
static voms_string_array *
voms_string_array_new()
{
    voms_string_array *array = NULL;
    array = malloc(sizeof(voms_string_array));
    if (array == NULL) {
        return NULL;
    }

    array->elements = malloc(sizeof(char *) * DEFAULT_CAPACITY);
    if (array->elements == NULL) {
        free(array);
        return NULL;
    }
    array->capacity = DEFAULT_CAPACITY;
    array->size = 0;

    return array;
}

static void
voms_string_array_free(voms_string_array *array)
{
    int i;
    if (array == NULL) return;

    for (i = 0; i < array->size; i++) {
        free(array->elements[i]);
    }
    free(array->elements);
    free(array);
}

static int
voms_string_array_ensure_capacity(voms_string_array *array,
                                  size_t expect_capacity)
{
    size_t new_capacity;
    size_t current_capacity;
    char **new_elements = NULL;

    assert(array != NULL);

    current_capacity = array->capacity;
    if (expect_capacity < current_capacity) {
        return 0;
    }

    new_capacity = sizeof(char *) * (current_capacity + DEFAULT_CAPACITY);
    new_elements = realloc(array->elements, new_capacity);
    if (new_elements == NULL) {
        return -1;
    }
    if (new_elements != array->elements) {
        array->elements = new_elements;
    }
    array->capacity = new_capacity;

    return 0;
}

static int
voms_string_array_add(voms_string_array *array, const char * str)
{

    char * element = NULL;

    assert(array != NULL);
    assert(str != NULL);

    if (voms_string_array_ensure_capacity(array, array->size + 1) < 0) {
        return -1;
    }

    element = strdup(str);
    if (element == NULL) {
        return -1;
    }
    array->elements[array->size++] = element;

    return 0;
}

static char * 
voms_string_array_join(voms_string_array *array, const char *delim)
{
    int i = 0;
    char * result = NULL;
    size_t result_size = 0;
    size_t delim_size = 0;

    assert(array != NULL);
    assert(delim != NULL);

    if (array->size == 0) {
        return NULL;
    } else if (array->size == 1) {
        return strdup(array->elements[0]);
    }

    delim_size = strlen(delim);
    result_size = strlen(array->elements[0]);
    for (i = 1; i < array->size; i++) {
        result_size += delim_size;
        result_size += strlen(array->elements[i]);
    }
    result_size += 1;

    result = malloc(sizeof(char) * result_size);
    if (result == NULL) {
        return NULL;
    }

    strcpy(result, array->elements[0]);
    for (i = 1; i < array->size; i++) {
        strcat(result, delim);
        strcat(result, array->elements[i]);
    }
    return result;
}

static char **
voms_string_array_to_myproxy_array(const voms_string_array *array)
{
    char **result = NULL;
    int i = 0;

    result = malloc(sizeof(char *) * (array->size + 1));
    if (result == NULL) {
        return NULL;
    }

    for (i = 0; i < array->size; i++) {
        result[i] = strdup(array->elements[i]);
        if (result[i] == NULL) {
            goto cleanup;
        }
    }
    result[array->size] = NULL;

    return result;

  cleanup:
    for ( ; i >= 0; i--) {
        if (result[i] != NULL) {
            free(result[i]);
        }
    }
    free(result);
    return NULL;
}

static int
is_comment_line(const char *line)
{
    if ((line == NULL) || (*line == '\0')) { return 1; }
    while ( *line ) {
        if ( ! isspace(*line) ) {
            if (*line == '#') {
                return 1;
            } else {
                break;
            }
        }
        line++;
    }
    return 0;
}

static int
is_empty_line(const char *line)
{
    if (line == NULL) { return 1; }
    while ( *line ) {
        if ( ! isspace(*line) ) {
            return 0;
        }
        line++;
    }
    return 1;
}

static char *
parse_vomses(const char *line) 
{
    int i = 0;
    int count = 0;
    int is_quoted = 0;
    char token[TOKEN_SIZE];
    voms_string_array *array = NULL;
    char * result = NULL;

    assert(line != NULL);

    if ((array = voms_string_array_new()) == NULL) {
        goto error;
    }

    for (i = 0; line[i]; i++) {
        if ((line[i] == '"') && (! is_quoted)) {
            is_quoted = 1;

            if (TOKEN_SIZE <= (count+2)) {
                goto error;
            }
            token[count++] = line[i];
            token[count] = '\0';

            continue;
        }
        if (is_quoted) {
            if (line[i] == '"') {
                is_quoted = 0;

                if (TOKEN_SIZE <= (count+2)) {
                    goto error;
                }
                token[count++] = line[i];
                token[count] = '\0';

                if (voms_string_array_add(array, token) < 0) {
                    goto error;
                }
                count = 0;

                continue;
            }

            if (TOKEN_SIZE <= (count+2)) {
                goto error;
            }
            token[count++] = line[i];
            token[count] = '\0';
        }
    }

    if ((array->size == 5) || (array->size == 6)) {
        result = voms_string_array_join(array, " ");
    }

  error:
    if (array != NULL) {
        voms_string_array_free(array);
    }

    return result;
}

static char * 
create_filepath(const char *base, const char *name)
{
    size_t base_len;
    size_t name_len;
    size_t buff_len;
    char * buffer;
    int delimited = 0;
    
    assert(base != NULL);
    assert(name != NULL);

    base_len = strlen(base);
    if (base_len == 0) {
        return strdup(name);
    }

    name_len = strlen(name);
    if ((base_len > 0) && (base[base_len-1] == '/')) {
        delimited = 1;
        buff_len = sizeof(char) * (base_len + name_len + 1);
    } else {
        buff_len = sizeof(char) * (base_len + name_len + 2);
    }
    buffer = malloc(buff_len);
    if (buffer == NULL) {
        return NULL;
    }

    if (delimited) {
        snprintf(buffer, buff_len, "%s%s", base, name);
    } else {
        snprintf(buffer, buff_len, "%s%s%s", base, "/", name);
    }
    return buffer;
}

static char **
load_vomses_file(const char *filename)
{
    FILE *fp = NULL;
    char buffer[LINE_BUFF_SIZE];
    voms_string_array *array = NULL;
    char **result = NULL;

    assert (filename != NULL);

    if ((array = voms_string_array_new()) == NULL) {
        goto error;
    }
    if ((fp = fopen(filename, "r")) == NULL ) {
        goto error;
    }

    while (fgets(buffer, LINE_BUFF_SIZE, fp) != NULL) {
        char *vomses = NULL;
        if (is_comment_line(buffer) || is_empty_line(buffer)) {
            continue;
        }
        if ((vomses = parse_vomses(buffer)) == NULL) {
            continue;
        }
        voms_string_array_add(array, vomses);
        free(vomses);
    }

    result = voms_string_array_to_myproxy_array(array);

 error:
    if (fp != NULL) {
        fclose(fp);
    }
    if (array != NULL) {
        voms_string_array_free(array);
    }

    return result;
}

static int
load_vomses(const char *path, voms_string_array *array)
{
    struct stat file_stat;

    assert(path != NULL);

    if (stat(path, &file_stat) < 0) {
        return -1;
    }

    if (S_ISREG(file_stat.st_mode)) {
        int i;
        char **vomses = NULL;
        vomses = load_vomses_file(path);
        if (vomses == NULL) {
            return -1;
        }
        for (i = 0; vomses[i] != NULL; i++) {
            voms_string_array_add(array, vomses[i]);
            free(vomses[i]);
        }
        free(vomses);
    } else if (S_ISDIR(file_stat.st_mode)) {
        DIR *dp = opendir(path);
        if (dp != NULL) {
            struct dirent *entry;
            while ((entry = readdir(dp)) != NULL) {
                char *name = entry->d_name;
                if (name && (strcmp(name, ".") != 0) 
                         && (strcmp(name, "..") != 0)) {
                    char * filepath = create_filepath(path, name);
                    if (filepath != NULL) {
                        load_vomses(filepath, array);
                        free(filepath);
                        filepath = NULL;
                    }
                }
            }
            closedir(dp);
        }
    }
    return 0;
}

static X509 *
load_X509_from_file(const char *filepath)
{
    FILE *certfile = NULL;
    X509 *cert = NULL;

    certfile = fopen(filepath, "r");
    if (certfile == NULL) {
        return NULL;
    }
    cert = PEM_read_X509(certfile, NULL, NULL, NULL);
    fclose(certfile);

    return cert;
}


/*
 *  External Function
 */

char **
get_vomses(const char *path)
{
    voms_string_array *array = NULL;
    char **result = NULL;

    assert(path != NULL);

    array = voms_string_array_new();
    if (array == NULL) {
        return NULL;
    }

    load_vomses(path, array);
    if (array->size > 0) {
        result = voms_string_array_to_myproxy_array(array);
    }

    if (array != NULL) {
        voms_string_array_free(array);
    }

    return result;
}


int
has_voms_extension(const char *certfilepath)
{
    ASN1_OBJECT *acseq_oid = NULL;
    X509 *cert = NULL;
    int position = -1;
    int result = -1;

    assert (certfilepath != NULL);

    acseq_oid = OBJ_txt2obj(ACSEQ_OID, 1);
    if (acseq_oid == NULL) {
        return result;
    }

    cert = load_X509_from_file(certfilepath);
    if (cert == NULL) {
        goto error;
    }

    position = X509_get_ext_by_OBJ(cert, acseq_oid, -1);
    if (position >= 0) {
        result = 1;
    } else {
        result = 0;
    }

    if (cert != NULL) {
        X509_free(cert);
    }

  error:

    if (acseq_oid != NULL) {
        ASN1_OBJECT_free(acseq_oid);
    }

    return result;
}

