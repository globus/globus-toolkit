%{
/*
 * Copyright 1999-2012 University of Chicago
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

#include "globus_common.h"
#include "globus_gram_protocol_constants.h"
#include "globus_rsl_assist.h"
#include "globus_rvf_parser.h"
#include "globus_i_rvf.h"
#include "globus_i_rvf_parser.h"
#include "globus_i_rvf_scanner.h"

int
globus_i_rvf_error(YYLTYPE * lloc, globus_list_t **output, void * scanner, char * str);

static const globus_rvf_record_t empty_record = {
    NULL,
    NULL,
    NULL,
    NULL,
    -1,
    -1,
    -1,
    -1
};

static const globus_i_rvf_aspect_t empty_aspect = { 0 };
static int globus_l_rvf_debug = 0;

static
void
globus_l_rvf_validation_record_destroy(
    globus_rvf_record_t *               record);

static
void
globus_l_rvf_records_destroy(globus_list_t *records); 

static
int
globus_l_rvf_attr_match(
    void *                              datum,
    void *                              args);
%}

%pure-parser
%error-verbose
%locations
%parse-param { globus_list_t ** output }
%parse-param { void * scanner }
%lex-param { void * scanner }
%debug 
%file-prefix="globus_i_rvf_"
%name-prefix="globus_i_rvf_"
%output="globus_i_rvf_parser.c"


%start validation_file

%union
{
    int aspect_name;
    globus_bool_t bool_value;
    globus_rvf_record_t record;
    globus_i_rvf_aspect_t aspect;
    struct
    {
        enum {RVF_STRINGVAL, RVF_WHENVAL, RVF_BOOLVAL, RVF_EMPTYVAL } value_type;
        char *string_value;
        int when_value;
        globus_bool_t bool_value;
    } value;
    globus_list_t * validation_file;
}

%token RVF_TOKEN_ERROR RVF_TOKEN_COMMENT RVF_TOKEN_NEWLINE RVF_TOKEN_QUOTE
/* Separate records by having a newline between them */
/* String value for some RVF aspects */
/* Aspect Name Tokens */
%token <aspect_name> RVF_TOKEN_ATTRIBUTE 
%token <aspect_name> RVF_TOKEN_DEFAULT
%token <aspect_name> RVF_TOKEN_DEFAULTWHEN
%token <aspect_name> RVF_TOKEN_DESCRIPTION
%token <aspect_name> RVF_TOKEN_PUBLISH
%token <aspect_name> RVF_TOKEN_REQUIREDWHEN
%token <aspect_name> RVF_TOKEN_VALIDWHEN
%token <aspect_name> RVF_TOKEN_VALUES
%token <value> RVF_TOKEN_TEXT

/* Delimiter between aspect name and value */
%token RVF_TOKEN_ASPECT_DELIMITER
/* When values */
%token RVF_TOKEN_SUBMIT
%token RVF_TOKEN_RESTART
%token RVF_TOKEN_STDIO_UPDATE
%token <bool_value> RVF_TOKEN_BOOL

%type <validation_file> records
%type <record> record
%type <record> aspect_list
%type <aspect> aspect
%type <aspect_name> aspect_name
%type <value> aspect_value quoted_value unquoted_value when_value when_value_list

%destructor {
    if ($$.value_type == RVF_STRINGVAL && $$.string_value != NULL)
    {
        free($$.string_value);
    }
} RVF_TOKEN_TEXT aspect_value quoted_value unquoted_value when_value when_value_list

%destructor { globus_l_rvf_validation_record_destroy(&$$); } record aspect_list
%destructor { globus_l_rvf_records_destroy($$); } records

%%

validation_file:
    optional_record_separator records optional_record_separator {
        while (!globus_list_empty($2))
        {
            globus_list_t * node;
            globus_rvf_record_t *record;

            record = globus_list_remove(&$2, $2);

            if (record->attribute == NULL)
            {
                globus_l_rvf_validation_record_destroy(record);
                free(record);
                continue;
            }
            node = globus_list_search_pred(
                *output,
                globus_l_rvf_attr_match,
                record->attribute);
            if (node)
            {
                /*
                 * Validation record already exists; override changed
                 * values.
                 */
                globus_rvf_record_t * old_record;

                old_record = globus_list_first(node);

                if(record->description)
                {
                    if(old_record->description)
                    {
                        free(old_record->description);
                    }
                    old_record->description = record->description;
                    record->description = NULL;
                }
                if(record->default_value)
                {
                    if(old_record->default_value)
                    {
                        free(old_record->default_value);
                    }
                    old_record->default_value = record->default_value;
                    record->default_value = NULL;
                }
                if(record->enumerated_values)
                {
                    if(old_record->enumerated_values)
                    {
                        free(old_record->enumerated_values);
                    }
                    old_record->enumerated_values = record->enumerated_values;
                    record->enumerated_values = NULL;
                }
                if(record->required_when != -1)
                {
                    old_record->required_when = record->required_when;
                }
                if(record->default_when != -1)
                {
                    old_record->default_when = record->default_when;
                }
                if(record->valid_when != -1)
                {
                    old_record->valid_when = record->valid_when;
                }
                if(record->publishable != -1)
                {
                    old_record->publishable = record->publishable;
                }
                free(record);
                record = GLOBUS_NULL;
            }
            else
            {
                globus_list_insert(output, record);
            }
        }
    }
    | optional_record_separator {
    }
    | error {
        return 1;
    }

records:
      records record_separator record {
        globus_rvf_record_t *           record;

        record = malloc(sizeof(globus_rvf_record_t));
        if (record == NULL)
        {
            YYERROR;
        }
        *record = $3;

        $$ = $1;
        globus_list_insert(&$$, record);
      }
    | record {
        globus_rvf_record_t *           record;

        $$ = NULL;

        record = malloc(sizeof(globus_rvf_record_t));
        if (record == NULL)
        {
            YYERROR;
        }
        *record = $1;

        globus_list_insert(&$$, record);
    }


record:
      aspect_list {
        if ($1.attribute != NULL)
        {
            globus_rsl_assist_string_canonicalize($$.attribute);
        }
        $$ = $1;
      }

optional_record_separator:
    /* empty */
    | record_separator 

record_separator:
    RVF_TOKEN_NEWLINE record_separator
    | RVF_TOKEN_NEWLINE

comment:
      RVF_TOKEN_COMMENT RVF_TOKEN_NEWLINE

aspect_list:
      aspect aspect_list {
        $$ = $2;

        switch ($1.aspect)
        {
            case RVF_TOKEN_ATTRIBUTE:
                $$.attribute = $1.string_value;
                break;
            case RVF_TOKEN_DEFAULT:
                $$.default_value = $1.string_value;
                break;
            case RVF_TOKEN_DEFAULTWHEN:
                $$.default_when = $1.when_value;
                break;
            case RVF_TOKEN_DESCRIPTION:
                $$.description = $1.string_value;
                break;
            case RVF_TOKEN_PUBLISH:
                $$.publishable = $1.bool_value;
                break;
            case RVF_TOKEN_REQUIREDWHEN:
                $$.required_when = $1.when_value;
                break;
            case RVF_TOKEN_VALIDWHEN:
                $$.valid_when = $1.when_value;
                break;
            case RVF_TOKEN_VALUES:
                $$.enumerated_values = $1.string_value;
                break;
        }
    }
    | comment aspect_list {
        $$ = $2;
    }
    | comment {
        $$ = empty_record;
    }
    | aspect {
        $$ = empty_record;

        switch ($1.aspect)
        {
            case RVF_TOKEN_ATTRIBUTE:
                $$.attribute = $1.string_value;
                break;
            case RVF_TOKEN_DEFAULT:
                $$.default_value = $1.string_value;
                break;
            case RVF_TOKEN_DEFAULTWHEN:
                $$.default_when = $1.when_value;
                break;
            case RVF_TOKEN_DESCRIPTION:
                $$.description = $1.string_value;
                break;
            case RVF_TOKEN_PUBLISH:
                $$.publishable = $1.bool_value;
                break;
            case RVF_TOKEN_REQUIREDWHEN:
                $$.required_when = $1.when_value;
                break;
            case RVF_TOKEN_VALIDWHEN:
                $$.valid_when = $1.when_value;
                break;
        }
    }

aspect:
      aspect_name aspect_delimiter aspect_value end_of_aspect {
          $$ = empty_aspect;

          switch ($1)
          {
              case RVF_TOKEN_ATTRIBUTE:
              case RVF_TOKEN_DEFAULT:
              case RVF_TOKEN_DESCRIPTION:
              case RVF_TOKEN_VALUES:
                if ($3.value_type == RVF_STRINGVAL)
                {
                    $$.aspect = $1;
                    $$.string_value = $3.string_value;
                }
                else if ($3.value_type == RVF_EMPTYVAL)
                {
                    $$.aspect = $1;
                    $$.string_value = NULL;
                }
                else
                {
                    YYERROR;
                }
                break;
              case RVF_TOKEN_DEFAULTWHEN:
              case RVF_TOKEN_VALIDWHEN:
              case RVF_TOKEN_REQUIREDWHEN:
                if ($3.value_type == RVF_WHENVAL)
                {
                    $$.aspect = $1;
                    $$.when_value = $3.when_value;
                }
                else if ($3.value_type == RVF_EMPTYVAL)
                {
                    $$.aspect = $1;
                    $$.when_value = 0;
                }
                else
                {
                    if ($3.value_type == RVF_STRINGVAL &&
                        $3.string_value != NULL)
                    {
                        free($3.string_value);
                        $3.string_value = NULL;
                    }
                    YYERROR;
                }

                break;
              case RVF_TOKEN_PUBLISH:
                if ($3.value_type == RVF_BOOLVAL)
                {
                    $$.aspect = $1;
                    $$.bool_value = $3.bool_value;
                }
                else
                {
                    if ($3.value_type == RVF_STRINGVAL &&
                        $3.string_value != NULL)
                    {
                        free($3.string_value);
                        $3.string_value = NULL;
                    }
                    YYERROR;
                }
                break;
          }
      }


aspect_name:
      RVF_TOKEN_ATTRIBUTE | RVF_TOKEN_DEFAULT | RVF_TOKEN_DESCRIPTION | RVF_TOKEN_VALUES
    | RVF_TOKEN_DEFAULTWHEN | RVF_TOKEN_VALIDWHEN | RVF_TOKEN_REQUIREDWHEN
    | RVF_TOKEN_PUBLISH {
        $$ = $1;
    }

aspect_delimiter:
    RVF_TOKEN_ASPECT_DELIMITER

aspect_value:
      RVF_TOKEN_QUOTE quoted_value RVF_TOKEN_QUOTE {
        $$ = $2;
    }
    | unquoted_value {
        $$ = $1;
    }
    | /* empty */ {
        $$.value_type = RVF_EMPTYVAL;
    }

quoted_value:
    when_value_list {
        $$.value_type = RVF_WHENVAL;
        $$.when_value = $1.when_value;
    }
    | RVF_TOKEN_BOOL {
        $$.value_type = RVF_BOOLVAL;
        $$.bool_value = $1;
    }
    | RVF_TOKEN_TEXT {
        $$.value_type = RVF_STRINGVAL;
        $$.string_value = $1.string_value;
    }
    | /* empty */ {
        $$.value_type = RVF_EMPTYVAL;
    }

unquoted_value:
    when_value_list {
        $$.value_type = RVF_WHENVAL;
        $$.when_value = $1.when_value;
    }
    | RVF_TOKEN_BOOL {
        $$.value_type = RVF_BOOLVAL;
        $$.bool_value = $1;
    }
    | RVF_TOKEN_TEXT {
        $$.value_type = RVF_STRINGVAL;
        $$.string_value = $1.string_value;
    }

when_value_list:
      when_value when_value_list {
        $$.value_type = RVF_WHENVAL;
        $$.when_value = $1.when_value | $2.when_value;
    }
    | when_value {
        $$ = $1;
    }

when_value:
      RVF_TOKEN_SUBMIT {
        $$.value_type = RVF_WHENVAL;
        $$.when_value = 1;
      }
    | RVF_TOKEN_RESTART {
        $$.value_type = RVF_WHENVAL;
        $$.when_value = 2;
      }
    | RVF_TOKEN_STDIO_UPDATE {
        $$.value_type = RVF_WHENVAL;
        $$.when_value = 4;
      }

end_of_aspect:
    RVF_TOKEN_NEWLINE 
    | RVF_TOKEN_COMMENT RVF_TOKEN_NEWLINE  {
    }
%%

typedef struct globus_rvf_extra_s
{
    char * buf;
    char * path;
    char * err;
} globus_rvf_extra_t;

int
globus_i_rvf_error(YYLTYPE * lloc, globus_list_t **output, void * scanner, char * str)
{
    globus_rvf_extra_t * extra;

    extra = globus_i_rvf_get_extra(scanner);

    extra->err = globus_common_create_string(
            "unable to parse %s at line %d (token starting with <<<%.15s>>>) %s",
            extra->path ? extra->path : "string",
            globus_i_rvf_get_lineno(scanner),
            globus_i_rvf_get_text(scanner),
            str);

    return 0;
}

static
int
globus_l_rvf_attr_match(
    void *                              datum,
    void *                              args)
{
    globus_rvf_record_t *               tmp = datum;

    return (strcmp(tmp->attribute, args) == 0);
}
/* globus_l_rvf_attr_match() */


static
void
globus_l_rvf_validation_record_destroy(
    globus_rvf_record_t *               record)
{
    if (record->attribute)
    {
        free(record->attribute);
    }
    if (record->description)
    {
        free(record->description);
    }
    if (record->default_value)
    {
        free(record->default_value);
    }
    if (record->enumerated_values)
    {
        free(record->enumerated_values);
    }
}


static
void
globus_l_rvf_records_destroy(globus_list_t *records)
{
    globus_list_t * l = records;
    while (!globus_list_empty(l))
    {
        globus_rvf_record_t *           record;

        record = globus_list_remove(&l, l);

        globus_l_rvf_validation_record_destroy(record);
    }
}
/* globus_l_rvf_records_destroy() */

/* Public API of the parser: pass in a path, return a list of
 * rsl validation records. if an error occurs, returns a non-zero value
 * and sets errstr
 */
int
globus_rvf_parse_file(
    char * path,
    globus_list_t **out,
    char ** errstr)
{
    FILE * f = fopen(path, "r");
    void * scanner;
    int rc;
    globus_rvf_extra_t extra;

    if (f == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_VALIDATION_FILE;
        *errstr = globus_common_create_string(
            "the job manager could not open the RSL attribute validation file \"%s\"", path ? path : "NULL");
        return rc;
    }

    extra.buf = NULL;
    extra.path = path;
    extra.err = NULL;

    *errstr = NULL;

    globus_i_rvf_lex_init(&scanner);
    globus_i_rvf_set_extra(&extra, scanner);

    globus_i_rvf_set_debug(globus_l_rvf_debug, scanner);
    

    globus_i_rvf_set_in(f, scanner);

    rc = globus_i_rvf_parse(out, scanner);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_READING_VALIDATION_FILE;

        *errstr = extra.err;
    }
    globus_i_rvf_lex_destroy(scanner);
    fclose(f);

    return rc;
}
/* globus_rvf_parse_file() */

/* Public API of the parser: pass in a path, return a list of
 * rsl validation records. if an error occurs, returns a non-zero value
 * and sets errstr
 */
int
globus_rvf_parse_string(
    char * buffer,
    globus_list_t **out,
    char ** errstr)
{
    void * scanner;
    int rc;
    globus_rvf_extra_t extra;
    YY_BUFFER_STATE lexbuf;

    extra.buf = buffer;
    extra.path = NULL;
    extra.err = NULL;

    *errstr = NULL;

    globus_i_rvf_lex_init(&scanner);
    globus_i_rvf_set_extra(&extra, scanner);

    globus_i_rvf_set_debug(globus_l_rvf_debug, scanner);
    
    lexbuf = globus_i_rvf__scan_string(buffer, scanner);

    rc = globus_i_rvf_parse(out, scanner);
    if (rc != GLOBUS_SUCCESS)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_READING_VALIDATION_FILE;

        *errstr = extra.err;
    }
    globus_i_rvf__delete_buffer(lexbuf, scanner);
    globus_i_rvf_lex_destroy(scanner);

    return rc;
}
/* globus_rvf_parse_string() */
