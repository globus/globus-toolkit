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
#include "globus_rvf_parser.h"
#include "globus_i_rvf.h"
#include "globus_i_rvf_parser.h"

%}

COMMENT_CHAR                            "#"
COMMENT                                 ({COMMENT_CHAR}[^\n]*)
NEWLINE                                 [\n]
WHITESPACE                              [ \t\r]+
WHITESPACE_OR_NEWLINE                   [ \n\t\r]+
ASPECT_DELIMITER                        [:]
QUOTE                                   ["]
BOOL                                    "true"|"false"
UNQUOTED_TEXT                           ([^"# \r\t\n][^\n#]*)
QUOTED_TEXT                             ([\\]["]|[^"])*
SUBMIT                                  "GLOBUS_GRAM_JOB_SUBMIT"
RESTART                                 "GLOBUS_GRAM_JOB_MANAGER_RESTART"
STDIO_UPDATE                            "GLOBUS_GRAM_JOB_MANAGER_STDIO_UPDATE"
WHEN_VALUE                              {SUBMIT}|{RESTART}|{STDIO_UPDATE}
WHEN_TRAIL                              (({WHITESPACE}({WHEN_VALUE}{WHITESPACE})*)|(({WHITESPACE}{WHEN_VALUE})*))?
QUOTED_WHEN_TRAIL                       ({WHITESPACE_OR_NEWLINE}({WHEN_VALUE}{WHITESPACE_OR_NEWLINE})*({WHEN_VALUE}?{WHITESPACE_OR_NEWLINE}?))?
QUOTED_BOOL                             ({WHITESPACE}|{NEWLINE})*{BOOL}({WHITESPACE}|{NEWLINE})*

%x DELIMITER VALUE QUOTED QUOTED_WHENVAL QUOTE_END VALUE_END

%option reentrant
%option prefix="globus_i_rvf_"
%option outfile="globus_i_rvf_scanner.c"
%option header-file="globus_i_rvf_scanner.h"
%option nodefault
%option yylineno
%option noyywrap
%option nounput
%option bison-bridge
%option bison-locations

%%

<INITIAL,VALUE_END>{COMMENT}/"\n" {
    return RVF_TOKEN_COMMENT;
}

<VALUE>{COMMENT} {
    BEGIN(VALUE_END);
    return RVF_TOKEN_COMMENT;
}

<INITIAL>(?i:Attribute) {
    BEGIN(DELIMITER);
    yylval->aspect_name = RVF_TOKEN_ATTRIBUTE;
    return RVF_TOKEN_ATTRIBUTE;
}
<INITIAL>(?i:Default) {
    BEGIN(DELIMITER);
    yylval->aspect_name = RVF_TOKEN_DEFAULT;
    return RVF_TOKEN_DEFAULT;
}
<INITIAL>(?i:DefaultWhen) {
    BEGIN(DELIMITER);
    yylval->aspect_name = RVF_TOKEN_DEFAULTWHEN;
    return RVF_TOKEN_DEFAULTWHEN;
}
<INITIAL>(?i:Description) {
    BEGIN(DELIMITER);
    yylval->aspect_name = RVF_TOKEN_DESCRIPTION;
    return RVF_TOKEN_DESCRIPTION;
}
<INITIAL>(?i:Publish) {
    BEGIN(DELIMITER);
    yylval->aspect_name = RVF_TOKEN_PUBLISH;
    return RVF_TOKEN_PUBLISH;
}
<INITIAL>(?i:RequiredWhen) {
    BEGIN(DELIMITER);
    yylval->aspect_name = RVF_TOKEN_REQUIREDWHEN;
    return RVF_TOKEN_REQUIREDWHEN;
}

<INITIAL>(?i:ValidWhen) {
    BEGIN(DELIMITER);
    yylval->aspect_name = RVF_TOKEN_VALIDWHEN;
    return RVF_TOKEN_VALIDWHEN;
}

<INITIAL>(?i:Values) {
    BEGIN(DELIMITER);
    yylval->aspect_name = RVF_TOKEN_VALUES;
    return RVF_TOKEN_VALUES;
}

<DELIMITER>{ASPECT_DELIMITER} {
    BEGIN(VALUE);
    return RVF_TOKEN_ASPECT_DELIMITER;
}

<*>{WHITESPACE} {
    ;
}

<INITIAL,VALUE_END,VALUE>{NEWLINE} {
    BEGIN(INITIAL);
    
    return RVF_TOKEN_NEWLINE;
}

<VALUE>{SUBMIT}/{WHEN_TRAIL} {
    return RVF_TOKEN_SUBMIT;
}

<VALUE>{RESTART}/{WHEN_TRAIL} {
    return RVF_TOKEN_RESTART;
}


<VALUE>{STDIO_UPDATE}/{WHEN_TRAIL} {
    return RVF_TOKEN_STDIO_UPDATE;
}

<VALUE>{BOOL} {
    yylval->bool_value = (strstr(yytext, "true") != NULL);

    return RVF_TOKEN_BOOL;
}

<VALUE>{QUOTE} {
    BEGIN(QUOTED);
    return RVF_TOKEN_QUOTE;
}

<VALUE>{UNQUOTED_TEXT} {
    BEGIN(VALUE_END);
    yylval->value.value_type = RVF_STRINGVAL;
    yylval->value.string_value = strdup(yytext);
    return RVF_TOKEN_TEXT;
}

<QUOTED>{QUOTED_BOOL} {
    yylval->bool_value = (strstr(yytext, "true") != NULL);
    BEGIN(QUOTE_END);
    return RVF_TOKEN_BOOL;
}
<QUOTED,QUOTED_WHENVAL>{SUBMIT}/{QUOTED_WHEN_TRAIL} {
    BEGIN(QUOTED_WHENVAL);

    return RVF_TOKEN_SUBMIT;
}

<QUOTED,QUOTED_WHENVAL>{STDIO_UPDATE}/{QUOTED_WHEN_TRAIL} {
    BEGIN(QUOTED_WHENVAL);

    return RVF_TOKEN_STDIO_UPDATE;
}

<QUOTED,QUOTED_WHENVAL>{RESTART}/{QUOTED_WHEN_TRAIL} {
    BEGIN(QUOTED_WHENVAL);

    return RVF_TOKEN_STDIO_UPDATE;
}

<QUOTED>{QUOTED_TEXT} {
    int len = strlen(yytext);
    int i,j;
    yylval->value.value_type = RVF_STRINGVAL;
    yylval->value.string_value = malloc(len+1);
    if (yylval->value.string_value == NULL)
    {
        return RVF_TOKEN_ERROR;
    }
    for (i = 0, j = 0; i < len; i++)
    {
        if (yytext[i] == '\\' && yytext[i+1] == '"')
        {
            i++;
            yylval->value.string_value[j++] = '"';
        }
        else
        {
            yylval->value.string_value[j++] = yytext[i];
        }
    }
    yylval->value.string_value[j] = '\0';

    BEGIN(QUOTE_END);
    return RVF_TOKEN_TEXT;
}

<QUOTED,QUOTE_END,QUOTED_WHENVAL>{QUOTE} {
    BEGIN(VALUE_END);
    return RVF_TOKEN_QUOTE;
}

<QUOTED_WHENVAL>{NEWLINE} {
    ;
}

<*>.|{NEWLINE} { return RVF_TOKEN_ERROR; }
