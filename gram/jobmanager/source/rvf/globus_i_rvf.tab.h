/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton interface for Bison's Yacc-like parsers in C

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     RVF_TOKEN_ERROR = 258,
     RVF_TOKEN_COMMENT = 259,
     RVF_TOKEN_NEWLINE = 260,
     RVF_TOKEN_QUOTE = 261,
     RVF_TOKEN_ATTRIBUTE = 262,
     RVF_TOKEN_DEFAULT = 263,
     RVF_TOKEN_DEFAULTWHEN = 264,
     RVF_TOKEN_DESCRIPTION = 265,
     RVF_TOKEN_PUBLISH = 266,
     RVF_TOKEN_REQUIREDWHEN = 267,
     RVF_TOKEN_VALIDWHEN = 268,
     RVF_TOKEN_VALUES = 269,
     RVF_TOKEN_TEXT = 270,
     RVF_TOKEN_ASPECT_DELIMITER = 271,
     RVF_TOKEN_SUBMIT = 272,
     RVF_TOKEN_RESTART = 273,
     RVF_TOKEN_STDIO_UPDATE = 274,
     RVF_TOKEN_BOOL = 275
   };
#endif
/* Tokens.  */
#define RVF_TOKEN_ERROR 258
#define RVF_TOKEN_COMMENT 259
#define RVF_TOKEN_NEWLINE 260
#define RVF_TOKEN_QUOTE 261
#define RVF_TOKEN_ATTRIBUTE 262
#define RVF_TOKEN_DEFAULT 263
#define RVF_TOKEN_DEFAULTWHEN 264
#define RVF_TOKEN_DESCRIPTION 265
#define RVF_TOKEN_PUBLISH 266
#define RVF_TOKEN_REQUIREDWHEN 267
#define RVF_TOKEN_VALIDWHEN 268
#define RVF_TOKEN_VALUES 269
#define RVF_TOKEN_TEXT 270
#define RVF_TOKEN_ASPECT_DELIMITER 271
#define RVF_TOKEN_SUBMIT 272
#define RVF_TOKEN_RESTART 273
#define RVF_TOKEN_STDIO_UPDATE 274
#define RVF_TOKEN_BOOL 275




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 70 "./rvf.y"
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
/* Line 1529 of yacc.c.  */
#line 104 "./globus_i_rvf.tab.h"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



#if ! defined YYLTYPE && ! defined YYLTYPE_IS_DECLARED
typedef struct YYLTYPE
{
  int first_line;
  int first_column;
  int last_line;
  int last_column;
} YYLTYPE;
# define yyltype YYLTYPE /* obsolescent; will be withdrawn */
# define YYLTYPE_IS_DECLARED 1
# define YYLTYPE_IS_TRIVIAL 1
#endif


