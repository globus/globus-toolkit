/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton implementation for Bison's Yacc-like parsers in C

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

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "2.3"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 1

/* Using locations.  */
#define YYLSP_NEEDED 1

/* Substitute the variable and function names.  */
#define yyparse globus_i_rvf_parse
#define yylex   globus_i_rvf_lex
#define yyerror globus_i_rvf_error
#define yylval  globus_i_rvf_lval
#define yychar  globus_i_rvf_char
#define yydebug globus_i_rvf_debug
#define yynerrs globus_i_rvf_nerrs
#define yylloc globus_i_rvf_lloc

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




/* Copy the first part of user declarations.  */
#line 1 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"

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


/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 1
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 1
#endif

/* Enabling the token table.  */
#ifndef YYTOKEN_TABLE
# define YYTOKEN_TABLE 0
#endif

#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 74 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
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
/* Line 193 of yacc.c.  */
#line 217 "globus_i_rvf_parser.c"
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


/* Copy the second part of user declarations.  */


/* Line 216 of yacc.c.  */
#line 242 "globus_i_rvf_parser.c"

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#elif (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
typedef signed char yytype_int8;
#else
typedef short int yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(msgid) dgettext ("bison-runtime", msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(msgid) msgid
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(e) ((void) (e))
#else
# define YYUSE(e) /* empty */
#endif

/* Identity function, used to suppress warnings about constant conditions.  */
#ifndef lint
# define YYID(n) (n)
#else
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static int
YYID (int i)
#else
static int
YYID (i)
    int i;
#endif
{
  return i;
}
#endif

#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#     ifndef _STDLIB_H
#      define _STDLIB_H 1
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (YYID (0))
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined _STDLIB_H \
       && ! ((defined YYMALLOC || defined malloc) \
	     && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef _STDLIB_H
#    define _STDLIB_H 1
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
	 || (defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL \
	     && defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss;
  YYSTYPE yyvs;
    YYLTYPE yyls;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE) + sizeof (YYLTYPE)) \
      + 2 * YYSTACK_GAP_MAXIMUM)

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  YYSIZE_T yyi;				\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (YYID (0))
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack)					\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack, Stack, yysize);				\
	Stack = &yyptr->Stack;						\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (YYID (0))

#endif

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  7
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   51

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  21
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  17
/* YYNRULES -- Number of rules.  */
#define YYNRULES  43
/* YYNRULES -- Number of states.  */
#define YYNSTATES  51

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   275

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint8 yyprhs[] =
{
       0,     0,     3,     7,     9,    11,    15,    17,    19,    20,
      22,    25,    27,    30,    33,    36,    38,    40,    45,    47,
      49,    51,    53,    55,    57,    59,    61,    63,    67,    69,
      70,    72,    74,    76,    77,    79,    81,    83,    86,    88,
      90,    92,    94,    96
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int8 yyrhs[] =
{
      22,     0,    -1,    25,    23,    25,    -1,    25,    -1,     1,
      -1,    23,    26,    24,    -1,    24,    -1,    28,    -1,    -1,
      26,    -1,     5,    26,    -1,     5,    -1,     4,     5,    -1,
      29,    28,    -1,    27,    28,    -1,    27,    -1,    29,    -1,
      30,    31,    32,    37,    -1,     7,    -1,     8,    -1,    10,
      -1,    14,    -1,     9,    -1,    13,    -1,    12,    -1,    11,
      -1,    16,    -1,     6,    33,     6,    -1,    34,    -1,    -1,
      35,    -1,    20,    -1,    15,    -1,    -1,    35,    -1,    20,
      -1,    15,    -1,    36,    35,    -1,    36,    -1,    17,    -1,
      18,    -1,    19,    -1,     5,    -1,     4,     5,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   131,   131,   211,   213,   218,   227,   240,   248,   250,
     253,   254,   257,   260,   291,   294,   297,   327,   398,   398,
     398,   398,   399,   399,   399,   400,   405,   408,   411,   414,
     419,   423,   427,   431,   436,   440,   444,   450,   454,   459,
     463,   467,   473,   474
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || YYTOKEN_TABLE
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "RVF_TOKEN_ERROR", "RVF_TOKEN_COMMENT",
  "RVF_TOKEN_NEWLINE", "RVF_TOKEN_QUOTE", "RVF_TOKEN_ATTRIBUTE",
  "RVF_TOKEN_DEFAULT", "RVF_TOKEN_DEFAULTWHEN", "RVF_TOKEN_DESCRIPTION",
  "RVF_TOKEN_PUBLISH", "RVF_TOKEN_REQUIREDWHEN", "RVF_TOKEN_VALIDWHEN",
  "RVF_TOKEN_VALUES", "RVF_TOKEN_TEXT", "RVF_TOKEN_ASPECT_DELIMITER",
  "RVF_TOKEN_SUBMIT", "RVF_TOKEN_RESTART", "RVF_TOKEN_STDIO_UPDATE",
  "RVF_TOKEN_BOOL", "$accept", "validation_file", "records", "record",
  "optional_record_separator", "record_separator", "comment",
  "aspect_list", "aspect", "aspect_name", "aspect_delimiter",
  "aspect_value", "quoted_value", "unquoted_value", "when_value_list",
  "when_value", "end_of_aspect", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    21,    22,    22,    22,    23,    23,    24,    25,    25,
      26,    26,    27,    28,    28,    28,    28,    29,    30,    30,
      30,    30,    30,    30,    30,    30,    31,    32,    32,    32,
      33,    33,    33,    33,    34,    34,    34,    35,    35,    36,
      36,    36,    37,    37
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     3,     1,     1,     3,     1,     1,     0,     1,
       2,     1,     2,     2,     2,     1,     1,     4,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     3,     1,     0,
       1,     1,     1,     0,     1,     1,     1,     2,     1,     1,
       1,     1,     1,     2
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       0,     4,    11,     0,     3,     9,    10,     1,     0,    18,
      19,    22,    20,    25,    24,    23,    21,     8,     6,    15,
       7,    16,     0,    12,     2,     9,    14,    13,    26,    29,
       5,    33,    36,    39,    40,    41,    35,     0,    28,    34,
      38,    32,    31,     0,    30,     0,    42,    17,    37,    27,
      43
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int8 yydefgoto[] =
{
      -1,     3,    17,    18,     4,     5,    19,    20,    21,    22,
      29,    37,    43,    38,    39,    40,    47
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -30
static const yytype_int8 yypact[] =
{
       9,   -30,     7,    28,    35,   -30,   -30,   -30,    25,   -30,
     -30,   -30,   -30,   -30,   -30,   -30,   -30,     7,   -30,    35,
     -30,    35,    16,   -30,   -30,    35,   -30,   -30,   -30,    18,
     -30,   -14,   -30,   -30,   -30,   -30,   -30,     3,   -30,   -30,
       8,   -30,   -30,    34,   -30,    29,   -30,   -30,   -30,   -30,
     -30
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -30,   -30,   -30,    26,    24,    -2,   -30,    10,   -30,   -30,
     -30,   -30,   -30,   -30,   -29,   -30,   -30
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -9
static const yytype_int8 yytable[] =
{
       6,    41,    44,    33,    34,    35,    42,    45,    46,    -8,
       1,    48,     2,    -8,     2,    25,    -8,    -8,    -8,    -8,
      -8,    -8,    -8,    -8,    31,    33,    34,    35,     7,    26,
      23,    27,    28,    32,    50,    33,    34,    35,    36,     8,
      49,    24,     9,    10,    11,    12,    13,    14,    15,    16,
       0,    30
};

static const yytype_int8 yycheck[] =
{
       2,    15,    31,    17,    18,    19,    20,     4,     5,     0,
       1,    40,     5,     4,     5,    17,     7,     8,     9,    10,
      11,    12,    13,    14,     6,    17,    18,    19,     0,    19,
       5,    21,    16,    15,     5,    17,    18,    19,    20,     4,
       6,    17,     7,     8,     9,    10,    11,    12,    13,    14,
      -1,    25
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,     1,     5,    22,    25,    26,    26,     0,     4,     7,
       8,     9,    10,    11,    12,    13,    14,    23,    24,    27,
      28,    29,    30,     5,    25,    26,    28,    28,    16,    31,
      24,     6,    15,    17,    18,    19,    20,    32,    34,    35,
      36,    15,    20,    33,    35,     4,     5,    37,    35,     6,
       5
};

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrorlab


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */

#define YYFAIL		goto yyerrlab

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yytoken = YYTRANSLATE (yychar);				\
      YYPOPSTACK (1);						\
      goto yybackup;						\
    }								\
  else								\
    {								\
      yyerror (&yylloc, output, scanner, YY_("syntax error: cannot back up")); \
      YYERROR;							\
    }								\
while (YYID (0))


#define YYTERROR	1
#define YYERRCODE	256


/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#define YYRHSLOC(Rhs, K) ((Rhs)[K])
#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)				\
    do									\
      if (YYID (N))                                                    \
	{								\
	  (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;	\
	  (Current).first_column = YYRHSLOC (Rhs, 1).first_column;	\
	  (Current).last_line    = YYRHSLOC (Rhs, N).last_line;		\
	  (Current).last_column  = YYRHSLOC (Rhs, N).last_column;	\
	}								\
      else								\
	{								\
	  (Current).first_line   = (Current).last_line   =		\
	    YYRHSLOC (Rhs, 0).last_line;				\
	  (Current).first_column = (Current).last_column =		\
	    YYRHSLOC (Rhs, 0).last_column;				\
	}								\
    while (YYID (0))
#endif


/* YY_LOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

#ifndef YY_LOCATION_PRINT
# if defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL
#  define YY_LOCATION_PRINT(File, Loc)			\
     fprintf (File, "%d.%d-%d.%d",			\
	      (Loc).first_line, (Loc).first_column,	\
	      (Loc).last_line,  (Loc).last_column)
# else
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX yylex (&yylval, &yylloc, YYLEX_PARAM)
#else
# define YYLEX yylex (&yylval, &yylloc, scanner)
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (YYID (0))

# define YY_SYMBOL_PRINT(Title, Type, Value, Location)			  \
do {									  \
  if (yydebug)								  \
    {									  \
      YYFPRINTF (stderr, "%s ", Title);					  \
      yy_symbol_print (stderr,						  \
		  Type, Value, Location, output, scanner); \
      YYFPRINTF (stderr, "\n");						  \
    }									  \
} while (YYID (0))


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, YYLTYPE const * const yylocationp, globus_list_t ** output, void * scanner)
#else
static void
yy_symbol_value_print (yyoutput, yytype, yyvaluep, yylocationp, output, scanner)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
    YYLTYPE const * const yylocationp;
    globus_list_t ** output;
    void * scanner;
#endif
{
  if (!yyvaluep)
    return;
  YYUSE (yylocationp);
  YYUSE (output);
  YYUSE (scanner);
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# else
  YYUSE (yyoutput);
# endif
  switch (yytype)
    {
      default:
	break;
    }
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, YYLTYPE const * const yylocationp, globus_list_t ** output, void * scanner)
#else
static void
yy_symbol_print (yyoutput, yytype, yyvaluep, yylocationp, output, scanner)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
    YYLTYPE const * const yylocationp;
    globus_list_t ** output;
    void * scanner;
#endif
{
  if (yytype < YYNTOKENS)
    YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  YY_LOCATION_PRINT (yyoutput, *yylocationp);
  YYFPRINTF (yyoutput, ": ");
  yy_symbol_value_print (yyoutput, yytype, yyvaluep, yylocationp, output, scanner);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_stack_print (yytype_int16 *bottom, yytype_int16 *top)
#else
static void
yy_stack_print (bottom, top)
    yytype_int16 *bottom;
    yytype_int16 *top;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (; bottom <= top; ++bottom)
    YYFPRINTF (stderr, " %d", *bottom);
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (YYID (0))


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_reduce_print (YYSTYPE *yyvsp, YYLTYPE *yylsp, int yyrule, globus_list_t ** output, void * scanner)
#else
static void
yy_reduce_print (yyvsp, yylsp, yyrule, output, scanner)
    YYSTYPE *yyvsp;
    YYLTYPE *yylsp;
    int yyrule;
    globus_list_t ** output;
    void * scanner;
#endif
{
  int yynrhs = yyr2[yyrule];
  int yyi;
  unsigned long int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
	     yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      fprintf (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr, yyrhs[yyprhs[yyrule] + yyi],
		       &(yyvsp[(yyi + 1) - (yynrhs)])
		       , &(yylsp[(yyi + 1) - (yynrhs)])		       , output, scanner);
      fprintf (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (yyvsp, yylsp, Rule, output, scanner); \
} while (YYID (0))

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif



#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static YYSIZE_T
yystrlen (const char *yystr)
#else
static YYSIZE_T
yystrlen (yystr)
    const char *yystr;
#endif
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static char *
yystpcpy (char *yydest, const char *yysrc)
#else
static char *
yystpcpy (yydest, yysrc)
    char *yydest;
    const char *yysrc;
#endif
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
	switch (*++yyp)
	  {
	  case '\'':
	  case ',':
	    goto do_not_strip_quotes;

	  case '\\':
	    if (*++yyp != '\\')
	      goto do_not_strip_quotes;
	    /* Fall through.  */
	  default:
	    if (yyres)
	      yyres[yyn] = *yyp;
	    yyn++;
	    break;

	  case '"':
	    if (yyres)
	      yyres[yyn] = '\0';
	    return yyn;
	  }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into YYRESULT an error message about the unexpected token
   YYCHAR while in state YYSTATE.  Return the number of bytes copied,
   including the terminating null byte.  If YYRESULT is null, do not
   copy anything; just return the number of bytes that would be
   copied.  As a special case, return 0 if an ordinary "syntax error"
   message will do.  Return YYSIZE_MAXIMUM if overflow occurs during
   size calculation.  */
static YYSIZE_T
yysyntax_error (char *yyresult, int yystate, int yychar)
{
  int yyn = yypact[yystate];

  if (! (YYPACT_NINF < yyn && yyn <= YYLAST))
    return 0;
  else
    {
      int yytype = YYTRANSLATE (yychar);
      YYSIZE_T yysize0 = yytnamerr (0, yytname[yytype]);
      YYSIZE_T yysize = yysize0;
      YYSIZE_T yysize1;
      int yysize_overflow = 0;
      enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
      char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
      int yyx;

# if 0
      /* This is so xgettext sees the translatable formats that are
	 constructed on the fly.  */
      YY_("syntax error, unexpected %s");
      YY_("syntax error, unexpected %s, expecting %s");
      YY_("syntax error, unexpected %s, expecting %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s");
# endif
      char *yyfmt;
      char const *yyf;
      static char const yyunexpected[] = "syntax error, unexpected %s";
      static char const yyexpecting[] = ", expecting %s";
      static char const yyor[] = " or %s";
      char yyformat[sizeof yyunexpected
		    + sizeof yyexpecting - 1
		    + ((YYERROR_VERBOSE_ARGS_MAXIMUM - 2)
		       * (sizeof yyor - 1))];
      char const *yyprefix = yyexpecting;

      /* Start YYX at -YYN if negative to avoid negative indexes in
	 YYCHECK.  */
      int yyxbegin = yyn < 0 ? -yyn : 0;

      /* Stay within bounds of both yycheck and yytname.  */
      int yychecklim = YYLAST - yyn + 1;
      int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
      int yycount = 1;

      yyarg[0] = yytname[yytype];
      yyfmt = yystpcpy (yyformat, yyunexpected);

      for (yyx = yyxbegin; yyx < yyxend; ++yyx)
	if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	  {
	    if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
	      {
		yycount = 1;
		yysize = yysize0;
		yyformat[sizeof yyunexpected - 1] = '\0';
		break;
	      }
	    yyarg[yycount++] = yytname[yyx];
	    yysize1 = yysize + yytnamerr (0, yytname[yyx]);
	    yysize_overflow |= (yysize1 < yysize);
	    yysize = yysize1;
	    yyfmt = yystpcpy (yyfmt, yyprefix);
	    yyprefix = yyor;
	  }

      yyf = YY_(yyformat);
      yysize1 = yysize + yystrlen (yyf);
      yysize_overflow |= (yysize1 < yysize);
      yysize = yysize1;

      if (yysize_overflow)
	return YYSIZE_MAXIMUM;

      if (yyresult)
	{
	  /* Avoid sprintf, as that infringes on the user's name space.
	     Don't have undefined behavior even if the translation
	     produced a string with the wrong number of "%s"s.  */
	  char *yyp = yyresult;
	  int yyi = 0;
	  while ((*yyp = *yyf) != '\0')
	    {
	      if (*yyp == '%' && yyf[1] == 's' && yyi < yycount)
		{
		  yyp += yytnamerr (yyp, yyarg[yyi++]);
		  yyf += 2;
		}
	      else
		{
		  yyp++;
		  yyf++;
		}
	    }
	}
      return yysize;
    }
}
#endif /* YYERROR_VERBOSE */


/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep, YYLTYPE *yylocationp, globus_list_t ** output, void * scanner)
#else
static void
yydestruct (yymsg, yytype, yyvaluep, yylocationp, output, scanner)
    const char *yymsg;
    int yytype;
    YYSTYPE *yyvaluep;
    YYLTYPE *yylocationp;
    globus_list_t ** output;
    void * scanner;
#endif
{
  YYUSE (yyvaluep);
  YYUSE (yylocationp);
  YYUSE (output);
  YYUSE (scanner);

  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  switch (yytype)
    {
      case 15: /* "RVF_TOKEN_TEXT" */
#line 118 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
	{
    if ((yyvaluep->value).value_type == RVF_STRINGVAL && (yyvaluep->value).string_value != NULL)
    {
        free((yyvaluep->value).string_value);
    }
};
#line 1208 "globus_i_rvf_parser.c"
	break;
      case 23: /* "records" */
#line 126 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
	{ globus_l_rvf_records_destroy((yyvaluep->validation_file)); };
#line 1213 "globus_i_rvf_parser.c"
	break;
      case 24: /* "record" */
#line 125 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
	{ globus_l_rvf_validation_record_destroy(&(yyvaluep->record)); };
#line 1218 "globus_i_rvf_parser.c"
	break;
      case 28: /* "aspect_list" */
#line 125 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
	{ globus_l_rvf_validation_record_destroy(&(yyvaluep->record)); };
#line 1223 "globus_i_rvf_parser.c"
	break;
      case 32: /* "aspect_value" */
#line 118 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
	{
    if ((yyvaluep->value).value_type == RVF_STRINGVAL && (yyvaluep->value).string_value != NULL)
    {
        free((yyvaluep->value).string_value);
    }
};
#line 1233 "globus_i_rvf_parser.c"
	break;
      case 33: /* "quoted_value" */
#line 118 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
	{
    if ((yyvaluep->value).value_type == RVF_STRINGVAL && (yyvaluep->value).string_value != NULL)
    {
        free((yyvaluep->value).string_value);
    }
};
#line 1243 "globus_i_rvf_parser.c"
	break;
      case 34: /* "unquoted_value" */
#line 118 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
	{
    if ((yyvaluep->value).value_type == RVF_STRINGVAL && (yyvaluep->value).string_value != NULL)
    {
        free((yyvaluep->value).string_value);
    }
};
#line 1253 "globus_i_rvf_parser.c"
	break;
      case 35: /* "when_value_list" */
#line 118 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
	{
    if ((yyvaluep->value).value_type == RVF_STRINGVAL && (yyvaluep->value).string_value != NULL)
    {
        free((yyvaluep->value).string_value);
    }
};
#line 1263 "globus_i_rvf_parser.c"
	break;
      case 36: /* "when_value" */
#line 118 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
	{
    if ((yyvaluep->value).value_type == RVF_STRINGVAL && (yyvaluep->value).string_value != NULL)
    {
        free((yyvaluep->value).string_value);
    }
};
#line 1273 "globus_i_rvf_parser.c"
	break;

      default:
	break;
    }
}


/* Prevent warnings from -Wmissing-prototypes.  */

#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int yyparse (void *YYPARSE_PARAM);
#else
int yyparse ();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int yyparse (globus_list_t ** output, void * scanner);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */






/*----------.
| yyparse.  |
`----------*/

#ifdef YYPARSE_PARAM
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void *YYPARSE_PARAM)
#else
int
yyparse (YYPARSE_PARAM)
    void *YYPARSE_PARAM;
#endif
#else /* ! YYPARSE_PARAM */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (globus_list_t ** output, void * scanner)
#else
int
yyparse (output, scanner)
    globus_list_t ** output;
    void * scanner;
#endif
#endif
{
  /* The look-ahead symbol.  */
int yychar;

/* The semantic value of the look-ahead symbol.  */
YYSTYPE yylval;

/* Number of syntax errors so far.  */
int yynerrs;
/* Location data for the look-ahead symbol.  */
YYLTYPE yylloc;

  int yystate;
  int yyn;
  int yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus;
  /* Look-ahead token as an internal (translated) token number.  */
  int yytoken = 0;
#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

  /* Three stacks and their tools:
     `yyss': related to states,
     `yyvs': related to semantic values,
     `yyls': related to locations.

     Refer to the stacks thru separate pointers, to allow yyoverflow
     to reallocate them elsewhere.  */

  /* The state stack.  */
  yytype_int16 yyssa[YYINITDEPTH];
  yytype_int16 *yyss = yyssa;
  yytype_int16 *yyssp;

  /* The semantic value stack.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  YYSTYPE *yyvsp;

  /* The location stack.  */
  YYLTYPE yylsa[YYINITDEPTH];
  YYLTYPE *yyls = yylsa;
  YYLTYPE *yylsp;
  /* The locations where the error started and ended.  */
  YYLTYPE yyerror_range[2];

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N), yylsp -= (N))

  YYSIZE_T yystacksize = YYINITDEPTH;

  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;
  YYLTYPE yyloc;

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss;
  yyvsp = yyvs;
  yylsp = yyls;
#if defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL
  /* Initialize the default location before parsing starts.  */
  yylloc.first_line   = yylloc.last_line   = 1;
  yylloc.first_column = yylloc.last_column = 0;
#endif

  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack.  Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	yytype_int16 *yyss1 = yyss;
	YYLTYPE *yyls1 = yyls;

	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow (YY_("memory exhausted"),
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),
		    &yyls1, yysize * sizeof (*yylsp),
		    &yystacksize);
	yyls = yyls1;
	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	yytype_int16 *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyexhaustedlab;
	YYSTACK_RELOCATE (yyss);
	YYSTACK_RELOCATE (yyvs);
	YYSTACK_RELOCATE (yyls);
#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;
      yylsp = yyls + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     look-ahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to look-ahead token.  */
  yyn = yypact[yystate];
  if (yyn == YYPACT_NINF)
    goto yydefault;

  /* Not known => get a look-ahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid look-ahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yyn == 0 || yyn == YYTABLE_NINF)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the look-ahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  yystate = yyn;
  *++yyvsp = yylval;
  *++yylsp = yylloc;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];

  /* Default location.  */
  YYLLOC_DEFAULT (yyloc, (yylsp - yylen), yylen);
  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 2:
#line 131 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
        while (!globus_list_empty((yyvsp[(2) - (3)].validation_file)))
        {
            globus_list_t * node;
            globus_rvf_record_t *record;

            record = globus_list_remove(&(yyvsp[(2) - (3)].validation_file), (yyvsp[(2) - (3)].validation_file));

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
    break;

  case 3:
#line 211 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
    }
    break;

  case 4:
#line 213 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
        return 1;
    }
    break;

  case 5:
#line 218 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
        globus_rvf_record_t *           record;

        record = malloc(sizeof(globus_rvf_record_t));
        *record = (yyvsp[(3) - (3)].record);

        (yyval.validation_file) = (yyvsp[(1) - (3)].validation_file);
        globus_list_insert(&(yyval.validation_file), record);
      }
    break;

  case 6:
#line 227 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
        globus_rvf_record_t *           record;

        (yyval.validation_file) = NULL;

        record = malloc(sizeof(globus_rvf_record_t));
        *record = (yyvsp[(1) - (1)].record);

        globus_list_insert(&(yyval.validation_file), record);
    }
    break;

  case 7:
#line 240 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
        if ((yyvsp[(1) - (1)].record).attribute != NULL)
        {
            globus_rsl_assist_string_canonicalize((yyval.record).attribute);
        }
        (yyval.record) = (yyvsp[(1) - (1)].record);
      }
    break;

  case 13:
#line 260 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
        (yyval.record) = (yyvsp[(2) - (2)].record);

        switch ((yyvsp[(1) - (2)].aspect).aspect)
        {
            case RVF_TOKEN_ATTRIBUTE:
                (yyval.record).attribute = (yyvsp[(1) - (2)].aspect).string_value;
                break;
            case RVF_TOKEN_DEFAULT:
                (yyval.record).default_value = (yyvsp[(1) - (2)].aspect).string_value;
                break;
            case RVF_TOKEN_DEFAULTWHEN:
                (yyval.record).default_when = (yyvsp[(1) - (2)].aspect).when_value;
                break;
            case RVF_TOKEN_DESCRIPTION:
                (yyval.record).description = (yyvsp[(1) - (2)].aspect).string_value;
                break;
            case RVF_TOKEN_PUBLISH:
                (yyval.record).publishable = (yyvsp[(1) - (2)].aspect).bool_value;
                break;
            case RVF_TOKEN_REQUIREDWHEN:
                (yyval.record).required_when = (yyvsp[(1) - (2)].aspect).when_value;
                break;
            case RVF_TOKEN_VALIDWHEN:
                (yyval.record).valid_when = (yyvsp[(1) - (2)].aspect).when_value;
                break;
            case RVF_TOKEN_VALUES:
                (yyval.record).enumerated_values = (yyvsp[(1) - (2)].aspect).string_value;
                break;
        }
    }
    break;

  case 14:
#line 291 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
        (yyval.record) = (yyvsp[(2) - (2)].record);
    }
    break;

  case 15:
#line 294 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
        (yyval.record) = empty_record;
    }
    break;

  case 16:
#line 297 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
        (yyval.record) = empty_record;

        switch ((yyvsp[(1) - (1)].aspect).aspect)
        {
            case RVF_TOKEN_ATTRIBUTE:
                (yyval.record).attribute = (yyvsp[(1) - (1)].aspect).string_value;
                break;
            case RVF_TOKEN_DEFAULT:
                (yyval.record).default_value = (yyvsp[(1) - (1)].aspect).string_value;
                break;
            case RVF_TOKEN_DEFAULTWHEN:
                (yyval.record).default_when = (yyvsp[(1) - (1)].aspect).when_value;
                break;
            case RVF_TOKEN_DESCRIPTION:
                (yyval.record).description = (yyvsp[(1) - (1)].aspect).string_value;
                break;
            case RVF_TOKEN_PUBLISH:
                (yyval.record).publishable = (yyvsp[(1) - (1)].aspect).bool_value;
                break;
            case RVF_TOKEN_REQUIREDWHEN:
                (yyval.record).required_when = (yyvsp[(1) - (1)].aspect).when_value;
                break;
            case RVF_TOKEN_VALIDWHEN:
                (yyval.record).valid_when = (yyvsp[(1) - (1)].aspect).when_value;
                break;
        }
    }
    break;

  case 17:
#line 327 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
          (yyval.aspect) = empty_aspect;

          switch ((yyvsp[(1) - (4)].aspect_name))
          {
              case RVF_TOKEN_ATTRIBUTE:
              case RVF_TOKEN_DEFAULT:
              case RVF_TOKEN_DESCRIPTION:
              case RVF_TOKEN_VALUES:
                if ((yyvsp[(3) - (4)].value).value_type == RVF_STRINGVAL)
                {
                    (yyval.aspect).aspect = (yyvsp[(1) - (4)].aspect_name);
                    (yyval.aspect).string_value = (yyvsp[(3) - (4)].value).string_value;
                }
                else if ((yyvsp[(3) - (4)].value).value_type == RVF_EMPTYVAL)
                {
                    (yyval.aspect).aspect = (yyvsp[(1) - (4)].aspect_name);
                    (yyval.aspect).string_value = NULL;
                }
                else
                {
                    YYERROR;
                }
                break;
              case RVF_TOKEN_DEFAULTWHEN:
              case RVF_TOKEN_VALIDWHEN:
              case RVF_TOKEN_REQUIREDWHEN:
                if ((yyvsp[(3) - (4)].value).value_type == RVF_WHENVAL)
                {
                    (yyval.aspect).aspect = (yyvsp[(1) - (4)].aspect_name);
                    (yyval.aspect).when_value = (yyvsp[(3) - (4)].value).when_value;
                }
                else if ((yyvsp[(3) - (4)].value).value_type == RVF_EMPTYVAL)
                {
                    (yyval.aspect).aspect = (yyvsp[(1) - (4)].aspect_name);
                    (yyval.aspect).when_value = 0;
                }
                else
                {
                    if ((yyvsp[(3) - (4)].value).value_type == RVF_STRINGVAL &&
                        (yyvsp[(3) - (4)].value).string_value != NULL)
                    {
                        free((yyvsp[(3) - (4)].value).string_value);
                        (yyvsp[(3) - (4)].value).string_value = NULL;
                    }
                    YYERROR;
                }

                break;
              case RVF_TOKEN_PUBLISH:
                if ((yyvsp[(3) - (4)].value).value_type == RVF_BOOLVAL)
                {
                    (yyval.aspect).aspect = (yyvsp[(1) - (4)].aspect_name);
                    (yyval.aspect).bool_value = (yyvsp[(3) - (4)].value).bool_value;
                }
                else
                {
                    if ((yyvsp[(3) - (4)].value).value_type == RVF_STRINGVAL &&
                        (yyvsp[(3) - (4)].value).string_value != NULL)
                    {
                        free((yyvsp[(3) - (4)].value).string_value);
                        (yyvsp[(3) - (4)].value).string_value = NULL;
                    }
                    YYERROR;
                }
                break;
          }
      }
    break;

  case 25:
#line 400 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
        (yyval.aspect_name) = (yyvsp[(1) - (1)].aspect_name);
    }
    break;

  case 27:
#line 408 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
        (yyval.value) = (yyvsp[(2) - (3)].value);
    }
    break;

  case 28:
#line 411 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
        (yyval.value) = (yyvsp[(1) - (1)].value);
    }
    break;

  case 29:
#line 414 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
        (yyval.value).value_type = RVF_EMPTYVAL;
    }
    break;

  case 30:
#line 419 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
        (yyval.value).value_type = RVF_WHENVAL;
        (yyval.value).when_value = (yyvsp[(1) - (1)].value).when_value;
    }
    break;

  case 31:
#line 423 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
        (yyval.value).value_type = RVF_BOOLVAL;
        (yyval.value).bool_value = (yyvsp[(1) - (1)].bool_value);
    }
    break;

  case 32:
#line 427 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
        (yyval.value).value_type = RVF_STRINGVAL;
        (yyval.value).string_value = (yyvsp[(1) - (1)].value).string_value;
    }
    break;

  case 33:
#line 431 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
        (yyval.value).value_type = RVF_EMPTYVAL;
    }
    break;

  case 34:
#line 436 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
        (yyval.value).value_type = RVF_WHENVAL;
        (yyval.value).when_value = (yyvsp[(1) - (1)].value).when_value;
    }
    break;

  case 35:
#line 440 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
        (yyval.value).value_type = RVF_BOOLVAL;
        (yyval.value).bool_value = (yyvsp[(1) - (1)].bool_value);
    }
    break;

  case 36:
#line 444 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
        (yyval.value).value_type = RVF_STRINGVAL;
        (yyval.value).string_value = (yyvsp[(1) - (1)].value).string_value;
    }
    break;

  case 37:
#line 450 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
        (yyval.value).value_type = RVF_WHENVAL;
        (yyval.value).when_value = (yyvsp[(1) - (2)].value).when_value | (yyvsp[(2) - (2)].value).when_value;
    }
    break;

  case 38:
#line 454 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
        (yyval.value) = (yyvsp[(1) - (1)].value);
    }
    break;

  case 39:
#line 459 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
        (yyval.value).value_type = RVF_WHENVAL;
        (yyval.value).when_value = 1;
      }
    break;

  case 40:
#line 463 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
        (yyval.value).value_type = RVF_WHENVAL;
        (yyval.value).when_value = 2;
      }
    break;

  case 41:
#line 467 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
        (yyval.value).value_type = RVF_WHENVAL;
        (yyval.value).when_value = 4;
      }
    break;

  case 43:
#line 474 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"
    {
    }
    break;


/* Line 1267 of yacc.c.  */
#line 2014 "globus_i_rvf_parser.c"
      default: break;
    }
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;
  *++yylsp = yyloc;

  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (&yylloc, output, scanner, YY_("syntax error"));
#else
      {
	YYSIZE_T yysize = yysyntax_error (0, yystate, yychar);
	if (yymsg_alloc < yysize && yymsg_alloc < YYSTACK_ALLOC_MAXIMUM)
	  {
	    YYSIZE_T yyalloc = 2 * yysize;
	    if (! (yysize <= yyalloc && yyalloc <= YYSTACK_ALLOC_MAXIMUM))
	      yyalloc = YYSTACK_ALLOC_MAXIMUM;
	    if (yymsg != yymsgbuf)
	      YYSTACK_FREE (yymsg);
	    yymsg = (char *) YYSTACK_ALLOC (yyalloc);
	    if (yymsg)
	      yymsg_alloc = yyalloc;
	    else
	      {
		yymsg = yymsgbuf;
		yymsg_alloc = sizeof yymsgbuf;
	      }
	  }

	if (0 < yysize && yysize <= yymsg_alloc)
	  {
	    (void) yysyntax_error (yymsg, yystate, yychar);
	    yyerror (&yylloc, output, scanner, yymsg);
	  }
	else
	  {
	    yyerror (&yylloc, output, scanner, YY_("syntax error"));
	    if (yysize != 0)
	      goto yyexhaustedlab;
	  }
      }
#endif
    }

  yyerror_range[0] = yylloc;

  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse look-ahead token after an
	 error, discard it.  */

      if (yychar <= YYEOF)
	{
	  /* Return failure if at end of input.  */
	  if (yychar == YYEOF)
	    YYABORT;
	}
      else
	{
	  yydestruct ("Error: discarding",
		      yytoken, &yylval, &yylloc, output, scanner);
	  yychar = YYEMPTY;
	}
    }

  /* Else will try to reuse look-ahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  yyerror_range[0] = yylsp[1-yylen];
  /* Do not reclaim the symbols of the rule which action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (yyn != YYPACT_NINF)
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
	YYABORT;

      yyerror_range[0] = *yylsp;
      yydestruct ("Error: popping",
		  yystos[yystate], yyvsp, yylsp, output, scanner);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  *++yyvsp = yylval;

  yyerror_range[1] = yylloc;
  /* Using YYLLOC is tempting, but would change the location of
     the look-ahead.  YYLOC is available though.  */
  YYLLOC_DEFAULT (yyloc, (yyerror_range - 1), 2);
  *++yylsp = yyloc;

  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#ifndef yyoverflow
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (&yylloc, output, scanner, YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEOF && yychar != YYEMPTY)
     yydestruct ("Cleanup: discarding lookahead",
		 yytoken, &yylval, &yylloc, output, scanner);
  /* Do not reclaim the symbols of the rule which action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
		  yystos[*yyssp], yyvsp, yylsp, output, scanner);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  /* Make sure YYID is used.  */
  return YYID (yyresult);
}


#line 476 "../../../../../../gram/jobmanager/source/rvf/globus_i_rvf_parser.y"


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

