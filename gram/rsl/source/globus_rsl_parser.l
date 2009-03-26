/*
 * Copyright 1999-2006 University of Chicago
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
%{
/* NOTE: You MUST run flex with the -s option (to disable the default rule)
 *   for this to work.  Of course you should always do this anyway
 *   if you care about correctness...
 * NOTE: You must use bison with %pure_parser and flex for this to work */


/* needed to read input from string rather than stdin
 * from page 157 of Nutshell lex & yacc
 * NOTE: only works if using flex and not lex
 */

#undef YY_INPUT
#define YY_INPUT(b,r,ms) (r = my_yyinput(b, ms))

/* end from page 157 of Nutshell lex & yacc
 */


/*
 * The following macros give yylex() the appropriate
 * arguments, as expected by bison with %pure_parser
 */
#ifdef YYPURE
#ifdef YYLSP_NEEDED
#ifdef YYLEX_PARAM
#define YY_DECL       int yylex (YYSTYPE *yylval, YYLTYPE *yylloc, void *YYLEX_PARAM)
#else
#define YY_DECL       int yylex (YYSTYPE *yylval, YYLTYPE *yylloc)
#endif
#else /* not YYLSP_NEEDED */
#ifdef YYLEX_PARAM
#define YY_DECL       int yylex (YYSTYPE *yylval, void *YYLEX_PARAM)
#else
#define YY_DECL       int yylex (YYSTYPE *yylval)
#endif
#endif /* not YYLSP_NEEDED */
#define GRAMI_YYLVAL_DOT yylval->
#endif

  /* the token types used by our parser */

/* #include "globus_rsl_tokens.tab.h" */


  /* variables etc. used by the lexer rules below */

#include "globus_common.h"


  /* this lexer uses exclusive start-conditions to implement
   * several inter-related lexical languages.
   *
   * the INITIAL state implements the top-level RSL lexical language
   * consisting of operators, comments, value-expressions, and 
   * variable-reference expressions.
   *
   * the VARIABLE state implements the embedded variable-reference
   * scanner for tokens in value expressions (as the INITIAL state does),
   * but also maintains context to recognize when the end of a variable
   * reference in the RSL grammar has been reached (by matching parens).
   * the beginning and end of variable references mark points in the input
   * stream where we must pay particular attention to whitespace to
   * recognize the implicit concatenation lexical notation.  when we
   * encounter this notation, we inject a concatenation operator into
   * the token stream so that the parser doesn't have to do anything
   * special for implicit concatenate.
   *
   * the IMPLICIT_CONCATENATE state doesn't scan any characters, but
   * generates a single concatenate operator token.  this is used by
   * the INITIAL and VARIABLE states to emit the extra token at certain
   * transition points.
   *
   * the COMMENT state implements the embedded scanner that eats
   * the body and terminating delimiter of comments once the comment
   * sublanguage has been recognized by the INITIAL and VARIABLE scanners.
   *
   * the QUOTE and QUOTE_HIT_DELIM states implement the embedded 
   * quoted-literal lexical language, generating quoted-literal tokens 
   * once the quoted-literal sublanguage has been recognized by the 
   * INITIAL and VARIABLE scanners.
   *
   * start-state machine:
   *
   *   INITIAL->COMMENT->INITIAL
   *   INITIAL->QUOTE->QUOTE_HIT_DELIM->INITIAL
   *   INITIAL->VARIABLE
   *   INITIAL->IMPLICIT_CONCATENATE->VARIABLE
   *
   *   VARIABLE->COMMENT->VARIABLE
   *   VARIABLE->QUOTE->QUOTE_HIT_DELIM->VARIABLE
   *   VARIABLE->IMPLICIT_CONCATENATE->INITIAL
   *   VARIABLE->INITIAL
   *   VARIABLE->IMPLICIT_CONCATENATE->VARIABLE
   * 
   *   the calling_state variable below is used to return
   *   from non-recursive quote/comment/implicit-concatenate states to the 
   *   appropriate initial/variable state.
   *
   *   the recursive variable/initial transitions are controlled
   *   by the stack documented below.
   */

int calling_state;  /* one of INITIAL, VARIABLE */

char             quote_delimiter = '\0';
globus_fifo_t  * quote_text_fifo = NULL; /* completely dynamic buffer */


  /* the scanner matches left and right-parens by
   * introducing a new counter at the beginning of each
   * variable reference expression.  this allows it to
   * detect the terminating right-paren of the variable reference
   * and check whether the enjambed implicit-concatenation
   * syntax is being used.  it then restores the previous
   * paren counter and keeps going (to recognize the end
   * of any enclosing variable reference expression).
   */
typedef struct paren_count_stack_elem_s {
  int count;
} paren_count_stack_elem_t;

/* manipulate this list as stack...
 * introduced as a list rather than an abstract-data-type
 * so we can simply init it here as the constant NULL. */
globus_list_t * paren_count_stack = NULL; 



/* the following sections define:
 *    symbolic regular-expression names (put all char-set details together)
 *    start-condition (state) definitions
 *    pattern/action rules
 */

/* notes about the character classes:
 *   because unquoted literals can contain '/', the comment
 *   syntax must be separated from prefix unquoted literals by whitespace.
 * 
 *   in this implementation, the comment-start notation '/''*' match 
 *   will win over the alternate match of '/' as an unquoted literal 
 *   followed by the invalid single char '*' since it is a longer match.
 */
%}


UNQUOTED_LITERAL           ([^\t \n+&|=!<>()"'^*$#?~]+)
UNQUOTED_LITERAL_CHAR      ([^\t \n+&|=!<>()"'^*$#?~])
NORMAL_QUOTE_DELIMITER     (["'])
USER_QUOTE_DELIMITER       ("^")

WHITESPACE                 ([ \t\n])

VARIABLE_START             ("$")

COMMENT_START              ("(""*")
COMMENT_END                ("*"")")
/*
COMMENT_BODY               ((("*"[^)])|([^*]))*)
*/

LPAREN                     ("(")
RPAREN                     (")")

OP_EQ                      ("=")
OP_NEQ                     ("!=")
OP_LT                      ("<")
OP_LTEQ                    ("<=")
OP_GT                      (">")
OP_GTEQ                    (">=")

OP_MULTIREQ                ("+")
OP_AND                     ("&")
OP_OR                      ("|")

OP_CONCATENATE             ("#")


%{
  /* the following are all exclusive states.  the use of the states
   * are explained above.
   *
   * the difference between exclusive and inclusive states in flex
   * is that in exclusive states any bare pattern/action rules 
   * are disabled, so _only_ rules explicitly labeled as being active
   * in the exclusive state are active when that state is entered.
   * inclusive states activate both explicitly labeled rules and
   * the bare unlabeled rules.
   *
   * this flex file does not use any unlabeled rules, so this distinction
   * doesn't really matter.  please keep it that way if you modify it.
   *
   * this flex file also does not rely on the order of pattern/action
   * rules to resolve anything.  each of the rule sets active in a given
   * state are resolved only by the basic greatest-matching-prefix
   * distinction.
   */
%}

%x COMMENT
%x VARIABLE
%x QUOTE
%x QUOTE_HIT_DELIM
%x IMPLICIT_CONCATENATE



%%

<IMPLICIT_CONCATENATE>(.|\n)			{ BEGIN (calling_state);
   /* we just ate a character "by accident", so push it back */
   yyless(yyleng-1);

   return (RSL_OP_CONCATENATE);
dummy_implicit_concatenate_label: ;
}


<COMMENT>{COMMENT_END}				{ BEGIN (calling_state);
}

<COMMENT>([^*])*  { }
<COMMENT>("*")/[^)] { }

<QUOTE>(.|\n) 					{ /* conditional BEGIN */
  if ( yytext[0] != quote_delimiter ) {
    /* another quoted character */

    globus_fifo_enqueue (quote_text_fifo,
			 (void *) (yytext[0]));
  }
  else {

    BEGIN (QUOTE_HIT_DELIM);
  }
}

<QUOTE_HIT_DELIM>(.|\n)			        { /* conditional BEGIN */
  if ( yytext[0] == quote_delimiter ) {
    /* an escaped delimiter */
    globus_fifo_enqueue (quote_text_fifo,
			 (void *) (yytext[0]));

    /* continue scanning the quoted literal */
    BEGIN (QUOTE);
  }
  else {
    /* we just ate a character after the delimiter, so push it back */
    yyless(yyleng-1);

    BEGIN (calling_state);

    /* return the quoted literal token */
    {
      char * buf;
      char c;
      int i;

      buf = globus_malloc (sizeof(char)
			   * (globus_fifo_size (quote_text_fifo)
			      + 1));
      assert (buf!=NULL);
      
      i = 0;
      while ( ! globus_fifo_empty (quote_text_fifo) ) {
	buf[i] = (char) (long) globus_fifo_dequeue (quote_text_fifo);
	i++;
      }
      buf[i] = '\0';

      GRAMI_YYLVAL_DOT String = buf;

      globus_fifo_destroy (quote_text_fifo);
      globus_free (quote_text_fifo);
      quote_text_fifo = NULL;

      return (RSL_STRING);
    dummy_quoted_literal_label: ;
    }
  }
}


<INITIAL,VARIABLE>{COMMENT_START}		{ 
  calling_state = YY_START;
  BEGIN (COMMENT);
}

<INITIAL,VARIABLE>{NORMAL_QUOTE_DELIMITER}	{
  calling_state = YY_START;
  BEGIN (QUOTE);
  quote_delimiter = yytext[0];
  quote_text_fifo = globus_malloc (sizeof (globus_fifo_t));
  assert (quote_text_fifo!=NULL);
  globus_fifo_init (quote_text_fifo);
}

<INITIAL,VARIABLE>{USER_QUOTE_DELIMITER}(.|\n) { 
  calling_state = YY_START;
  BEGIN (QUOTE);
  quote_delimiter = yytext[1]; /* the user's quote character */
  quote_text_fifo = globus_malloc (sizeof (globus_fifo_t));
  assert (quote_text_fifo!=NULL);
  globus_fifo_init (quote_text_fifo);
}

<INITIAL,VARIABLE>{VARIABLE_START}		{ BEGIN (VARIABLE);
  {
    paren_count_stack_elem_t * frame;
    frame = globus_malloc (sizeof (paren_count_stack_elem_t));
    assert (frame!=NULL);
    frame->count = 0;
    globus_list_insert (&paren_count_stack, (void *) frame);
  }

  return (RSL_VARIABLE_START);
dummy_variable_start_label: ;
}

<INITIAL,VARIABLE>{UNQUOTED_LITERAL}/{VARIABLE_START} { 
  calling_state = YY_START;
  BEGIN (IMPLICIT_CONCATENATE);
  /* this unquoted literal is enjambed with a variable,
   * so we bounce through the IMPLICIT_CONCATENATE state to
   * generate an extra CONCATENATE token and bounce back to 
   * the calling state, where the variable will be recognized
   * as usual.
   */
  GRAMI_YYLVAL_DOT String = strdup (yytext);
  return (RSL_STRING);
dummy_unquoted_literal_label_1: ;
}

<INITIAL,VARIABLE>{UNQUOTED_LITERAL}		{
  GRAMI_YYLVAL_DOT String = strdup (yytext);
  return (RSL_STRING);
dummy_unquoted_literal_label_2: ;
}

<INITIAL>{LPAREN}				{ 
  return (RSL_LPAREN); 
dummy_lparen_label_1: ;
}

<VARIABLE>{LPAREN}				{
  assert (! globus_list_empty (paren_count_stack));
  (((paren_count_stack_elem_t *) 
    globus_list_first (paren_count_stack))->count) += 1;
  return (RSL_LPAREN);
dummy_lparen_label_2: ;
}

<INITIAL>{RPAREN} 				{
  return (RSL_RPAREN);
dummy_rparen_label_1: ;
}

<VARIABLE>{RPAREN}/({UNQUOTED_LITERAL_CHAR}|{VARIABLE_START}) { 
						  /* conditional BEGIN */
  int * paren_countp;

  assert (! globus_list_empty (paren_count_stack));
  paren_countp = &(((paren_count_stack_elem_t *) 
		    globus_list_first (paren_count_stack))->count);

  (*paren_countp) -= 1;

  if ((*paren_countp) == 0) {
    /* this right-paren closes a variable reference expression,
     * and is enjambed with a quoted-literal or variable,
     * so we bounce through the IMPLICIT_CONCATENATE state to
     * generate an extra CONCATENATE token and bounce back to 
     * the calling state, where the variable will be recognized
     * as usual.
     */

    /* pop our completed counter from the stack */
    globus_free ((paren_count_stack_elem_t *) 
		 globus_list_first (paren_count_stack));
    globus_list_remove (&paren_count_stack, paren_count_stack);

    if ( globus_list_empty (paren_count_stack)) {
      /* we were the outermost variable reference, so the 
       * implicit-concatenation state should return to the INITIAL state
       * after generating a token.
       */
      calling_state = INITIAL;
    }
    else {
      calling_state = VARIABLE;
    }

    BEGIN (IMPLICIT_CONCATENATE);
  }

  return (RSL_RPAREN);
dummy_rparen_label_2: ;
}

<VARIABLE>{RPAREN} 				{ /* conditional BEGIN */
  int * paren_countp;

  assert (! globus_list_empty (paren_count_stack));
  paren_countp = &(((paren_count_stack_elem_t *) 
		    globus_list_first (paren_count_stack))->count);

  (*paren_countp) -= 1;

  if ((*paren_countp) == 0) {
    /* this right-paren closes a variable reference expression */
    /* pop our completed counter from the stack */
    globus_free ((paren_count_stack_elem_t *) 
		 globus_list_first (paren_count_stack));
    globus_list_remove (&paren_count_stack, paren_count_stack);

    if ( globus_list_empty (paren_count_stack)) {
      /* we were the outermost variable reference, so the 
       * next state should be INITIAL */

      BEGIN (INITIAL);
    }
    else {

      BEGIN (VARIABLE);
    }
  }

  return (RSL_RPAREN);
dummy_rparen_label_4: ;
}

<INITIAL,VARIABLE>{OP_EQ} 			{
  return (RSL_OP_EQ);
dummy_op_eq_label: ;
}

<INITIAL,VARIABLE>{OP_NEQ} 			{
  return (RSL_OP_NEQ);
dummy_op_neq_label: ;
}

<INITIAL,VARIABLE>{OP_LT} 			{
  return (RSL_OP_LT);
dummy_op_lt_label: ;
}

<INITIAL,VARIABLE>{OP_LTEQ} 			{
  return (RSL_OP_LTEQ);
dummy_op_lteq_label: ;
}

<INITIAL,VARIABLE>{OP_GT} 			{
  return (RSL_OP_GT);
dummy_op_gt_label: ;
}

<INITIAL,VARIABLE>{OP_GTEQ} 			{
  return (RSL_OP_GTEQ);
dummy_op_gteq_label: ;
}

<INITIAL,VARIABLE>{OP_MULTIREQ} 		{
  return (RSL_OP_MULTIREQ);
dummy_op_multireq_label: ;
}

<INITIAL,VARIABLE>{OP_AND}		{
  return (RSL_OP_AND);
dummy_op_conjunction_label: ;
}

<INITIAL,VARIABLE>{OP_OR} 		{
  return (RSL_OP_OR);
dummy_op_disjunction_label: ;
}

<INITIAL,VARIABLE>{OP_CONCATENATE}		{
  return (RSL_OP_CONCATENATE);
dummy_op_concatenate_label: ;
}

<INITIAL,VARIABLE>{WHITESPACE}+ 		{ }


<*>.						{
  /* we ran into a character not matched by any of the
   * above patterns.  let the parser sort it out. */
  yyterminate();
dummy_invalid_char_label: ;
}


<*><<EOF>>					{
  /* we ran into EOF in any of the states.  maybe error, maybe not.
   * let the parser sort it out. */
  yyterminate();
dummy_eof_label: ;
}
