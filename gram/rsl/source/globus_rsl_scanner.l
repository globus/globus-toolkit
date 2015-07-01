%{
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

#include "globus_common.h"
#include "globus_rsl.h"
#include "globus_i_rsl_parser.h"
#include "globus_rsl_parser.h"


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
#undef YY_INPUT
#define YY_INPUT(b,r,s) globus_i_rsl_yyinput(globus_rslget_extra(yyscanner), b, &r, s)
#define YY_NO_INPUT
%}


UNQUOTED_LITERAL           ([^\t \n+&|=!<>()"'^*$#?~][^\t \n=!<>()"'^*$#?~]*)
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


%option 8bit
%option reentrant
%option prefix="globus_rsl"
%option yylineno
%option noyywrap
%option nounput
%option extra-type="struct globus_parse_state_s *"
%option bison-bridge
%option bison-locations
%option header-file="globus_rsl_scanner.h"


%%

%{
    struct globus_parse_state_s        *parse_state;
    parse_state = globus_rslget_extra(yyscanner);
%}

<IMPLICIT_CONCATENATE>(.|\n)			{ BEGIN (parse_state->calling_state);
   /* we just ate a character "by accident", so push it back */
   yyless(yyleng-1);

   return (RSL_OP_CONCATENATE);
}


<COMMENT>{COMMENT_END}				{ BEGIN (parse_state->calling_state);
}

<COMMENT>([^*])*  { }
<COMMENT>("*")/[^)] { }

<QUOTE>(.|\n) 					{ /* conditional BEGIN */
  if ( yytext[0] != parse_state->quote_delimiter ) {
    /* another quoted character */

    globus_fifo_enqueue (parse_state->quote_text_fifo,
			 (void *) (intptr_t) (yytext[0]));
  }
  else {

    BEGIN (QUOTE_HIT_DELIM);
  }
}

<QUOTE_HIT_DELIM>(.|\n)			        { /* conditional BEGIN */
  if ( yytext[0] == parse_state->quote_delimiter ) {
    /* an escaped delimiter */
    globus_fifo_enqueue (parse_state->quote_text_fifo,
			 (void *) (intptr_t) (yytext[0]));

    /* continue scanning the quoted literal */
    BEGIN (QUOTE);
  }
  else {
    /* we just ate a character after the delimiter, so push it back */
    yyless(yyleng-1);

    BEGIN (parse_state->calling_state);

    /* return the quoted literal token */
    {
      char * buf;
      int i;

      buf = globus_malloc (sizeof(char)
			   * (globus_fifo_size (parse_state->quote_text_fifo)
			      + 1));
      assert (buf!=NULL);
      
      i = 0;
      while ( ! globus_fifo_empty (parse_state->quote_text_fifo) ) {
	buf[i] = (char) (long) globus_fifo_dequeue (parse_state->quote_text_fifo);
	i++;
      }
      buf[i] = '\0';

      yylval->String = buf;

      globus_fifo_destroy (parse_state->quote_text_fifo);
      globus_free (parse_state->quote_text_fifo);
      parse_state->quote_text_fifo = NULL;

      return (RSL_STRING);
    }
  }
}


<INITIAL,VARIABLE>{COMMENT_START}		{ 
  parse_state->calling_state = YY_START;
  BEGIN (COMMENT);
}

<INITIAL,VARIABLE>{NORMAL_QUOTE_DELIMITER}	{
  parse_state->calling_state = YY_START;
  BEGIN (QUOTE);
  parse_state->quote_delimiter = yytext[0];
  parse_state->quote_text_fifo = globus_malloc (sizeof (globus_fifo_t));
  assert (parse_state->quote_text_fifo!=NULL);
  globus_fifo_init (parse_state->quote_text_fifo);
}

<INITIAL,VARIABLE>{USER_QUOTE_DELIMITER}(.|\n) { 
  parse_state->calling_state = YY_START;
  BEGIN (QUOTE);
  parse_state->quote_delimiter = yytext[1]; /* the user's quote character */
  parse_state->quote_text_fifo = globus_malloc (sizeof (globus_fifo_t));
  assert (parse_state->quote_text_fifo!=NULL);
  globus_fifo_init (parse_state->quote_text_fifo);
}

<INITIAL,VARIABLE>{VARIABLE_START}		{ BEGIN (VARIABLE);
  {
    paren_count_stack_elem_t * frame;
    frame = globus_malloc (sizeof (paren_count_stack_elem_t));
    assert (frame!=NULL);
    frame->count = 0;
    globus_list_insert (&parse_state->paren_count_stack, (void *) frame);
  }

  return (RSL_VARIABLE_START);
}

<INITIAL,VARIABLE>{UNQUOTED_LITERAL}/{VARIABLE_START} { 
  parse_state->calling_state = YY_START;
  BEGIN (IMPLICIT_CONCATENATE);
  /* this unquoted literal is enjambed with a variable,
   * so we bounce through the IMPLICIT_CONCATENATE state to
   * generate an extra CONCATENATE token and bounce back to 
   * the calling state, where the variable will be recognized
   * as usual.
   */
  yylval->String = strdup (yytext);
  return (RSL_STRING);
}

<INITIAL,VARIABLE>{UNQUOTED_LITERAL}		{
  yylval->String = strdup (yytext);
  return (RSL_STRING);
}

<INITIAL>{LPAREN}				{ 
  return (RSL_LPAREN); 
}

<VARIABLE>{LPAREN}				{
  assert (! globus_list_empty (parse_state->paren_count_stack));
  (((paren_count_stack_elem_t *) 
    globus_list_first (parse_state->paren_count_stack))->count) += 1;
  return (RSL_LPAREN);
}

<INITIAL>{RPAREN} 				{
  return (RSL_RPAREN);
}

<VARIABLE>{RPAREN}/({UNQUOTED_LITERAL_CHAR}|{VARIABLE_START}) { 
						  /* conditional BEGIN */
  int * paren_countp;

  assert (! globus_list_empty (parse_state->paren_count_stack));
  paren_countp = &(((paren_count_stack_elem_t *) 
		    globus_list_first (parse_state->paren_count_stack))->count);

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
		 globus_list_first (parse_state->paren_count_stack));
    globus_list_remove (&parse_state->paren_count_stack, parse_state->paren_count_stack);

    if ( globus_list_empty (parse_state->paren_count_stack)) {
      /* we were the outermost variable reference, so the 
       * implicit-concatenation state should return to the INITIAL state
       * after generating a token.
       */
      parse_state->calling_state = INITIAL;
    }
    else {
      parse_state->calling_state = VARIABLE;
    }

    BEGIN (IMPLICIT_CONCATENATE);
  }

  return (RSL_RPAREN);
}

<VARIABLE>{RPAREN} 				{ /* conditional BEGIN */
  int * paren_countp;

  assert (! globus_list_empty (parse_state->paren_count_stack));
  paren_countp = &(((paren_count_stack_elem_t *) 
		    globus_list_first (parse_state->paren_count_stack))->count);

  (*paren_countp) -= 1;

  if ((*paren_countp) == 0) {
    /* this right-paren closes a variable reference expression */
    /* pop our completed counter from the stack */
    globus_free ((paren_count_stack_elem_t *) 
		 globus_list_first (parse_state->paren_count_stack));
    globus_list_remove (&parse_state->paren_count_stack, parse_state->paren_count_stack);

    if ( globus_list_empty (parse_state->paren_count_stack)) {
      /* we were the outermost variable reference, so the 
       * next state should be INITIAL */

      BEGIN (INITIAL);
    }
    else {

      BEGIN (VARIABLE);
    }
  }

  return (RSL_RPAREN);
}

<INITIAL,VARIABLE>{OP_EQ} 			{
  return (RSL_OP_EQ);
}

<INITIAL,VARIABLE>{OP_NEQ} 			{
  return (RSL_OP_NEQ);
}

<INITIAL,VARIABLE>{OP_LT} 			{
  return (RSL_OP_LT);
}

<INITIAL,VARIABLE>{OP_LTEQ} 			{
  return (RSL_OP_LTEQ);
}

<INITIAL,VARIABLE>{OP_GT} 			{
  return (RSL_OP_GT);
}

<INITIAL,VARIABLE>{OP_GTEQ} 			{
  return (RSL_OP_GTEQ);
}

<INITIAL,VARIABLE>{OP_MULTIREQ} 		{
  return (RSL_OP_MULTIREQ);
}

<INITIAL,VARIABLE>{OP_AND}		{
  return (RSL_OP_AND);
}

<INITIAL,VARIABLE>{OP_OR} 		{
  return (RSL_OP_OR);
}

<INITIAL,VARIABLE>{OP_CONCATENATE}		{
  return (RSL_OP_CONCATENATE);
}

<INITIAL,VARIABLE>{WHITESPACE}+ 		{ }


<*>.						{
  /* we ran into a character not matched by any of the
   * above patterns.  let the parser sort it out. */
  yyterminate();
}


<*><<EOF>>					{
  /* we ran into EOF in any of the states.  maybe error, maybe not.
   * let the parser sort it out. */
  yyterminate();
}
