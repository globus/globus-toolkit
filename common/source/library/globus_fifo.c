
/********************************************************************
 *
 * This file implements the fifo_t type
 *
 ********************************************************************/

#include "config.h"
#include "globus_common.h"

#include <assert.h>
#include <stdlib.h>

#include "globus_fifo.h"

#include "globus_list.h"


int
globus_fifo_init (globus_fifo_t * fifo)
{
  if (fifo==GLOBUS_NULL) return -1;

  fifo->head = GLOBUS_NULL;
  fifo->tail = GLOBUS_NULL;

  return 0;
}

extern void
globus_fifo_destroy (globus_fifo_t * fifo)
{
  if (fifo!=GLOBUS_NULL) {
    globus_list_free (fifo->head);
    fifo->head = GLOBUS_NULL;
    fifo->tail = GLOBUS_NULL;
  }
}

extern int 
globus_fifo_empty (const globus_fifo_t * fifo)
{
  assert (fifo!=GLOBUS_NULL);

  return fifo->head==GLOBUS_NULL;
}

extern int 
globus_fifo_size (globus_fifo_t * fifo)
{
  assert (fifo!=GLOBUS_NULL);

  return globus_list_size (fifo->head);
}

extern int
globus_fifo_enqueue (globus_fifo_t * fifo,
		     void          * datum)
{
  int err;

  if (fifo==GLOBUS_NULL) return -1;

  if (fifo->tail==GLOBUS_NULL) {
    err = globus_list_insert ((globus_list_t **) &(fifo->tail), 
			      datum);
    fifo->head = fifo->tail;
  }
  else {
    err = globus_list_insert (globus_list_rest_ref (fifo->tail),
			      datum);
    fifo->tail = globus_list_rest (fifo->tail);
  }

  return err;
}

globus_fifo_t *
globus_fifo_copy (globus_fifo_t *fifo)
{
  globus_fifo_t * copy;

  if ( fifo == NULL ) return NULL;

  copy = globus_malloc (sizeof(globus_fifo_t));
  if ( copy == NULL ) return NULL;

  globus_fifo_init (copy);

  copy->head = globus_list_copy (fifo->head);
  copy->tail = copy->head;

  while ( ! globus_list_empty (globus_list_rest (copy->tail)) ) {
    copy->tail = globus_list_rest (copy->tail);
  }

  return copy;
}

extern void *
globus_fifo_peek (globus_fifo_t * fifo)
{
  assert (fifo!=GLOBUS_NULL);
  assert (! globus_list_empty (fifo->head));

  return globus_list_first (fifo->head);
}

extern void *
globus_fifo_tail_peek (globus_fifo_t * fifo)
{
  assert (fifo!=GLOBUS_NULL);
  assert (! globus_list_empty (fifo->tail));

  return globus_list_first (fifo->tail);
}

extern void *
globus_fifo_dequeue (globus_fifo_t *fifo)
{
  void * datum;

  assert (fifo!=GLOBUS_NULL);

  if ( globus_list_empty (fifo->head) ) return GLOBUS_NULL;

  datum = globus_list_remove ((globus_list_t **) &(fifo->head), 
			      (globus_list_t *) fifo->head);

  if ( globus_list_empty (fifo->head) ) {
    fifo->tail = fifo->head;
  }

  return datum;
}


extern void *
globus_fifo_remove (globus_fifo_t *fifo, void *datum)
{
  globus_list_t * iter_prev;
  globus_list_t * iter;

  assert (fifo!=GLOBUS_NULL);

  if ( globus_list_empty (fifo->head) ) return GLOBUS_NULL;

  iter_prev = GLOBUS_NULL;
  iter = fifo->head;
  while ( (! globus_list_empty (iter))
	  && (globus_list_first (iter) != datum) ) {
    iter_prev = iter;
    iter = globus_list_rest (iter);
  }

  if ( ! globus_list_empty (iter) ) {
    /* iter is the element to remove, iter_prev is the previous */
    if ( iter == fifo->tail ) {
      /* make sure tail doesn't dangle */
      fifo->tail = iter_prev;
    }
    globus_list_remove (&(fifo->head), iter);

    return datum;
  }
  else
    return GLOBUS_NULL;
}

int
globus_fifo_move(
    globus_fifo_t *				fifo_dest,
    globus_fifo_t *				fifo_src)
{
  if (fifo_dest == GLOBUS_NULL || fifo_src == GLOBUS_NULL)
  {
      return -1;
  }

  fifo_dest->head = fifo_src->head;
  fifo_dest->tail = fifo_src->tail;

  fifo_src->head = GLOBUS_NULL;
  fifo_src->tail = GLOBUS_NULL;

  return 0;
}
