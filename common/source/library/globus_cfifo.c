
/********************************************************************
 *
 * This file implements the cfifo_t type
 *
 ********************************************************************/

#include "globus_common_include.h"
#include "globus_fifo.h"
#include "globus_cfifo.h"
#include "globus_libc.h"


#define GLOBUS_CFIFO_BLOCKSIZE  500


typedef struct globus_cfifo_block_s {
  int head;
  int tail;
  char data[GLOBUS_CFIFO_BLOCKSIZE];
} globus_cfifo_block_t;


int
globus_cfifo_init (globus_cfifo_t * fifo)
{
  return globus_fifo_init (fifo);
}

extern void
globus_cfifo_destroy (globus_cfifo_t * fifo)
{
  if (fifo!=GLOBUS_NULL) {
    while (! globus_fifo_empty (fifo)) {
      globus_cfifo_block_t * block;
      block = ((globus_cfifo_block_t *) globus_fifo_dequeue (fifo));
      globus_free (block);
    }
  }
}

extern int 
globus_cfifo_empty (globus_cfifo_t * fifo)
{
  assert (fifo!=GLOBUS_NULL);

  return globus_fifo_empty (fifo);
}

extern int 
globus_cfifo_size (globus_cfifo_t * fifo)
{
  int blockcount;
  globus_cfifo_block_t * block;

  assert (fifo!=GLOBUS_NULL);

  blockcount = globus_fifo_size (fifo);

  if ( blockcount == 0 ) {
    return 0;
  }
  else if ( blockcount == 1 ) {
    block = (globus_cfifo_block_t *) globus_fifo_peek (fifo);
    return (block->tail - block->head);
  }
  else {
    int headsize, tailsize;

    block = (globus_cfifo_block_t *) globus_fifo_peek (fifo);
    headsize = (block->tail - block->head);

    block = (globus_cfifo_block_t *) globus_fifo_tail_peek (fifo);
    tailsize = (block->tail - block->head);

    return (headsize + tailsize 
	    + ((blockcount - 2) * GLOBUS_CFIFO_BLOCKSIZE));
  }
}

extern int
globus_cfifo_enqueue (globus_cfifo_t * fifo,
		      char             datum)
{
  globus_cfifo_block_t * block;

  if ( fifo==NULL ) return GLOBUS_FAILURE;

  if ( ( ! globus_fifo_empty (fifo) ) &&
       ((block = (globus_cfifo_block_t *) globus_fifo_tail_peek (fifo))
	->tail < GLOBUS_CFIFO_BLOCKSIZE ) ) {
    /* there is room in the existing insertion block */
    block->data[block->tail] = datum;
    block->tail += 1;

    return GLOBUS_SUCCESS;
  }
  
  /* insert a new block */
  block = ((globus_cfifo_block_t *) 
	   globus_malloc (sizeof (globus_cfifo_block_t)));
  block->head = 0;
  block->tail = 1;
  block->data[0] = datum;
  return globus_fifo_enqueue (fifo, (void *) block);
}

extern char
globus_cfifo_peek (globus_cfifo_t * fifo)
{
  globus_cfifo_block_t * block;

  assert (fifo!=GLOBUS_NULL);
  assert (! globus_fifo_empty (fifo));

  block = (globus_cfifo_block_t *) globus_fifo_peek (fifo);

  return block->data[block->head];
}

extern char
globus_cfifo_tail_peek (globus_cfifo_t * fifo)
{
  globus_cfifo_block_t * block;

  assert (fifo!=GLOBUS_NULL);
  assert (! globus_fifo_empty (fifo));

  block = (globus_cfifo_block_t *) globus_fifo_tail_peek (fifo);

  return block->data[(block->tail)-1];
}

extern char
globus_cfifo_dequeue (globus_cfifo_t *fifo)
{
  globus_cfifo_block_t * block;
  char datum;

  assert (fifo!=GLOBUS_NULL);

  if ( globus_fifo_empty (fifo) ) return '\0';

  block = (globus_cfifo_block_t *) globus_fifo_peek (fifo);
  datum = block->data[block->head];
  block->head += 1;

  if ( block->head >= block->tail ) {
    globus_free (block);
    globus_fifo_dequeue (fifo);
  }

  return datum;
}





