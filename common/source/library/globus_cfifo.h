#ifndef GLOBUS_COMMON_CFIFO_H
#define GLOBUS_COMMON_CFIFO_H

/********************************************************************
 *
 * This file defines the globus_fifo_t type
 * useful for queuing character data efficiently
 *
 ********************************************************************/

#include "globus_fifo.h"


EXTERN_C_BEGIN

typedef globus_fifo_t globus_cfifo_t;

extern int
globus_cfifo_init (globus_cfifo_t * fifo);

extern void
globus_cfifo_destroy (globus_cfifo_t * fifo);

extern int 
globus_cfifo_empty (globus_cfifo_t * fifo);

extern int 
globus_cfifo_size (globus_cfifo_t *fifo);

extern int
globus_cfifo_enqueue (globus_cfifo_t * fifo,
		      char             datum);

extern char
globus_cfifo_peek (globus_cfifo_t * fifo);

extern char
globus_cfifo_tail_peek (globus_cfifo_t * fifo);

extern char
globus_cfifo_dequeue (globus_cfifo_t *fifo);


EXTERN_C_END

#endif /* GLOBUS_COMMON_CFIFO_H */


