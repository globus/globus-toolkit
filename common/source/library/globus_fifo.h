
#ifndef GLOBUS_COMMON_FIFO_H
#define GLOBUS_COMMON_FIFO_H

/********************************************************************
 *
 * This file defines the globus_fifo_t type
 * useful for queuing arbitrary data (via void-pointer)
 *
 ********************************************************************/

#include "globus_list.h"


#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif
 
EXTERN_C_BEGIN

typedef struct globus_fifo_s {
  globus_list_t * volatile head;
  globus_list_t * volatile tail;
} globus_fifo_t;

extern int
globus_fifo_init (globus_fifo_t * fifo);

extern void
globus_fifo_destroy (globus_fifo_t * fifo);

extern int 
globus_fifo_empty (const globus_fifo_t * fifo);

extern int 
globus_fifo_size (globus_fifo_t *fifo);

extern int
globus_fifo_enqueue (globus_fifo_t * fifo,
		     void          * datum);

extern globus_fifo_t *
globus_fifo_copy (globus_fifo_t * fifo);

extern void *
globus_fifo_peek (globus_fifo_t * fifo);

extern void *
globus_fifo_tail_peek (globus_fifo_t * fifo);

extern void *
globus_fifo_remove (globus_fifo_t *headp, void *datum);

extern void *
globus_fifo_dequeue (globus_fifo_t *fifo);

extern int
globus_fifo_move(
    globus_fifo_t *				fifo_dest,
    globus_fifo_t *				fifo_src);
    

EXTERN_C_END

#endif /* GLOBUS_COMMON_FIFO_H */
