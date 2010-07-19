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

/********************************************************************
 *
 * This file implements the fifo_t type
 *
 ********************************************************************/

#include "globus_common_include.h"

#include "globus_fifo.h"
#include "globus_list.h"
#include "globus_libc.h"

/*
 * internal structure is hidden from user 
 */
struct globus_fifo_s 
{
    globus_list_t * volatile                    head;
    globus_list_t * volatile                    tail;
	unsigned long								size;
};

int
globus_fifo_init (globus_fifo_t * fifo)
{
    struct globus_fifo_s *                      s_fifo;
    
    if (fifo==GLOBUS_NULL) return -1;

    s_fifo = (struct globus_fifo_s *)globus_malloc(sizeof(struct globus_fifo_s));
    *fifo = s_fifo;
    
    s_fifo->head = GLOBUS_NULL;
    s_fifo->tail = GLOBUS_NULL;
	s_fifo->size = 0;

    return 0;
}

void
globus_fifo_destroy ( globus_fifo_t * fifo)
{
    struct globus_fifo_s * s_fifo;
    
    if (fifo == GLOBUS_NULL) 
    {
        return;
    }
    
    s_fifo = *fifo;
    globus_list_free (s_fifo->head);
    s_fifo->head = GLOBUS_NULL;
    s_fifo->tail = GLOBUS_NULL;
    s_fifo->size = 0;
    
    globus_free(s_fifo);
}

void
globus_fifo_destroy_all(
    globus_fifo_t *                     fifo,
    void                                (*datum_free)(void *))
{
    struct globus_fifo_s *              s_fifo;
    
    if (fifo == GLOBUS_NULL) 
    {
        return;
    }
    
    s_fifo = *fifo;
    globus_list_destroy_all(s_fifo->head, datum_free);
    s_fifo->head = GLOBUS_NULL;
    s_fifo->tail = GLOBUS_NULL;
    s_fifo->size = 0;
    
    globus_free(s_fifo);
}

int 
globus_fifo_empty ( const globus_fifo_t * fifo)
{
    struct globus_fifo_s * s_fifo;

    assert (fifo!=GLOBUS_NULL);
    s_fifo = *fifo;
    
    return s_fifo->head==GLOBUS_NULL;
}

int 
globus_fifo_size( const globus_fifo_t * fifo)
{
    struct globus_fifo_s *                          s_fifo;
    
    assert (fifo!=GLOBUS_NULL);
    s_fifo = *fifo;
    
    return s_fifo->size;
}

int
globus_fifo_enqueue(
    globus_fifo_t *                                 fifo,
    void *                                          datum)
{
    int                                             err;
    struct globus_fifo_s *                          s_fifo;

    if (fifo==GLOBUS_NULL) 
		return -1;
    s_fifo = *fifo;
    if(s_fifo==GLOBUS_NULL) 
		return -1;

    if(s_fifo->tail==GLOBUS_NULL) 
    {
        err = globus_list_insert (
                (globus_list_t **) &(s_fifo->tail), 
			    datum);
        s_fifo->head = s_fifo->tail;
    }
    else 
    {
        err = globus_list_insert (globus_list_rest_ref (s_fifo->tail),
			      datum);
  
        s_fifo->tail = globus_list_rest (s_fifo->tail);
    }
	if(!err)
	{
		s_fifo->size++;
	}

    return err;
}

globus_fifo_t *
globus_fifo_copy (
    const globus_fifo_t *                                 fifo)
{
    globus_fifo_t *                                 copy;
    struct globus_fifo_s *                          s_copy;
    struct globus_fifo_s *                          s_fifo;

    if (fifo == GLOBUS_NULL) 
		return NULL;
    s_fifo = *fifo;
    if(s_fifo==GLOBUS_NULL) 
		return NULL;

    copy = globus_malloc (sizeof(globus_fifo_t));
    if (copy == NULL) 
		return NULL;

    globus_fifo_init(copy);

    s_copy = *copy;
    s_copy->head = globus_list_copy(s_fifo->head);
    s_copy->tail = s_copy->head;

    while(!globus_list_empty(globus_list_rest(s_copy->tail))) 
    {
        s_copy->tail = globus_list_rest (s_copy->tail);
    }
 
	s_copy->size = s_fifo->size;
	return copy;
}

void *
globus_fifo_peek (
    globus_fifo_t *                                 fifo)
{
    struct globus_fifo_s *                          s_fifo;
    
    assert(fifo != GLOBUS_NULL);
    s_fifo = *fifo;
    assert(s_fifo != GLOBUS_NULL);
    assert(!globus_list_empty(s_fifo->head));

    return globus_list_first(s_fifo->head);
}

void *
globus_fifo_tail_peek(
    globus_fifo_t *                                 fifo)
{
    struct globus_fifo_s *                          s_fifo;
    
    assert(fifo != GLOBUS_NULL);
    s_fifo = *fifo;
    assert(s_fifo != GLOBUS_NULL);
    assert(!globus_list_empty(s_fifo->tail));

    return globus_list_first(s_fifo->tail);
}

void *
globus_fifo_dequeue(    
    globus_fifo_t *                                 fifo)
{
    void *                                          datum;
    struct globus_fifo_s *                          s_fifo;
    
    assert(fifo != GLOBUS_NULL);
    s_fifo = *fifo;
    assert(s_fifo != GLOBUS_NULL);

    if(globus_list_empty(s_fifo->head)) 
		return GLOBUS_NULL;

    datum = globus_list_remove ((globus_list_t **) &(s_fifo->head), 
			      (globus_list_t *) s_fifo->head);

    if(globus_list_empty (s_fifo->head)) 
    {
        s_fifo->tail = s_fifo->head;
    }

	s_fifo->size--;
  
	return datum;
}

void *
globus_fifo_remove(
    globus_fifo_t *                                 fifo, 
    void *                                          datum)
{
    globus_list_t *                                 iter_prev;
    globus_list_t *                                 iter;
    struct globus_fifo_s *                          s_fifo;
    
    assert(fifo != GLOBUS_NULL);
    s_fifo = *fifo;
    assert(s_fifo != GLOBUS_NULL);

    if(globus_list_empty(s_fifo->head)) 
		return GLOBUS_NULL;

    iter_prev = GLOBUS_NULL;
    iter = s_fifo->head;
    while((!globus_list_empty(iter))
	  && (globus_list_first(iter) != datum)) 
	{
        iter_prev = iter;
        iter = globus_list_rest(iter);
    }

    if(!globus_list_empty(iter)) 
    {
        /* iter is the element to remove, iter_prev is the previous */
        if(iter == s_fifo->tail) 
        {
            /* make sure tail doesn't dangle */
            s_fifo->tail = iter_prev;
        }
        globus_list_remove (&(s_fifo->head), iter);

		s_fifo->size--;
        return datum;
    }
    else
    {
        return GLOBUS_NULL;
    }
}

int
globus_fifo_move(
    globus_fifo_t *				                    fifo_dest,
    globus_fifo_t *				                    fifo_src)
{
    struct globus_fifo_s *                          s_fifo_dest;
    struct globus_fifo_s *                          s_fifo_src;

	if(fifo_dest == GLOBUS_NULL || fifo_src == GLOBUS_NULL)
    {
        return -1;
    }
    globus_fifo_init(fifo_dest);
    s_fifo_dest = *fifo_dest;
    s_fifo_src = *fifo_src;
    if(s_fifo_dest == GLOBUS_NULL || s_fifo_src == GLOBUS_NULL)
    {
        return -1;
    }

    s_fifo_dest->head = s_fifo_src->head;
    s_fifo_dest->tail = s_fifo_src->tail;
    s_fifo_dest->size = s_fifo_src->size;

    s_fifo_src->head = GLOBUS_NULL;
    s_fifo_src->tail = GLOBUS_NULL;
    s_fifo_src->size = 0;

    return 0;
}

globus_list_t *
globus_fifo_convert_to_list(
	globus_fifo_t *    fifo )
{
    struct globus_fifo_s *              s_fifo;
    globus_list_t *                     list;
    
    assert(fifo != GLOBUS_NULL);
    s_fifo = *fifo;
    assert(s_fifo != GLOBUS_NULL);

    list = s_fifo->head;
    s_fifo->head = GLOBUS_NULL;
    s_fifo->tail = GLOBUS_NULL;
    s_fifo->size = 0;
    
    return list;
}
