/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#include "globus_common.h"
#include "globus_thread_common.h"

static globus_memory_t                   mem;

#define MEM_INIT_SIZE      15
#ifndef TARGET_ARCH_WIN32
#define POPS               100000
#else
#define POPS                 1000
#endif

typedef struct mem_test_s
{
    char a;
    char b;
    char c;
    char x[4];
    
} mem_test_t;

int mem_init(mem_test_t * m, int cnt);

void dump(globus_byte_t * buf, int size);

int main(int argc, char * argv[])
{
   int                         rc = GLOBUS_SUCCESS;
   mem_test_t *                mem_ptr[POPS];
   int                         cnt = 0;

   globus_module_activate(GLOBUS_COMMON_MODULE);

   globus_memory_init(&mem,
		      sizeof(mem_test_t),
		      MEM_INIT_SIZE);

   for(cnt = 0; cnt < POPS; cnt++)
   {
       mem_ptr[cnt] = ( mem_test_t *) globus_memory_pop_node(&mem); 
       mem_init(mem_ptr[cnt], cnt);
   }

   /* nodes are aligned on mod 8 boundaries, add 1 to 7 to make 8 */
   dump((globus_byte_t *) mem_ptr[0], MEM_INIT_SIZE * (sizeof(mem_test_t) + 1));
   
   globus_memory_push_node(&mem, (globus_byte_t *)mem_ptr[0]);
   
   for(cnt = 1; cnt < POPS; cnt++)
   {
       globus_memory_push_node(&mem, (globus_byte_t *) mem_ptr[cnt]);
   }

   globus_memory_destroy(&mem);

   globus_module_deactivate(GLOBUS_COMMON_MODULE);

   return rc;
}

int
mem_init(mem_test_t * m, int cnt)
{
    memset(m, 0, sizeof(mem_test_t) + 1);
    m->a = 'a';
    m->b = 'b';
    m->c = 'c';
 
    return GLOBUS_TRUE;
}

void dump(globus_byte_t * buf, int size)
{
    int  ctr;
    int  col = 0;
    
    printf("printing %d bytes\n", size);
    printf("\n    ....+....1....+....2....+....3....+....4\n    ");
    for(ctr = 0; ctr < size; ctr++)
    {
	printf("%c", isprint(buf[ctr]) ? buf[ctr] : '.');
	col++;
        if(col >= 40)
	{
            printf("\n    ");
	    col = 0;
	}
    }
    printf("\n");
}
