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

/******************************************************************************
globus_common.c

Description:

  Routines common to all of Globus

CVS Information:

******************************************************************************/

/******************************************************************************
			     Include header files
******************************************************************************/
#include "globus_common_include.h"
#include "globus_thread_common.h"
#include "globus_i_thread.h"
#include "version.h"
#include "globus_libc.h"
#include "globus_callback.h"
#include "globus_libc.h"
#include "globus_print.h"
#include "globus_common.h"

#define THREAD_STACK_INIT_SIZE 32

typedef struct globus_l_thread_stack_node_s
{
    globus_thread_blocking_func_t  func;
    void *                         user_args;
    globus_callback_space_t        space;
    globus_bool_t                  enabled;

} globus_l_thread_stack_node_t;

typedef struct globus_l_thread_stack_manager
{
    globus_l_thread_stack_node_t *        stack;
    int                                   max;
    int                                   top;

} globus_l_thread_stack_manager_t;


static int
globus_l_thread_common_activate(void);

static int
globus_l_thread_common_deactivate(void);

static void 
globus_l_thread_blocking_callback_destroy(void* p);

#if !defined(TARGET_ARCH_WIN32) || defined(BUILD_LITE)
static globus_thread_key_t              l_thread_stack_key  = GLOBUS_NULL;
#else
static globus_thread_key_t              l_thread_stack_key  =
{ 0, NULL }; // is this type of initialization necessary for Windows???
#endif
static globus_bool_t                    globus_l_mod_active = GLOBUS_FALSE;

globus_module_descriptor_t              globus_i_thread_common_module =
{
   "globus_thread_common",
    globus_l_thread_common_activate,
    globus_l_thread_common_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};       

static globus_l_thread_stack_manager_t *
globus_l_thread_blocking_callback_init()
{
   globus_l_thread_stack_manager_t *         manager; 

   manager = (globus_l_thread_stack_manager_t *)
		globus_malloc(sizeof(globus_l_thread_stack_manager_t));

   manager->top = -1;
   manager->max = THREAD_STACK_INIT_SIZE;
   manager->stack = (globus_l_thread_stack_node_t *)
		      globus_malloc(sizeof(globus_l_thread_stack_node_t) *
		      THREAD_STACK_INIT_SIZE);

   return manager;
}



void
globus_i_thread_report_bad_rc(int rc,
			      char *message )
{
    char achMessHead[] = "[Thread System]";
    char achDesc[GLOBUS_L_LIBC_MAX_ERR_SIZE];
    
    if(rc != GLOBUS_SUCCESS)
    {
	switch( rc )
	{
	case EAGAIN:
	    strcpy(achDesc, _GCSL("system out of resources (EAGAIN)"));
	    break;
	case ENOMEM:
	    strcpy(achDesc, _GCSL("insufficient memory (ENOMEM)"));
	    break;
	case EINVAL:
	    strcpy(achDesc, _GCSL("invalid value passed to thread interface (EINVAL)"));
	    break;
	case EPERM:
	    strcpy(achDesc, _GCSL("user does not have adequate permission (EPERM)"));
	    break;
	case ERANGE:
	    strcpy(achDesc, _GCSL("a parameter has an invalid value (ERANGE)"));
	    break;
	case EBUSY:
	    strcpy(achDesc, _GCSL("mutex is locked (EBUSY)"));
	    break;
	case EDEADLK:
	    strcpy(achDesc, _GCSL("deadlock detected (EDEADLK)"));
	    break;
	case ESRCH:
	    strcpy(achDesc, _GCSL("could not find specified thread (ESRCH)"));
	    break;
	default:
	    globus_fatal(_GCSL("%s %s\n%s unknown error number: %d\n"),
				  achMessHead,
				  message,
				  achMessHead,
				  rc);
	    break;
	}
	globus_fatal("%s %s\n%s %s",
			      achMessHead,
			      message,
			      achMessHead,
			      achDesc);
    }
} /* globus_i_thread_report_bad_rc() */


/*
 *
 */
int
globus_thread_blocking_space_callback_push(
    globus_thread_blocking_func_t       func,
    void *                              user_args,
    globus_callback_space_t             space,
    globus_thread_callback_index_t *    i)
{
   globus_l_thread_stack_node_t *            n;
   globus_l_thread_stack_manager_t *         manager; 

   if(!globus_l_mod_active)
   {
       return GLOBUS_FAILURE;
   }

   /*
    *  If module not yet activated return -1
    */

   manager = (globus_l_thread_stack_manager_t *)
		       globus_thread_getspecific(l_thread_stack_key);
   /*
    *  If first time push is called on this thread create a new 
    *  manager structure.
    */
   if(manager == NULL)
   {
       manager = globus_l_thread_blocking_callback_init();
   }

   manager->top = manager->top + 1;
   n = &(manager->stack[manager->top]);

   n->func = func;
   n->user_args = user_args;
   n->space = space;
   n->enabled = GLOBUS_TRUE;

   if(i != NULL)
   {
       *i = manager->top;
   }
   if(manager->top >= manager->max - 1)
   {
       manager->max += THREAD_STACK_INIT_SIZE;
       manager->stack = (globus_l_thread_stack_node_t *)
       realloc((void*)manager->stack, 
                    sizeof(globus_l_thread_stack_node_t) * manager->max);
	   
   }
   globus_thread_setspecific(l_thread_stack_key,
			         (void *)manager);

   return GLOBUS_SUCCESS;
}

/*
 *
 */
int
globus_thread_blocking_callback_pop(
    globus_thread_callback_index_t * i)
{
   globus_l_thread_stack_manager_t *       manager; 
   
   /*
    *  If module not yet activated return -1
    */
   if(!globus_l_mod_active)
   {
       return GLOBUS_FAILURE;
   }
   
       manager = (globus_l_thread_stack_manager_t *)
  		          globus_thread_getspecific(l_thread_stack_key);

       if(manager == NULL ||
          manager->top < 0)
       {
           return GLOBUS_FAILURE;
       }

       if(i != NULL)
       {
           *i = manager->top;
       }
       manager->top--;

   return GLOBUS_SUCCESS;
}

/*
 *
 */
int
globus_thread_blocking_callback_enable(
    globus_thread_callback_index_t * i)
{
    globus_l_thread_stack_manager_t *       manager; 
   
    /*
     *  If module not yet activated return -1
     */
    if(!globus_l_mod_active)
    {
        return GLOBUS_FAILURE;
    }
   
    manager = (globus_l_thread_stack_manager_t *)
		       globus_thread_getspecific(l_thread_stack_key);

    if(manager == NULL)
    {
	return GLOBUS_FAILURE;
    }

    if(*i <= manager->top)
    {
        manager->stack[*i].enabled = GLOBUS_TRUE;
    }

    return GLOBUS_SUCCESS;
}

void
globus_thread_blocking_reset()
{
    globus_l_thread_stack_manager_t *       manager; 

    manager = (globus_l_thread_stack_manager_t *)
		       globus_thread_getspecific(l_thread_stack_key);
    globus_l_thread_blocking_callback_destroy(manager);
}

/*
 *
 */
int
globus_thread_blocking_callback_disable(
					globus_thread_callback_index_t * i)
{
    globus_l_thread_stack_manager_t *  manager; 
   
    /*
     *  If module not yet activated return -1
     */
    if(!globus_l_mod_active)
    {
        return GLOBUS_FAILURE;
    }
   
    manager = (globus_l_thread_stack_manager_t *)
		       globus_thread_getspecific(l_thread_stack_key);

    if(manager == NULL)
    {
	return GLOBUS_FAILURE;
    }

    if(*i <= manager->top)
    {
        manager->stack[*i].enabled = GLOBUS_FALSE;
    }

    return GLOBUS_TRUE;
}

/*
 *
 */
int
globus_thread_blocking_space_will_block(
    int                                 blocking_space)
{
    int                                       ctr;
    globus_thread_blocking_func_t             func;
    globus_l_thread_stack_manager_t *         manager; 

    
    /*
     *  If module not yet activated return -1
     */
    if(!globus_l_mod_active)
    {
        return GLOBUS_FAILURE;
    }

    manager = (globus_l_thread_stack_manager_t *)
		       globus_thread_getspecific(l_thread_stack_key);

    if(manager == NULL)
    {
        return GLOBUS_FAILURE;
    }

    for(ctr = manager->top;  ctr >= 0; ctr--)
    {
       if(manager->stack[ctr].enabled && 
        (manager->stack[ctr].space == GLOBUS_CALLBACK_GLOBAL_SPACE ||
            manager->stack[ctr].space == blocking_space))
       {
           func =  (manager->stack[ctr].func);
	   func(ctr, blocking_space, manager->stack[ctr].user_args);
       }
    }

    return GLOBUS_SUCCESS;
}

int
globus_l_thread_common_activate(void)
{
    int rc;

    /* 
     * safely initialize ICU library w/ threads
     */

    rc = globus_thread_key_create(&l_thread_stack_key,
			          globus_l_thread_blocking_callback_destroy);

    if(rc == 0)
    {
        globus_l_mod_active  = GLOBUS_TRUE;
    }
    return rc;
}

int
globus_l_thread_common_deactivate(void)
{
    return GLOBUS_SUCCESS;
}

static void 
globus_l_thread_blocking_callback_destroy(void* p)
{
     globus_l_thread_stack_manager_t * manager = 
             (globus_l_thread_stack_manager_t*)p;
 
     if(!manager)
       return;
     free(manager->stack);
     free(manager);
    globus_thread_setspecific(l_thread_stack_key,
                                 (void *)GLOBUS_NULL);
}

/* This function contains non-portable code and won't compile
 * directly on Windows.
 *
 * Michael Lebman
 * 5-28-02
 */
#ifndef TARGET_ARCH_WIN32

void thread_print(char * s, ...)
{
    char tmp[1023];
    int x;
    va_list ap;
    pid_t   pid = getpid();
    
#ifdef HAVE_STDARG_H
        va_start(ap, s);
#else
	va_start(ap);
#endif

#if !defined(BUILD_LITE)
    sprintf(tmp, "p#%dt#%ld::", pid, (long)globus_thread_self());
    x = strlen(tmp);
    vsprintf(&tmp[x], s, ap);

    globus_libc_printf(tmp);
    globus_thread_yield();
#else
    sprintf(tmp, "p#%dt#main::", pid);
    x = strlen(tmp);
    vsprintf(&tmp[x], s, ap);
    printf(tmp);
#endif
   
    fflush(stdin);
}

#endif

/*
 *  not found in win32
 */
#ifndef TARGET_ARCH_WIN32

int
globus_i_thread_ignore_sigpipe(void)
{
#ifdef HAVE_SIGACTION
    struct sigaction act;
    struct sigaction oldact;
    int rc;
    int save_errno;

    memset(&oldact, '\0', sizeof(struct sigaction));

    do
    {
        rc = sigaction(SIGPIPE, GLOBUS_NULL, &oldact);
	save_errno = errno;
    } while(rc < 0 && save_errno == EINTR);

    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }
    else if(oldact.sa_handler != SIG_DFL)
    {
	return GLOBUS_SUCCESS;
    }
    else
    {
        memset(&act, '\0', sizeof(struct sigaction));
        sigemptyset(&(act.sa_mask));
        act.sa_handler = SIG_IGN;
        act.sa_flags = 0;

        return sigaction(SIGPIPE, &act, GLOBUS_NULL);
    }
#else
    return GLOBUS_SUCCESS;
#endif
}
/* globus_i_thread_ignore_sigpipe() */

#endif


