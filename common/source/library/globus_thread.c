/*
 * Copyright 1999-2010 University of Chicago
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

/**
 * @file globus_thread_none.h Globus Threading Abstraction
 *
 * @details
 *
 * Stubs for the Globus threads package, to be used when Globus has been
 * configured not to use threads.
 *
 * CVS Information:
 *
 * $Source$
 * $Date$
 * $Revision$
 * $State$
 * $Author$
 */

#include "globus_thread.h"
#include "ltdl.h"
extern globus_module_descriptor_t globus_i_thread_none_module;

static
int
globus_l_thread_activate(void);

static
int
globus_l_thread_deactivate(void);

extern globus_mutex_t                   globus_libc_mutex;
static globus_thread_impl_t *           globus_l_thread_impl;
static globus_thread_impl_t *           globus_l_activated_thread_impl;
static globus_module_descriptor_t *     globus_l_thread_impl_module;

static char                             globus_l_thread_model[16] = "";

globus_module_descriptor_t              globus_i_thread_module =
{
    "globus_thread",
    globus_l_thread_activate,
    globus_l_thread_deactivate
};


extern
int
globus_thread_set_model(
    const char *                        model)
{
    if (model == NULL)
    {
        return GLOBUS_FAILURE;
    }

    if (globus_l_thread_impl != NULL)
    {
        return GLOBUS_FAILURE;
    }

    strncpy(globus_l_thread_model, model, sizeof(globus_l_thread_model));
    globus_l_thread_model[sizeof(globus_l_thread_model)-1] = 0;

    return GLOBUS_SUCCESS;
}
/* globus_thread_set_model() */

static
int
globus_l_thread_activate(void)
{
    return globus_module_activate(globus_l_thread_impl_module);
}

static
int
globus_l_thread_deactivate(void)
{
    return globus_module_deactivate(globus_l_thread_impl_module);
}

extern
int
globus_i_thread_pre_activate(void)
{
    char *                              impl_name;
    const char                          format[] = "libglobus_thread_%s.la";
    lt_dlhandle                         impl_lib;
    globus_thread_impl_t *              impl;

    lt_dlinit();

    if (globus_l_thread_model[0] == 0)
    {
        char *                          model;

        model = getenv("GLOBUS_THREAD_MODEL");

        if (model)
        {
            strncpy(globus_l_thread_model, model, sizeof(globus_l_thread_model));
            globus_l_thread_model[sizeof(globus_l_thread_model)-1] = 0;
        }
    }
    if (globus_l_thread_model[0] == 0)
    {
        strncpy(globus_l_thread_model, "none", sizeof(globus_l_thread_model));
    }
    if (strcmp(globus_l_thread_model, "none") != 0)
    {
        impl_name = malloc(sizeof(format) + strlen(globus_l_thread_model) + 1);
        sprintf(impl_name, format, globus_l_thread_model);

        impl_lib = lt_dlopen(impl_name);
        if (impl_lib == NULL)
        {
            printf("dlopen %s: %s\n", impl_name, lt_dlerror());
            exit(1);
        }
        globus_assert(impl_lib != NULL);

        globus_l_thread_impl_module = lt_dlsym(impl_lib, "globus_extension_module");
        if (globus_l_thread_impl_module == NULL)
        {
            printf("dlsym: %s\n", lt_dlerror());
            exit(1);
        }
        globus_assert(globus_l_thread_impl_module != NULL);
    }
    else
    {
        globus_l_thread_impl_module = &globus_i_thread_none_module;
    }

    impl = globus_l_thread_impl_module->get_pointer_func();
    globus_assert(impl != NULL);

    globus_l_thread_impl = impl;

    globus_l_activated_thread_impl = globus_l_thread_impl;

    globus_l_thread_impl->thread_pre_activate();

    globus_mutex_init(&globus_libc_mutex, NULL);

    return 0;
}

extern
int
globus_mutex_init(
    globus_mutex_t *                    mutex,
    globus_mutexattr_t *                attr)
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->mutex_init)
    {
        rc = globus_l_thread_impl->mutex_init(mutex, attr);
    }

    return rc;
}
/* globus_mutex_init() */

extern
int
globus_mutex_destroy(
    globus_mutex_t *                    mutex)
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->mutex_destroy)
    {
        rc = globus_l_thread_impl->mutex_destroy(mutex);
    }

    return rc;
}
/* globus_mutex_destroy() */

extern
int
globus_mutex_lock(
    globus_mutex_t *                    mutex)
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->mutex_lock)
    {
        rc = globus_l_thread_impl->mutex_lock(mutex);
    }

    return rc;
}
/* globus_mutex_lock() */

extern
int
globus_mutex_unlock(
    globus_mutex_t *                    mutex)
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->mutex_unlock)
    {
        rc = globus_l_thread_impl->mutex_unlock(mutex);
    }

    return rc;
}
/* globus_mutex_unlock() */

extern
int
globus_mutex_trylock(
    globus_mutex_t *                    mutex)
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->mutex_trylock)
    {
        rc = globus_l_thread_impl->mutex_trylock(mutex);
    }

    return rc;
}
/* globus_mutex_trylock() */

extern
int
globus_cond_init(
    globus_cond_t *                     cond,
    globus_condattr_t *                 attr)
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->cond_init)
    {
        rc = globus_l_thread_impl->cond_init(cond, attr);
    }

    return rc;

}
/* globus_cond_init() */

extern
int
globus_cond_destroy(
    globus_cond_t *                     cond)
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->cond_destroy)
    {
        rc = globus_l_thread_impl->cond_destroy(cond);
    }

    return rc;

}
/* globus_cond_destroy() */

extern
int
globus_cond_wait(
    globus_cond_t *                     cond,
    globus_mutex_t *                    mutex)
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->cond_wait)
    {
        rc = globus_l_thread_impl->cond_wait(cond, mutex);
    }

    return rc;

}
/* globus_cond_wait() */

extern
int
globus_cond_timedwait(
    globus_cond_t *                     cond,
    globus_mutex_t *                    mutex,
    globus_abstime_t *                  abstime)
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->cond_timedwait)
    {
        rc = globus_l_thread_impl->cond_timedwait(cond, mutex, abstime);
    }

    return rc;
}
/* globus_cond_timedwait() */

extern int
globus_cond_signal(
    globus_cond_t *                     cond)
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->cond_signal)
    {
        rc = globus_l_thread_impl->cond_signal(cond);
    }

    return rc;
}
/* globus_cond_signal() */

extern
int
globus_cond_broadcast(
    globus_cond_t *                     cond)
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->cond_broadcast)
    {
        rc = globus_l_thread_impl->cond_broadcast(cond);
    }

    return rc;
}
/* globus_cond_broadcast() */

extern
int
globus_mutexattr_init(
    globus_mutexattr_t *                attr)
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->mutexattr_init)
    {
        rc = globus_l_thread_impl->mutexattr_init(attr);
    }

    return rc;
}
/* globus_mutexattr_init() */

extern
int
globus_mutexattr_destroy(
    globus_mutexattr_t *                attr)
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->mutexattr_destroy)
    {
        rc = globus_l_thread_impl->mutexattr_destroy(attr);
    }

    return rc;
}
/* globus_mutexattr_destroy() */

extern int
globus_condattr_init(
    globus_condattr_t *                 cond_attr)
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->condattr_init)
    {
        rc = globus_l_thread_impl->condattr_init(cond_attr);
    }

    return rc;
}
/* globus_condattr_init() */
    
extern int
globus_condattr_destroy(
    globus_condattr_t *                 cond_attr)
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->condattr_destroy)
    {
        rc = globus_l_thread_impl->condattr_destroy(cond_attr);
    }

    return rc;
}
/* globus_condattr_destroy() */

extern int
globus_condattr_setspace(
    globus_condattr_t *                 cond_attr,
    int                                 space)
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->condattr_setspace)
    {
        rc = globus_l_thread_impl->condattr_setspace(cond_attr, space);
    }

    return rc;
}
/* globus_condattr_setspace() */

extern int
globus_condattr_getspace(
    globus_condattr_t *                 cond_attr,
    int *                               space)
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->condattr_getspace)
    {
        rc = globus_l_thread_impl->condattr_getspace(cond_attr, space);
    }
    else
    {
        rc = 0;
    }

    return rc;
}
/* globus_condattr_getspace() */

extern
int
globus_thread_create(
    globus_thread_t *                   thread,
    globus_threadattr_t *               attr,
    globus_thread_func_t                func,
    void *                              user_arg)
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->thread_create)
    {
        rc = globus_l_thread_impl->thread_create(thread, attr, func, user_arg);
    }
    else
    {
        rc = EINVAL;
    }

    return rc;
}
/* globus_thread_create() */

extern
int
globus_thread_key_create(
    globus_thread_key_t *               key,
    globus_thread_key_destructor_func_t destructor)
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->thread_key_create)
    {
        rc = globus_l_thread_impl->thread_key_create(key, destructor);
    }

    return rc;
}
/* globus_thread_key_create() */

extern
int
globus_thread_key_delete(
    globus_thread_key_t                 key)
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->thread_key_delete)
    {
        rc = globus_l_thread_impl->thread_key_delete(key);
    }

    return rc;
}
/* globus_thread_key_delete() */

extern
int
globus_thread_once(
    globus_thread_once_t *              once,
    void                                (*init_routine)(void))
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->thread_once)
    {
        rc = globus_l_thread_impl->thread_once(once, init_routine);
    }
    else
    {
        rc = EINVAL;
    }

    return rc;
}
/* globus_thread_once() */

extern
void *
globus_thread_getspecific(
    globus_thread_key_t                 key)
{
    void *                              val = NULL;
    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->thread_getspecific)
    {
        val = globus_l_thread_impl->thread_getspecific(key);
    }

    return val;
}
/* globus_thread_getspecific() */

extern
int
globus_thread_setspecific(
    globus_thread_key_t                 key,
    void *                              value)
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->thread_setspecific)
    {
        rc = globus_l_thread_impl->thread_setspecific(key, value);
    }

    return rc;
}
/* globus_thread_setspecific() */

extern
void
globus_thread_yield(void)
{
    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->thread_yield)
    {
        globus_l_thread_impl->thread_yield();
    }
}
/* globus_thread_yield() */

extern
void
globus_thread_exit(
    void *                              value)
{
    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->thread_exit)
    {
        globus_l_thread_impl->thread_exit(value);
    }
}
/* globus_thread_exit() */

extern
int
globus_thread_sigmask(
    int                                 how,
    const sigset_t *                    new_mask,
    sigset_t *                          old_mask)
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->thread_sigmask)
    {
        rc = globus_l_thread_impl->thread_sigmask(how, new_mask, old_mask);
    }

    return rc;
}
/* globus_thread_sigmask() */

extern
int
globus_thread_kill(
    globus_thread_t                     thread,
    int                                 sig)
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->thread_kill)
    {
        rc = globus_l_thread_impl->thread_kill(thread, sig);
    }

    return rc;
}
/* globus_thread_kill() */

extern
globus_thread_t
globus_thread_self(void)
{
    globus_thread_t                     result;

    memset(&result, 0, sizeof(globus_thread_t));

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->thread_self)
    {
        result = globus_l_thread_impl->thread_self();
    }

    return result;
}
/* globus_thread_self() */

extern
globus_bool_t
globus_thread_equal(
    globus_thread_t                     thread1,
    globus_thread_t                     thread2)
{
    globus_bool_t                       result = GLOBUS_TRUE;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->thread_equal)
    {
        result = globus_l_thread_impl->thread_equal(thread1, thread2);
    }

    return result;
}
/* globus_thread_equal() */

extern
globus_bool_t
globus_thread_preemptive_threads(void)
{
    globus_bool_t                       result = GLOBUS_TRUE;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->preemptive_threads)
    {
        result = globus_l_thread_impl->preemptive_threads();
    }

    return result;
}
/* globus_thread_preemptive_threads() */

extern
globus_bool_t
globus_i_am_only_thread(void)
{
    globus_bool_t                       result = GLOBUS_TRUE;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->i_am_only_thread)
    {
        result = globus_l_thread_impl->i_am_only_thread();
    }

    return result;
}

extern
void *
globus_thread_cancellable_func(
    void *                              (*func)(void *),
    void *                              arg,
    void                                (*cleanup_func)(void *),
    void *                              cleanup_arg,
    globus_bool_t                       execute_cleanup)
{
    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);
    if (globus_l_thread_impl->thread_cancellable_func)
    {
        return globus_l_thread_impl->thread_cancellable_func(
                func, arg, cleanup_func, cleanup_arg, execute_cleanup);
    }
    else
    {
        return NULL;
    }
}

extern
int
globus_thread_cancel(globus_thread_t thr)
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->thread_cancel)
    {
        rc = globus_l_thread_impl->thread_cancel(thr);
    }

    return rc;
}

extern
void
globus_thread_testcancel(void)
{
    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->thread_testcancel)
    {
        globus_l_thread_impl->thread_testcancel();
    }
}

extern
int
globus_thread_setcancelstate(
    int                                 state,
    int *                               oldstate)
{
    int                                 rc = 0;

    globus_assert(globus_l_thread_impl == globus_l_activated_thread_impl);

    if (globus_l_thread_impl->thread_setcancelstate)
    {
        rc = globus_l_thread_impl->thread_setcancelstate(state, oldstate);
    }

    return rc;
}
