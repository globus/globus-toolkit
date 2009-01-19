#include "globus_states.h"

globus_extension_registry_t      globus_i_state_diagram_registry;

#ifdef __GNUC__
#define GlobusStateName(func) static const char * _state_name __attribute__((__unused__)) = #func
#else
#define GlobusStateName(func) static const char * _state_name = #func
#endif


#define GlobusStateErrorObjParameter(param_name)                            \
    globus_error_construct_error(                                           \
        GLOBUS_COMMON_MODULE,                                               \
        GLOBUS_NULL,                                                        \
        GLOBUS_STATE_ERROR_PARAMETER,                                       \
        __FILE__,                                                           \
        _state_name,                                                        \
        __LINE__,                                                           \
        "Bad parameter, %s",                                        \
        (param_name))

#define GlobusStateErrorParameter(param_name)                               \
    globus_error_put(                                                       \
        GlobusStateErrorObjParameter(param_name))

#define GlobusStateErrorObjTrans(_s1, _e1)                             \
    globus_error_construct_error(                                           \
        GLOBUS_COMMON_MODULE,                                               \
        GLOBUS_NULL,                                                        \
        GLOBUS_STATE_ERROR_INVALID_TRANSITION,                              \
        __FILE__,                                                           \
        _state_name,                                                        \
        __LINE__,                                                           \
        "Invalid transition: %s on event %s",                 \
        (_s1), (_e1))

#define GlobusStateErrorTrans(_s1, _e1)                             \
    globus_error_put(                                                       \
        GlobusStateErrorObjTrans(_s1, _e1))


typedef enum
{
    GLOBUS_STATE_ERROR_PARAMETER,
    GLOBUS_STATE_ERROR_INVALID_TRANSITION
} globus_xio_error_type_t;

typedef struct globus_state_entry_s
{
    int                                 next_state;
    globus_states_transition_function_t cb;
    char *                              desc;
    char *                              edge_name;
} globus_state_entry_t;

typedef struct globus_i_state_handle_s
{
    int                                 state_count;
    int                                 event_count;
    globus_state_entry_t ***            map;
    char **                             event_names;
    char **                             state_names;
} globus_i_state_handle_t;


int
globus_state_module_activate()
{
    return 0;
}

globus_result_t
globus_states_init(
    globus_state_handle_t *             out_handle,
    globus_states_init_function_t       init_func)
{
    globus_result_t                     result;
    globus_i_state_handle_t *           handle;

    handle = (globus_i_state_handle_t *) globus_calloc(
        1, sizeof(globus_i_state_handle_t));

    result = init_func(handle);

    *out_handle = handle;

    return result;
}

globus_result_t
globus_states_set_events(
    globus_state_handle_t               handle,
    int                                 state_count,
    int                                 event_count,
    char *                              reg_name,
    char **                             state_name,
    char **                             event_name)
{
    int                                 i;

    handle->map = globus_calloc(state_count, sizeof(globus_state_entry_t *));
    for(i = 0; i < state_count; i++)
    {
        handle->map[i] = globus_calloc(
            event_count, sizeof(globus_state_entry_t));   
    }
    handle->state_count = state_count;
    handle->event_count = event_count;
    handle->state_names = state_name;
    handle->event_names = event_name;

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_state_add_transition_real(
    globus_state_handle_t               in_handle,
    int                                 state,
    int                                 event,
    int                                 new_state,
    globus_states_transition_function_t cb,
    char *                              edge_name,
    char *                              desc)
{
    globus_state_entry_t *              ent;
    globus_i_state_handle_t *           handle;
    GlobusStateName(globus_state_add_transition_real);

    handle = (globus_i_state_handle_t *) in_handle;

    if(handle == NULL)
    {
        return GlobusStateErrorParameter("handle");
    }
    if(handle->state_count <= state)
    {
        return GlobusStateErrorParameter("state");
    }
    if(handle->event_count <= event)
    {
        return GlobusStateErrorParameter("event");
    }

    ent = (globus_state_entry_t *)
        globus_calloc(1, sizeof(globus_state_entry_t));

    ent->cb = cb;
    ent->next_state = new_state;
    ent->desc = globus_libc_strdup(desc);
    ent->edge_name = strdup(edge_name);

    handle->map[state][event] = ent;

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_state_handle_event_now(
    globus_state_handle_t               in_handle,
    int                                 state,
    int                                 event,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_i_state_handle_t *           handle;
    globus_state_entry_t *              ent;
    GlobusStateName(globus_state_transition);

    handle = (globus_i_state_handle_t *) in_handle;

    if(handle == NULL)
    {
        return GlobusStateErrorParameter("handle");
    }
    if(handle->state_count <= state)
    {
        return GlobusStateErrorParameter("state");
    }
    if(handle->event_count <= event)
    {
        return GlobusStateErrorParameter("event");
    }
    ent = (globus_state_entry_t *) handle->map[state][event];

    if(ent == NULL)
    {
        return GlobusStateErrorTrans(
            handle->state_names[state],
            handle->event_names[event]);
    }

    if(ent->cb)
    {
        result = ent->cb(ent->next_state, user_arg);
    }
    else
    {
        result = GLOBUS_SUCCESS;
    }

    return result;
}


globus_result_t
globus_state_transition(
    globus_state_handle_t               in_handle,
    int                                 state,
    int                                 event,
    void *                              user_arg,
    int *                               out_new_state)
{
    globus_result_t                     result;
    globus_i_state_handle_t *           handle;
    globus_state_entry_t *              ent;
    GlobusStateName(globus_state_transition);

    handle = (globus_i_state_handle_t *) in_handle;

    if(handle == NULL)
    {
        return GlobusStateErrorParameter("handle");
    }
    if(handle->state_count <= state)
    {
        return GlobusStateErrorParameter("state");
    }
    if(handle->event_count <= event)
    {
        return GlobusStateErrorParameter("event");
    }

    ent = (globus_state_entry_t *) handle->map[state][event];

    if(ent == NULL)
    {
        return GlobusStateErrorTrans(
            handle->state_names[state],
            handle->event_names[event]);
    }

    result = ent->cb(ent->next_state, user_arg);

    return result;
}

globus_result_t
globus_state_destroy(
    globus_state_handle_t               in_handle)
{
    globus_i_state_handle_t *           handle;

    handle = (globus_i_state_handle_t *) in_handle;

    globus_free(handle->map); 
    globus_free(handle); 

    return GLOBUS_SUCCESS;
}


globus_result_t
globus_state_make_graph(
    globus_state_handle_t               in_handle,
    const char *                        graph_fname,
    const char *                        txt_fname,
    int                                 flags,
    char *                              user_desc)
{
    int                                 i;
    int                                 j;
    globus_i_state_handle_t *           handle;
    globus_state_entry_t *              map;
    FILE *                              fptr;
    char *                              desc;
    char *                              delim;
    char *                              tmp_desc;
    int *                               done_a;
    int                                 count = 0;
    globus_list_t **                    list_array;
    int                                 done_ndx;
    int                                 str_ndx;
    globus_list_t *                     list;
    globus_bool_t                       std_out_f;

    if(strcmp(graph_fname, "-") == 0)
    {
        fptr = stdout;
        std_out_f = GLOBUS_TRUE;
    }
    else
    {
        std_out_f = GLOBUS_FALSE;
        fptr = fopen(graph_fname, "w");
        if(fptr == NULL)
        {
            return GLOBUS_SUCCESS;
        }
    }

    fprintf(fptr, "digraph {\n");

    handle = (globus_i_state_handle_t *) in_handle;
    done_a = (int *) globus_calloc(
        handle->state_count * handle->state_count+1, sizeof(int));
    list_array = (globus_list_t **) globus_calloc(
        handle->state_count*handle->state_count + 1,
        sizeof(globus_list_t *));

    for(i = 0; i < handle->state_count; i++)
    {
        for(j = 0; j < handle->event_count; j++)
        {
            map = handle->map[i][j];
            if(!map)
            {
                continue;
            }
            done_ndx = done_a[i*handle->state_count + map->next_state];
            str_ndx = done_ndx-1;
            if(str_ndx == -1)
            {
                done_a[i*handle->state_count + map->next_state] = count + 1;
                str_ndx = count;
                count++;
            }

            list = (globus_list_t * ) list_array[str_ndx];
            globus_list_insert(&list,
                globus_common_create_string("%s : %s",
                    handle->event_names[j], map->edge_name));
            list_array[str_ndx] = list;

            if(flags & GLOBUS_STATE_DIA_NO_DUPLICATES && done_ndx != 0)
            {
                continue;
            }

            fprintf(fptr, "%s -> %s ",
                handle->state_names[i],
                handle->state_names[map->next_state]);

            desc = globus_libc_strdup("");
            delim = "";
            if(flags & GLOBUS_STATE_DIA_NUMBER_LABELS)
            {
                tmp_desc = globus_common_create_string("label=\"%d\"",
                     count);
                globus_free(desc);
                desc = tmp_desc;
                delim = ",";
            } 
            else
            {
                if(flags & GLOBUS_STATE_DIA_EDGE_EVENT)
                {
                    tmp_desc = globus_common_create_string("label=\"%s\"",
                         map->edge_name);
                    globus_free(desc);
                    desc = tmp_desc;
                    delim = ",";
                }
                if(flags & GLOBUS_STATE_DIA_EDGE_FUNC)
                {
                    tmp_desc = globus_common_create_string("%s%slabel=\"%s\"",
                        desc, delim, handle->event_names[j]);
                    globus_free(desc);
                    desc = tmp_desc;
                    delim = ",";
                }
            }
            if(user_desc != NULL)
            {
                tmp_desc = globus_common_create_string("%s%s%s",
                    desc, delim, user_desc);
                globus_free(desc);
                desc = tmp_desc;
            }

            if(strcmp(desc, "") != 0)
            {
                tmp_desc = globus_common_create_string("[%s]",
                    desc);
                globus_free(desc);
                desc = tmp_desc;
            }

            fprintf(fptr, "%s;\n", desc);
            globus_free(desc);
        }
    }
    fprintf(fptr, "}\n");

    if(!std_out_f)
    {
        fclose(fptr);
    }

    if(txt_fname != NULL)
    {
        if(strcmp(txt_fname, "-") == 0)
        {
            std_out_f = GLOBUS_TRUE;
            fptr = stdout;
        }
        else
        {
            std_out_f = GLOBUS_FALSE;
            fptr = fopen(txt_fname, "w");
            if(fptr == NULL)
            {
                return GLOBUS_SUCCESS;
            }
        }

        for(i = 0; i < count-1; i++)
        {
            list = list_array[i];
            while(!globus_list_empty(list))   
            {
                char * tmp_str = (char *) globus_list_remove(&list, list);
                fprintf(fptr, "%d\t%s\n", i+1, tmp_str);
            }
        }

        /* print handled and unhandled events */
        for(i = 0; i < handle->state_count; i++)
        {
            fprintf(fptr, "%s\n", handle->state_names[i]);
            for(j = 0; j < handle->event_count; j++)
            {
                map = handle->map[i][j];
                if(map)
                {
                    fprintf(fptr, "\thandled: %s with %s\n",
                        handle->event_names[j], map->edge_name);
                }
                else
                {
                    fprintf(fptr, "\tUNHANDLED: %s\n", handle->event_names[j]);
                }
            }
        }


        if(!std_out_f)
        {
            fclose(fptr);
        }
    }

    return GLOBUS_SUCCESS;
}
