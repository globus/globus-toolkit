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

/**
 * @file globus_states.h
 * @brief State Machine
 */

#if !defined(GLOBUS_STATES_H)
#define GLOBUS_STATES_H 1

#include "globus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define globus_state_add_transition(_h, _s, _e, _ns, _cb, _d) \
globus_state_add_transition_real(_h, _s, _e, _ns, _cb, #_cb, _d)

extern globus_extension_registry_t      globus_i_state_diagram_registry;
#define GLOBUS_STATE_DIAGRAM_REGISTRY   &globus_i_state_diagram_registry

typedef struct globus_i_state_handle_s * globus_state_handle_t;

typedef 
globus_result_t
(*globus_states_transition_function_t)(
    int                                 new_state,
    void *                              user_arg);

typedef 
void
(*globus_states_transition_error_function_t)(
    int                                 new_state,
    void *                              user_arg);

typedef
globus_result_t
(*globus_states_init_function_t)(
    globus_state_handle_t               handle);

typedef struct globus_state_extension_handle_s
{
    globus_states_init_function_t       init_handler;
    char *                              name;
} globus_state_extension_handle_t;



typedef enum globus_state_dia_flags_e 
{
    GLOBUS_STATE_DIA_EDGE_EVENT = 1,
    GLOBUS_STATE_DIA_EDGE_FUNC = 2,
    GLOBUS_STATE_DIA_NO_DUPLICATES = 4,
    GLOBUS_STATE_DIA_NUMBER_LABELS = 8
} globus_state_dia_flags_t;

globus_result_t
globus_states_set_events(
    globus_state_handle_t               handle,
    int                                 state_count,
    int                                 event_count,
    char *                              reg_name,
    char **                             state_name,
    char **                             event_name);

globus_result_t
globus_states_init(
    globus_state_handle_t *             out_handle,
    globus_states_init_function_t       init_func);

globus_result_t
globus_state_add_transition_real(
    globus_state_handle_t               in_handle,
    int                                 state,
    int                                 event,
    int                                 new_state,
    globus_states_transition_function_t cb,
    char *                              edge_name,
    char *                              desc);


globus_result_t
globus_state_handle_event_now(
    globus_state_handle_t               in_handle,
    int                                 state,
    int                                 event,
    void *                              user_arg);

globus_result_t
globus_state_queue_event(
    globus_state_handle_t               in_handle,
    int                                 state,
    int                                 event,
    void *                              user_arg,
    globus_states_transition_error_function_t error_event);



globus_result_t
globus_state_destroy(
    globus_state_handle_t               in_handle);

globus_result_t
globus_state_make_graph(
    globus_state_handle_t               in_handle,
    const char *                        filename,
    const char *                        txt_filename,
    int                                 flags,
    char *                              user_desc);

#ifdef __cplusplus
}
#endif

#endif
