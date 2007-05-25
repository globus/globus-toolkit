#include "globus_i_gfork.h"

static gfork_i_state_t **               gfork_l_state_tansitions;

static gfork_i_state_t **               gfork_l_child_state_tansitions;

static char *                           gfork_l_state_names[] =
{
    "GFORK_STATE_NONE",
    "GFORK_STATE_OPENING",
    "GFORK_STATE_OPEN",
    "GFORK_STATE_OPENING_AND_CLOSING",
    "GFORK_STATE_CLOSING",
    "GFORK_STATE_CLOSED",
    "GFORK_STATE_COUNT"
};

static char *                           gfork_l_event_names[] =
{
    "GFORK_EVENT_NONE",
    "GFORK_EVENT_ACCEPT_CB",
    "GFORK_EVENT_OPEN_RETURNS",
    "GFORK_EVENT_SIGCHILD",
    "GFORK_EVENT_CLOSE_RETURNS",
    "GFORK_EVENT_COUNT"
};


void
gfork_i_state_init()
{
    gfork_i_state_t **                  map;
    int                                 i;

    /* allocate all the pointes to each column */
    map = (gfork_i_state_t **)
        globus_calloc(GFORK_STATE_COUNT, sizeof(globus_bool_t *));
    for(i = 0; i < GFORK_STATE_COUNT; i++)
    {
        map[i] = (gfork_i_state_t *)
            globus_calloc(GFORK_EVENT_COUNT, sizeof(globus_bool_t));
    }

    map[GFORK_STATE_NONE][GFORK_EVENT_ACCEPT_CB] = GFORK_STATE_OPENING;

    map[GFORK_STATE_OPENING][GFORK_EVENT_OPEN_RETURNS] = GFORK_STATE_OPEN;
    map[GFORK_STATE_OPENING][GFORK_EVENT_SIGCHILD] =
        GFORK_STATE_OPENING_AND_CLOSING;

    map[GFORK_STATE_OPEN][GFORK_EVENT_SIGCHILD] = GFORK_STATE_CLOSING;

    map[GFORK_STATE_OPENING_AND_CLOSING][GFORK_EVENT_OPEN_RETURNS] =
        GFORK_STATE_CLOSING;

    map[GFORK_STATE_CLOSING][GFORK_EVENT_CLOSE_RETURNS] = GFORK_STATE_CLOSED;

    gfork_l_state_tansitions = map;
}

gfork_i_state_t
gfork_i_state_next(
    gfork_i_state_t                 current_state,
    gfork_i_events_t                event)
{
    gfork_i_state_t                 new_state;

    new_state = gfork_l_state_tansitions[current_state][event];
    GlobusGForkDebugState(
        gfork_l_state_names[current_state],
        gfork_l_state_names[new_state],
        gfork_l_event_names[event]);

    return new_state;
}

