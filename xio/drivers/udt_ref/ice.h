#ifndef __ICE_I__

#define __ICE_I__

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <nice/agent.h>

#define ICE_SUCCESS 0
#define ICE_FAILURE -1

struct CandidatePair {
    NiceCandidate *local;
    NiceCandidate *remote;
};


struct icedata {
    NiceAgent       *agent;
    GMainLoop       *gloop;
    GMainContext    *gcontext;
    GThread         *gloopthread;
    guint           stream_id;

    NiceAddress     *bind_addr;
    NiceAddress     *remote_addr;

    gboolean        selected_pair_done;
    gboolean        gather_done;
    gboolean        negotiate_done;
    GMutex          *state_mutex;
    GCond           *gather_cv;
    GCond           *negotiate_cv;
};


// userfrag(513) -- rfc5389 15.3
// + sep(1) -- colon
// + password(80) -- pjnath limit
// + max candidates *
// (
//     space(1)
//     + foundation(32) + sep(1) -- rfc5245 15.1
//     + prio(10) + sep(1) -- rfc5245 4.1.2, 15.1
//     + addr(45) + sep(1)
//     + port(5) + sep(1)
//     + type(5) -- rfc5245 15.1
// ) + null(1)
//
// (foundation):(prio):(addr):(port):(type)
#define LOCAL_DATA_SIZE (513 + 1 + 80 \
                         + NICE_AGENT_MAX_REMOTE_CANDIDATES * ( \
                             1 + 33 + 11 + INET6_ADDRSTRLEN + 6 + 7) \
                         + 1)
int ice_lib_init();
void ice_lib_shutdown();

// upas
int ice_init(struct icedata *icedata, const char *stun_host,
             unsigned int stun_port, int controlling);
int ice_get_local_data(struct icedata *ice_data, char *out, size_t outsize);

// uprt
int ice_negotiate(struct icedata *ice_data, int argc, char *rdata[]);
int ice_get_negotiated_addrs(struct icedata *ice_data,
                             struct sockaddr *laddr,
                             socklen_t *laddrlen,
                             struct sockaddr *raddr,
                             socklen_t *raddrlen);


// cleanup
void ice_destroy(struct icedata *ice_data);

char **ice_parse_args(char *line, int *argc);

#endif
