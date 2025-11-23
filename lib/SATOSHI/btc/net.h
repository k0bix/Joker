#ifndef __LIBBTC_NET_H__
#define __LIBBTC_NET_H__

#include "btc/protocol.h"
#include "btc/block.h"
#include "btc/tx.h"
#include "btc/clist.h"
#include "btc/serialize.h"

LIBBTC_BEGIN_DECL

#ifndef RELEASE_PTR
#define RELEASE_PTR(x) \
    if (x != NULL)     \
    {                  \
        free(x);       \
        x = NULL;      \
    }
#endif


#define BTC_P2P_MESSAGE_CHUNK_SIZE 4096

#define BEV_EVENT_TIMEOUT 1
#define BEV_EVENT_EOF 2
#define BEV_EVENT_ERROR 4
#define BEV_EVENT_CONNECTED 8

// #pragma pack(pop)

enum NODE_STATE
{
    NODE_CONNECTING = (1 << 0),
    NODE_CONNECTED = (1 << 1),
    NODE_ERRORED = (1 << 2),
    NODE_TIMEOUT = (1 << 3),
    NODE_HEADERSYNC = (1 << 4),
    NODE_BLOCKSYNC = (1 << 5),
    NODE_MISSBEHAVED = (1 << 6),
    NODE_DISCONNECTED = (1 << 7),
    NODE_DISCONNECTED_FROM_REMOTE_PEER = (1 << 8),
};

/* basic group-of-nodes structure */
struct btc_node_;
typedef struct btc_node_group_
{
    void *ctx; /* flexible context usefull in conjunction with the callbacks */
    void *event_base;
    vector *nodes; /* the groups nodes */
    char clientstr[1024];

    const btc_chainparams *chainparams;

    /* callbacks */
    int (*log_write_cb)(const char *format, ...); /* log callback, default=printf */
    btc_bool (*parse_cmd_cb)(struct btc_node_ *node, btc_p2p_msg_hdr *hdr, struct const_buffer *buf);
    void (*postcmd_cb)(struct btc_node_ *node, btc_p2p_msg_hdr *hdr, struct const_buffer *buf);
    void (*node_connection_state_changed_cb)(struct btc_node_ *node);
    btc_bool (*should_connect_to_more_nodes_cb)(struct btc_node_ *node);
    void (*handshake_done_cb)(struct btc_node_ *node);
    btc_bool (*periodic_timer_cb)(struct btc_node_ *node, uint64_t *time); // return false will cancle the internal logic
} btc_node_group;


extern uint8_t g_minting_btc_transcation_hash[SHA256_DIGEST_LENGTH];
extern bool g_fminting_btc_transcation_sent;


/* basic node structure */
typedef struct btc_node_
{
    struct sockaddr addr;
    // struct bufferevent* asyncnet;
    void *asyncnet;
    uint32_t rip;
    unsigned short rport;

    struct event *timer_event;
    btc_node_group *nodegroup;
    int nodeid;
    uint64_t lastping;
    uint64_t lastpong;
    uint64_t lastbtcprice;
    uint64_t lastquehandle;
    uint64_t time_started_con;
    uint64_t time_last_request;
    uint256 last_requested_inv;

    cstring *recvBuffer;
    bool skip_recvBuffer;
    uint64_t nonce;
    uint64_t services;
    uint32_t state;
    int missbehavescore;
    btc_bool version_handshake;

    unsigned int bestknownheight;

    uint32_t hints; /* can be use for user defined state */
    uint32_t start_time;
    bool is_nodesync;

} btc_node;

extern uint8_t *nft_image;

extern btc_node_group *g_group;

/* create new node object */
LIBBTC_API btc_node *btc_node_new();

/* disconnect a node */
LIBBTC_API void btc_node_disconnect(btc_node *node);

/* mark a node missbehave and disconnect */
LIBBTC_API btc_bool btc_node_missbehave(btc_node *node);

/* create a new node group */
LIBBTC_API btc_node_group *btc_node_group_new(const btc_chainparams *chainparams);

/* sends version command to node */
LIBBTC_API void btc_node_send_msg_version(btc_node *node);

/* send arbitrary data to node */
LIBBTC_API void btc_node_send_msg(btc_node *node, cstring *data);

LIBBTC_API int btc_node_parse_message(btc_node *node, btc_p2p_msg_hdr *hdr, struct const_buffer *buf);
LIBBTC_API void btc_node_connection_state_changed(btc_node *node);

LIBBTC_API btc_bool btc_node_group_add_peers_by_seed(const char *, btc_node_group *);
LIBBTC_API int btc_get_active_peers_from_dns(const char *, vector *, int port, int);
LIBBTC_API void DBGMSG(const char *, ...);

LIBBTC_API void event_cb(short, void *);

LIBBTC_API btc_node *get_active_peer();
LIBBTC_API void socket_write(btc_node *node, char *str, int len);
LIBBTC_API uint32_t get_free_psram_size();

LIBBTC_API void node_periodical_timer(btc_node *node);
LIBBTC_API void handle_getmsg_quene(btc_node *, int);

LIBBTC_API void hexdump(const void *mem, uint32_t len, uint8_t cols);

LIBBTC_API void G_bPrintMsgQuene();
LIBBTC_API void G_QUEMSG_Init();
LIBBTC_API bool G_bPutMsgQuene(uint8_t *pData, size_t dwMsgSize, uint8_t type);
LIBBTC_API uint8_t *G_bGetMsgQuene(size_t *pMsgSize, uint8_t *type);
LIBBTC_API bool connect_to_node();
LIBBTC_API bool get_btc_price();
LIBBTC_API void printTftText(uint8_t section, const char *format, ...);

LIBBTC_END_DECL

#endif // __LIBBTC_NET_H__
