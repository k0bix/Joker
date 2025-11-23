#include "btc/net.h"

btc_bool btc_node_missbehave(btc_node *node)
{
    DBGMSG("[-]Mark node %d as missbehaved\n", node->nodeid);
    node->state |= NODE_MISSBEHAVED;
    btc_node_connection_state_changed(node);
    btc_node_disconnect(node);

    connect_to_node();
    return 1;
}

void btc_node_disconnect(btc_node *node)
{
    DBGMSG("[-]BTC node disconnect");
    node = get_active_peer();
    if (!node)
        return;
    node->time_started_con = 0;
    node->state &= ~NODE_CONNECTING;
    node->state &= ~NODE_CONNECTED;
    node->state |= NODE_DISCONNECTED;
}

void btc_node_free(void *obj)
{
    btc_node *node = (btc_node *)obj;
    DBGMSG("enter btc_node_free %d\n", node->nodeid);

    btc_node_disconnect(node);
    cstr_free(node->recvBuffer, true);
    btc_free(node);
}

void handle_inv_msg(struct btc_node_ *node, struct const_buffer *buf)
{
    int inv_msg_length = buf->len;
    void *inv_msg_ptr = (char *)buf->p;

    uint32_t vsize;

    if (!deser_varlen(&vsize, buf))
    {
        DBGMSG("[-]error handle_inv_msg");
        btc_node_missbehave(node);

        return;
    }

    btc_p2p_inv_msg inv_msg;

    for (unsigned int i = 0; i < vsize; i++)
    {
        if (!btc_p2p_msg_inv_deser(&inv_msg, buf))
        {
            btc_node_missbehave(node);
            return;
        }

        if (inv_msg.type == BTC_INV_TYPE_TX)
        {
            *(uint32_t *)((char *)buf->p - 36) = 0x40000001;
            G_bPutMsgQuene((uint8_t *)inv_msg_ptr, inv_msg_length, 0x000011);
            node->time_last_request = time(NULL);
            return;
        }
    }
}

bool handle_version(btc_node *node, btc_p2p_msg_hdr *hdr, struct const_buffer *buf)
{
    btc_p2p_version_msg v_msg_check;
    if (!btc_p2p_msg_version_deser(&v_msg_check, buf))
    {
        return false;
    }

    time_t t = (v_msg_check.timestamp);
    struct tm timeinfo;
    __secs_to_tm(t, &timeinfo);

    node->bestknownheight = v_msg_check.start_height;
    DBGMSG("[+]Connected to node %d: %s (%d) version=%d services=%lld time=%s\n",
           node->nodeid, v_msg_check.useragent, v_msg_check.start_height,
           v_msg_check.version, v_msg_check.services, asctime(&timeinfo));

    if (!(v_msg_check.services & BTC_NODE_NETWORK))
        return false;

    if (!(v_msg_check.services & BTC_NODE_WITNESS))
        return false;

    cstring *verack = btc_p2p_message_new(node->nodegroup->chainparams->netmagic, "verack", NULL, 0);
    btc_node_send_msg(node, verack);
    cstr_free(verack, true);

    return true;
}

void postcmd(struct btc_node_ *node, btc_p2p_msg_hdr *hdr, struct const_buffer *buf)
{
    if (strcmp(hdr->command, "inv") == 0)
    {
        handle_inv_msg(node, buf);
        return;
    }

    if (strcmp(hdr->command, "tx") == 0)
    {
        if (hdr->data_len > 520 && hdr->data_len < 100 * 1024)
            G_bPutMsgQuene((uint8_t *)buf->p, hdr->data_len, 0x000012);

        return;
    }

    DBGMSG("[+]CMD=%s", hdr->command);
    // hexdump(hdr->command, 12 ,8);

    if (strcmp(hdr->command, "version") == 0)
    {
        if (!handle_version(node, hdr, buf))
        {
            DBGMSG("[-]handle version failed!");
            btc_node_disconnect(node);

            return;
        }
    }

    if (strcmp(hdr->command, "verack") == 0)
    {
        DBGMSG("%s", "[+]complete handshake if verack has been received");
        node->version_handshake = true;

        if (node->nodegroup->handshake_done_cb)
            node->nodegroup->handshake_done_cb(node);

        return;
    }

    if (strcmp(hdr->command, "ping") == 0)
    {
        uint8_t nonce[8] = {0};

        if (!deser_bytes(nonce, buf, 8))
        {
            btc_node_missbehave(node);
            return;
        }

        DBGMSG("[+]FREE SPRAM=%d", get_free_psram_size());

        cstring *pongmsg = btc_p2p_message_new(node->nodegroup->chainparams->netmagic, "pong", nonce, 8);
        btc_node_send_msg(node, pongmsg);
        cstr_free(pongmsg, true);
        return;
    }

    if (strcmp(hdr->command, "pong") == 0)
    {
        node->lastpong = time(NULL);
        return;
    }
}

void handshake_done(struct btc_node_ *node)
{
    DBGMSG("[+]handshake_done.", node->bestknownheight);
    node->rip = htonl(node->rip);
    printTftText(2, "%s", inet_ntoa(node->rip));
}

btc_node_group *btc_node_group_new(const btc_chainparams *chainparams)
{
    btc_node_group *node_group;
    node_group = btc_calloc(1, sizeof(*node_group));

    node_group->nodes = vector_new(1, btc_node_free);
    node_group->chainparams = (chainparams ? chainparams : &btc_chainparams_main);
    node_group->parse_cmd_cb = NULL;
    strcpy(node_group->clientstr, "libbtc 0.1");

    node_group->postcmd_cb = postcmd;
    node_group->node_connection_state_changed_cb = NULL;
    node_group->should_connect_to_more_nodes_cb = NULL;
    node_group->handshake_done_cb = handshake_done;
    node_group->log_write_cb = (int (*)(const char *, ...))DBGMSG;

    return node_group;
}

void event_cb(short type, void *ctx)
{
    btc_node *node = (btc_node *)ctx;
    node->nodegroup->log_write_cb("Event callback on node %d\n", node->nodeid);

    if (((type & BEV_EVENT_TIMEOUT) != 0) && ((node->state & NODE_CONNECTING) == NODE_CONNECTING))
    {
        node->nodegroup->log_write_cb("Timout connecting to node %d.\n", node->nodeid);
        node->state = 0;
        node->state |= NODE_ERRORED;
        node->state |= NODE_TIMEOUT;
        btc_node_connection_state_changed(node);
    }
    else if (((type & BEV_EVENT_EOF) != 0) ||
             ((type & BEV_EVENT_ERROR) != 0))
    {
        node->state = 0;
        node->state |= NODE_ERRORED;
        node->state |= NODE_DISCONNECTED;
        if ((type & BEV_EVENT_EOF) != 0)
        {
            node->nodegroup->log_write_cb("Disconnected from the remote peer %d.\n", node->nodeid);
            node->state |= NODE_DISCONNECTED_FROM_REMOTE_PEER;
        }
        else
        {
            node->nodegroup->log_write_cb("Error connecting to node %d.\n", node->nodeid);
        }
        btc_node_connection_state_changed(node);
    }
    else if (type & BEV_EVENT_CONNECTED)
    {
        node->nodegroup->log_write_cb("Successfull connected to node %d.\n", node->nodeid);
        node->state |= NODE_CONNECTED;
        node->state &= ~NODE_CONNECTING;
        node->state &= ~NODE_ERRORED;
        btc_node_connection_state_changed(node);
        DBGMSG("[+]Successfull connected to node %d.\n", node->nodeid);
        /* if callback is set, fire */
    }
}

void btc_node_connection_state_changed(btc_node *node)
{
    DBGMSG("[-]btc_node_connection_state_changed");
    if (node->nodegroup->node_connection_state_changed_cb)
        node->nodegroup->node_connection_state_changed_cb(node);

    if ((node->state & NODE_ERRORED) == NODE_ERRORED)
    {
       connect_to_node();
    }
    if ((node->state & NODE_MISSBEHAVED) == NODE_MISSBEHAVED)
    {
        if ((node->state & NODE_CONNECTED) == NODE_CONNECTED || (node->state & NODE_CONNECTING) == NODE_CONNECTING)
        {
            btc_node_disconnect(node);
        }
    }
    else
        btc_node_send_msg_version(node);
}

btc_node *btc_node_new()
{
    btc_node *node;
    node = btc_calloc(1, sizeof(*node));
    node->version_handshake = false;
    node->nonce = 0;
    node->state = 0;
    node->services = 0; // 0x70016;
    node->lastping = time(NULL);
    node->lastpong = node->lastping;
    node->lastbtcprice = node->lastping;
    node->lastquehandle = 0;
    node->time_started_con = 0;
    node->time_last_request = 0;
    node->skip_recvBuffer = false;
    btc_hash_clear(node->last_requested_inv);
    node->recvBuffer = cstr_new_sz(BTC_P2P_MESSAGE_CHUNK_SIZE);

    node->hints = 0;
    return node;
}

void btc_node_send_msg(btc_node *node, cstring *data)
{
    if (g_group->nodes->len && (node->state & NODE_CONNECTED) != NODE_CONNECTED)
    {
        DBGMSG("[-]WARNING btc_node_send_msg error");
        return;
    }
    socket_write(node, (char *)data->str, data->len);
}

void btc_node_send_msg_version(btc_node *node)
{
    /* get new string buffer */
    cstring *version_msg_cstr = cstr_new_sz(256);

    /* copy socket_addr to p2p addr */
    btc_p2p_address fromAddr;
    btc_p2p_address_init(&fromAddr);
    btc_p2p_address toAddr;
    btc_p2p_address_init(&toAddr);
    btc_addr_to_p2paddr(&node->addr, &toAddr); //??

    /* create a version message struct */
    btc_p2p_version_msg version_msg;
    memset(&version_msg, 0, sizeof(version_msg));

    /* create a serialized version message */
    // btc_p2p_msg_version_init(&version_msg, &fromAddr, &toAddr, node->nodegroup->clientstr, true);
    btc_p2p_msg_version_init(&version_msg, &fromAddr, &toAddr, "SATBOX_v0.1", true /*RELAY_TX*/, 0);

    btc_p2p_msg_version_ser(&version_msg, version_msg_cstr);

    /* create p2p message */
    cstring *p2p_msg = btc_p2p_message_new(node->nodegroup->chainparams->netmagic, "version", version_msg_cstr->str, version_msg_cstr->len);

    /* send message */
    btc_node_send_msg(node, p2p_msg);

    /* cleanup */
    cstr_free(version_msg_cstr, true);
    cstr_free(p2p_msg, true);
}

int btc_node_parse_message(btc_node *node, btc_p2p_msg_hdr *hdr, struct const_buffer *buf)
{
    if (node->nodegroup->postcmd_cb)
        node->nodegroup->postcmd_cb(node, hdr, buf);

    return true;
}

btc_node *get_active_peer()
{
    if (g_group && g_group->nodes->len > 0)
    {
        for (int i = 0; i < g_group->nodes->len; i++)
        {
            btc_node *node = (btc_node *)vector_idx(g_group->nodes, i);
            if (g_group->nodes->len && (node->state & NODE_CONNECTED))
            {
                return node;
            }
        }
    }
    return NULL;
}

void handle_getmsg_quene(btc_node *node, int cycle)
{
    uint64_t now = time(NULL);

    if (node->lastquehandle + 1 < now)
    {
        node->lastquehandle = now;
        for (int z = 0; z < cycle; z++)
        {
            size_t size;
            uint8_t type;

            uint8_t *ptr = G_bGetMsgQuene(&size, &type);
            if (!ptr)
                return;

            if (type == 0x000011) // send request
            {
                cstring *p2p_msg = btc_p2p_message_new(node->nodegroup->chainparams->netmagic, "getdata", ptr, size);

                if ((g_group->nodes->len))
                {
                    btc_node_send_msg(node, p2p_msg);
                }

                cstr_free(p2p_msg, true);
            }

            if (type == 0x000012) // parse the nft
            {
                btc_tx *tx = btc_tx_new();

                G_bPrintMsgQuene();
                if (!btc_tx_deserialize(ptr, size, tx, NULL, true))
                    DBGMSG("[-]error:btc_tx_deserialize");

                btc_tx_free(tx);
            }

            RELEASE_PTR(ptr)

            break;
        }
    }
}

void node_periodical_timer(btc_node *node)
{
    if (g_group->nodes->len && ((node->state & NODE_CONNECTED) == NODE_CONNECTED))
    {
        uint64_t now = time(NULL);

        if (node->lastping + 180 < now)
        {
            uint64_t nonce;
            btc_cheap_random_bytes((uint8_t *)&nonce, sizeof(nonce));
            cstring *pingmsg = btc_p2p_message_new(node->nodegroup->chainparams->netmagic, "ping", &nonce, sizeof(nonce));
            btc_node_send_msg(node, pingmsg);
            cstr_free(pingmsg, true);
            node->lastping = now;
        }

        if (node->lastpong + 360 < now)
            btc_node_missbehave(node);

        
        if (node->lastbtcprice + 60 * 5 < now)
        {
            get_btc_price();
            node->lastbtcprice = now;
        }
    }
}