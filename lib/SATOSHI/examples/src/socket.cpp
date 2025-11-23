#include "hw_config.h"
#include <AsyncTCP.h>

btc_node_group *g_group;

const char *g_pdns_seeds[] = {"seed.bitcoin.sipa.be",
                              "dnsseed.bluematt.me",
                              "seed.bitcoinstats.com",
                              "seed.bitcoin.jonasschnelli.ch",
                              "seed.btc.petertodd.org"};

void socket_write(btc_node *node, char *str, int len)
{
  if (g_group->nodes->len && (node->state & NODE_CONNECTED) != NODE_CONNECTED)
  {
    DBGMSG("[-] warning btc_node_send_msg error");
    return;
  }
  AsyncClient *tcpClient = (AsyncClient *)node->asyncnet;

  if (!tcpClient)
    return;

  size_t total_left_tosent = len;
  char *start = str;
  size_t size;
  while (total_left_tosent > 0)
  {
    if (tcpClient->space() > total_left_tosent && tcpClient->canSend())
    {
      size = tcpClient->write(start, total_left_tosent);
      total_left_tosent -= size;
      start += size;
    }
    else if (tcpClient->canSend())
    {
      size = tcpClient->write(start, tcpClient->space());

      total_left_tosent -= size;
      start += size;
    }
  }
}

static void socket_error_callback(void *arg, AsyncClient *tcpClient, int8_t error)
{
  DBGMSG("[CALLBACK] SOCKET ERROR");

  btc_node *node = (btc_node *)arg;

  event_cb(BEV_EVENT_ERROR, arg);
}

static void socket_disconnect_callback(void *arg, AsyncClient *tcpClient)
{
  DBGMSG("[CALLBACK] SOCKET DISCONNECTED");

  btc_node *node = (btc_node *)arg;

  event_cb(BEV_EVENT_EOF, arg);
}

static void socket_timeout_callback(void *arg, AsyncClient *tcpClient, uint32_t time)
{
  DBGMSG("[CALLBACK] SOCKET TIMEOUT");
  btc_node *node = (btc_node *)arg;

  event_cb(BEV_EVENT_TIMEOUT, arg);
}

static void socket_connected_callback(void *arg, AsyncClient *tcpClient)
{
  DBGMSG("[CALLBACK] SOCKET_CONNECTED");
  btc_node *node = (btc_node *)arg;

  node->start_time = time(NULL);
  event_cb(BEV_EVENT_CONNECTED, arg);
}

static void socket_recv_callback(void *arg, AsyncClient *tcpClient, void *data, size_t len)
{
  btc_node *node = (btc_node *)arg;
  if (g_group->nodes->len && (node->state & NODE_CONNECTED) != NODE_CONNECTED)
    return;

  cstr_alloc_minsize(node->recvBuffer, node->recvBuffer->len + len);

  memcpy(node->recvBuffer->str + node->recvBuffer->len, data, len);
  node->recvBuffer->len += len;

  struct const_buffer buf = {node->recvBuffer->str, node->recvBuffer->len};
  btc_p2p_msg_hdr hdr;
  char *read_upto = NULL;

  for (;;)
  {
    // check if message is complete
    if (buf.len < BTC_P2P_HDRSZ)
      break;

    btc_p2p_deser_msghdr(&hdr, &buf);

    if (buf.len < hdr.data_len)
      break;

    if (hdr.data_len > BTC_MAX_P2P_MSG_SIZE)
    {
      // check for invalid message lengths
      DBGMSG("[+] detect btc_node_missbehave %d %s", hdr.data_len, hdr.command);
      btc_node_missbehave(node);
      return;
    }

    if (buf.len >= hdr.data_len)
    {
      // at least one message is complete
      struct const_buffer cmd_data_buf = {buf.p, buf.len};
      // DBGMSG("[+]command=%s", hdr.command);

      btc_node_parse_message(node, &hdr, &cmd_data_buf);

      // skip the size of the whole message
      buf.p = (const unsigned char *)buf.p + hdr.data_len;
      buf.len -= hdr.data_len;

      read_upto = (char *)buf.p;
    }
    if (buf.len == 0)
    {
      cstr_free(node->recvBuffer, true);

      node->recvBuffer = cstr_new_sz(BTC_P2P_MESSAGE_CHUNK_SIZE);

      break;
    }
  }

  if (read_upto != NULL && node->recvBuffer->len != 0 && read_upto != (node->recvBuffer->str + node->recvBuffer->len))
  {
    char *end = node->recvBuffer->str + node->recvBuffer->len;
    size_t available_chunk_data = end - read_upto;

    cstr_free(node->recvBuffer, true);
    node->recvBuffer = cstr_new_buf(read_upto, available_chunk_data);
  }
}

bool connect_to_node()
{
  g_group = btc_node_group_new(&btc_chainparams_main);
  static int g_dns_seed_domain_index = 0;

  if (g_group->nodes->len < 1)
    if (!btc_node_group_add_peers_by_seed(g_pdns_seeds[g_dns_seed_domain_index++], g_group))
      DBGMSG("[-]error zero nodes added [%d]", g_dns_seed_domain_index);

  DBGMSG("[+]dns seed domain=%s node count=%d", g_pdns_seeds[g_dns_seed_domain_index - 1], g_group->nodes->len);

  btc_node *node = (btc_node *)vector_idx(g_group->nodes, g_group->nodes->len - 1);

  if (node->asyncnet)
    delete (AsyncClient *)node->asyncnet;

  node->asyncnet = (void *)new AsyncClient();
  AsyncClient *tcpClient = (AsyncClient *)node->asyncnet;

  tcpClient->onData(&socket_recv_callback, node);
  tcpClient->onError(&socket_error_callback, node);
  tcpClient->onTimeout(&socket_timeout_callback, node);
  tcpClient->onDisconnect(&socket_disconnect_callback, node);
  tcpClient->onConnect(&socket_connected_callback, node);

  if (tcpClient->connect(ntohl(node->rip), node->rport))
    return true;

  return false;
}
