#include "hw_config.h"

uint32_t g_free_psram_size;

void setup()
{
  Serial.begin(115200);

  initTft();

  DBGMSG("%s", IPAddress(initWiFi()).toString());
  G_QUEMSG_Init();

  connect_to_node();
}

void loop()
{
  check_connection_status();

  g_free_psram_size = ESP.getFreePsram();

  btc_node *node = get_active_peer();
  
  if (!node)
    return;

  node_periodical_timer(node);

  handle_getmsg_quene(node, 1);
}

