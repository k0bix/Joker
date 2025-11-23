#include "Arduino.h"
#include "btc/net.h"

void initTft();
uint16_t initWiFi();
void printTftText(uint8_t section, const char *format, ...);
void check_connection_status();
bool connect_to_node();
uint32_t get_free_psram_size();
bool get_btc_price();
