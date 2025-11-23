#include "hw_config.h"

#include <HTTPClient.h>
#include <WiFi.h>
#include "jsonlib.h"

const char *ssid = "k0bi";
const char *password = "12345678";

HTTPClient g_http;
String g_BTCUSDPrice;

#define NETWORK_INTERVAL 10000 * 1L * 6 * 100 // 10000 is 10 seconds
#define HEARTBEAT_INTERVAL 30000 * 1L         // 10000 is 10 seconds

uint16_t initWiFi()
{
  WiFi.begin(ssid, password);
  WiFi.setSleep(false);

  while (WiFi.status() != WL_CONNECTED)
  {
    delay(1000);
  }

  DBGMSG("[+]ESP32 signal=%d", WiFi.RSSI());
  printTftText(1, "%s,%d", ssid, WiFi.RSSI());

  return WiFi.localIP();
}

void check_connection_status()
{
  static ulong checkstatus_timeout = 0;

  if ((millis() > checkstatus_timeout) || (checkstatus_timeout == 0))
  {
    if (WiFi.status() != WL_CONNECTED)
      initWiFi();

    checkstatus_timeout = millis() + HEARTBEAT_INTERVAL;
  }
}

void DBGMSG(const char *format, ...)
{
  char debug[1024];
  sprintf(debug, "[%d]", xPortGetCoreID());
  va_list args;
  va_start(args, format);
  vsprintf(&debug[strlen(debug)], format, args);
  Serial.println(debug);

  va_end(args);
}

void hexdump(const void *mem, uint32_t len, uint8_t cols)
{
  Serial.printf("\n");
  const uint8_t *src = (const uint8_t *)mem;
  Serial.printf("\n[HEXDUMP] Address: 0x%08X len: 0x%X (%d)", (ptrdiff_t)src, len, len);
  for (uint32_t i = 0; i < len; i++)
  {
    if (i % cols == 0)
    {
      Serial.printf("\n[0x%08X] 0x%08X: ", (ptrdiff_t)src, i);
    }
    Serial.printf("%02X ", *src);
    src++;
  }
  Serial.printf("\n");
}

uint32_t get_free_psram_size()
{
  return ESP.getFreePsram();
}

bool get_btc_price()
{
    String url = "http://api.coindesk.com/v1/bpi/currentprice/BTC.json";
    
    g_http.begin(url);

    int httpCode = g_http.GET();
    String json = g_http.getString();
    
    String bpi = jsonExtract(json, "bpi");
    String USD = jsonExtract(bpi, "USD");
    String rate = jsonExtract(USD, "rate");


    g_http.end();

    char g_szbtc_price[100] = "";
    sprintf(g_szbtc_price, "$%s", rate.c_str());
    char *dot = strchr(g_szbtc_price, '.');
    if (dot)
        *dot = 0;

    printTftText(3, "BTCUSD:%s", g_szbtc_price);

    return true;
}