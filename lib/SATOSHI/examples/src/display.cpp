#include "hw_config.h"
#include "Arduino_GFX_Library.h"
#include "logo.h"
#include "pngle.h"
#include "esp32/rom/tjpgd.h"
#include "font.h"

Arduino_DataBus *bus = new Arduino_ESP32LCD8(7 /* DC */, 6 /* CS */, 8 /* WR */, 9 /* RD */, 39 /* D0 */, 40 /* D1 */, 41 /* D2 */, 42 /* D3 */,
                                             45 /* D4 */, 46 /* D5 */, 47 /* D6 */, 48 /* D7 */);

Arduino_GFX *gfx = new Arduino_ST7789(bus, 5 /* RST */, 0 /* rotation */, true /* IPS */, 170 /* width */, 320 /* height */, 35 /* col offset 1 */,
                                      0 /* row offset 1 */, 35 /* col offset 2 */, 0 /* row offset 2 */);

void initTft()
{
  pinMode(15, OUTPUT);
  digitalWrite(15, HIGH);

  ledcSetup(0, 2000, 8);
  ledcAttachPin(38, 0);
  ledcWrite(0, 255);

  gfx->begin();
  gfx->setRotation(1);
  gfx->fillScreen(BLACK);

  char chars[6] = "%&@G8";
  int length = strlen(image);

  for (int i = 0; i < length; i++)
    if (image[i] != ' ')
    {
      gfx->setTextColor(gfx->color565(200, 200, 0));
      gfx->print(chars[random(0, 4)]);
    }
    else
    {
      gfx->setTextColor(gfx->color565(90, 90, 90));
      gfx->print(chars[random(0, 9)]);
    }

  Serial.setDebugOutput(true);
  Serial.println();

  for (uint8_t t = 4; t > 0; t--)
  {
    DBGMSG("[+] SETUP BOOT WAIT %d.\n", t);
    Serial.flush();
    delay(600);
  }
}

void printTftText(uint8_t section, const char *format, ...)
{
  char buf[1024];
  va_list args;
  va_start(args, format);
  vsprintf(buf, format, args);

  gfx->setTextColor(0x264E);
  gfx->setFont(&Monospaced_bold_18);

  if (section == 1)
  {
    gfx->fillScreen(BLACK);
    gfx->draw16bitRGBBitmap(255, 85, (uint16_t *)logo, 59, 80);
  }

  gfx->setCursor(10, 30 * section);
  gfx->fillRect(10, 30 * section - 17, 200, 30, BLACK);
  gfx->println(buf);

  va_end(args);
}

void pngle_on_draw(pngle_t *pngle, uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint8_t rgba[4])
{
  // Convert to RGB 565 format
  uint16_t color = gfx->color565(rgba[0], rgba[1], rgba[2]);
  uint32_t png_width = pngle_get_width(pngle);
  uint32_t png_height = pngle_get_height(pngle);

  double scale = gfx->width() / png_width;

  if (rgba[3])
  {
    if (scale >= 1.0)
    {
      for (int i = 0; i < scale; i++)
        for (int j = 0; j < scale; j++)
          gfx->drawPixel(scale * x + i, scale * y + j, color);
    }
    else
    {
      int t = 1 / scale;
      gfx->drawPixel((int)(x / t), (int)(y / t), color);
    }
  }
}

void push_png_to_screen(const uint8_t *arrayData, uint32_t arraySize)
{
  pngle_t *pngle = pngle_new();
  pngle_set_draw_callback(pngle, pngle_on_draw);

  uint8_t buf[1024];

  uint32_t remain = 0;
  uint32_t arrayIndex = 0;
  uint32_t avail = arraySize;
  uint32_t take = 0;

  DBGMSG("[+]Start Randring PNG to Screen");
  gfx->fillScreen(BLACK);
  gfx->startWrite();
  while (avail > 0)
  {
    avail = arraySize - arrayIndex;
    take = sizeof(buf) - remain;
    if (take > avail)
      take = avail;
    memcpy_P(buf + remain, (const uint8_t *)(arrayData + arrayIndex), take);
    arrayIndex += take;
    remain += take;
    int fed = pngle_feed(pngle, buf, remain);
    if (fed < 0)
    {
      Serial.printf("ERROR: %s\n", pngle_error(pngle));
      break;
    }
    remain = remain - fed;
    if (remain > 0)
      memmove(buf, buf + fed, remain);
  }

  gfx->endWrite();
  pngle_destroy(pngle);
}

static uint32_t jpeg_buf_pos;
static uint8_t tjpgd_work[3096];
static uint32_t time_decomp = 0;

static uint32_t
feed_buffer(JDEC *jd, uint8_t *buff, uint32_t nd)
{
  uint8_t *device = (uint8_t *)jd->device;
  uint32_t count = 0;
  while (count < nd)
  {
    if (buff != NULL)
      *buff++ = device[jpeg_buf_pos];

    count++;
    jpeg_buf_pos++;
  }

  return count;
}

static uint32_t
tjd_output(JDEC *jd, void *bitmap, JRECT *rect)
{
  BYTE *src = (BYTE *)bitmap;
  // Serial.printf("%d, %d, %d, %d\n", rect->top, rect->left, rect->bottom, rect->right);
  for (int y = rect->top; y <= rect->bottom; y++)
  {
    for (int x = rect->left; x <= rect->right; x++)
    {
      gfx->drawPixel(x, y, gfx->color565(*(src++), *(src++), *(src++)));
    }
  }
  return 1;
}

int push_jpg_to_screen(uint8_t *arrayData)
{
  JDEC jd;
  JRESULT rc;

  jpeg_buf_pos = 0;

  DBGMSG("[+]Start Randring JPG to Screen");
  gfx->fillScreen(BLACK);

  rc = jd_prepare(&jd, feed_buffer, tjpgd_work, sizeof(tjpgd_work), arrayData);
  if (rc != JDR_OK)
  {
    Serial.println("JPG jd_prepare error");
    return ESP_FAIL;
  }

  uint32_t decode_start = esp_timer_get_time();

  rc = jd_decomp(&jd, tjd_output, 0);
  if (rc != JDR_OK)
  {
    Serial.println("JPG jd_decomp error");
    return ESP_FAIL;
  }

  return 1;
}