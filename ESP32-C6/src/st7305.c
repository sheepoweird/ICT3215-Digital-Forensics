#include "st7305.h"

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "font8x16.h"

static const char *TAG = "st7305";

#define LCD_HOST     SPI2_HOST
#define PIN_MOSI     14
#define PIN_SCLK     15
#define PIN_CS       8
#define PIN_DC       18
#define PIN_RST      9
#define LCD_SPI_HZ   (20 * 1000 * 1000)

/*
 * Panel RAM layout: 192 row pairs x 14 column units. Each column unit is
 * 3 bytes covering 12 pixels; each byte holds 4 columns x 2 rows, with
 * bit 7 = (col 0, even row), bit 6 = (col 0, odd row), ... bit 0 = (col 3, odd row).
 */
#define PANEL_COLS      168
#define PANEL_ROWS      384
#define COL_UNITS       14
#define ROW_PAIRS       192
#define BYTES_PER_ROW   (COL_UNITS * 3)
#define FB_SIZE         (ROW_PAIRS * BYTES_PER_ROW)   /* 8064 bytes */
#define CASET_START     0x17
#define CASET_END       (CASET_START + COL_UNITS - 1)

static spi_device_handle_t s_spi;
static uint8_t *s_fb;

static esp_err_t lcd_send(bool is_data, const uint8_t *buf, size_t len)
{
    if (len == 0) {
        return ESP_OK;
    }
    gpio_set_level(PIN_DC, is_data);
    spi_transaction_t t = {
        .length = len * 8,
        .tx_buffer = buf,
    };
    return spi_device_polling_transmit(s_spi, &t);
}

static esp_err_t lcd_cmd(uint8_t cmd, const uint8_t *data, size_t len)
{
    esp_err_t err = lcd_send(false, &cmd, 1);
    if (err == ESP_OK) {
        err = lcd_send(true, data, len);
    }
    return err;
}

#define CMD(c, ...) do { \
        static const uint8_t d_[] = { __VA_ARGS__ }; \
        ESP_ERROR_CHECK(lcd_cmd((c), d_, sizeof(d_))); \
    } while (0)
#define CMD0(c) ESP_ERROR_CHECK(lcd_cmd((c), NULL, 0))

/* Same sequence the stock firmware sends. */
static void lcd_init_sequence(void)
{
    CMD(0xD6, 0x13, 0x02);                  /* NVM load control */
    CMD(0xD1, 0x01);                        /* booster enable */
    CMD(0xC0, 0x12, 0x0A);                  /* gate voltage */
    CMD(0xC1, 0x73, 0x3E, 0x3C, 0x3C);      /* VSHP */
    CMD(0xC2, 0x00, 0x21, 0x23, 0x23);      /* VSLP */
    CMD(0xC4, 0x32, 0x5C, 0x5A, 0x5A);      /* VSHN */
    CMD(0xC5, 0x32, 0x35, 0x37, 0x37);      /* VSLN */
    CMD(0xD8, 0x80, 0xE9);                  /* OSC setting */
    CMD(0xB2, 0x12);                        /* frame rate */
    CMD(0xB3, 0xE5, 0xF6, 0x17, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x71); /* HPM EQ */
    CMD(0xB4, 0x05, 0x46, 0x77, 0x77, 0x77, 0x77, 0x76, 0x45);             /* LPM EQ */
    CMD(0x62, 0x32, 0x03, 0x1F);            /* gate timing */
    CMD(0xB7, 0x13);                        /* source EQ */
    CMD(0xB0, 0x60);                        /* gate line setting */
    CMD0(0x11);                             /* sleep out */
    vTaskDelay(pdMS_TO_TICKS(120));
    CMD(0xC9, 0x00);                        /* source voltage select */
    CMD(0x36, 0x4C);                        /* MADCTL */
    CMD(0x3A, 0x11);                        /* data format */
    CMD(0xB9, 0x20);                        /* gamma mode: mono */
    CMD(0xB8, 0x29);                        /* panel setting */
    CMD(0x2A, CASET_START, CASET_END);      /* column window */
    CMD(0x2B, 0x00, ROW_PAIRS - 1);         /* row window */
    CMD(0x35, 0x00);                        /* TE on */
    CMD(0xD0, 0xFF);                        /* auto power down */
    CMD0(0x38);                             /* high power mode */
    CMD0(0x29);                             /* display on */
    CMD0(0x20);                             /* inversion off */
    CMD(0xBB, 0x4F);                        /* enable clear RAM */
}

esp_err_t st7305_init(void)
{
    s_fb = heap_caps_calloc(1, FB_SIZE, MALLOC_CAP_DMA);
    if (!s_fb) {
        return ESP_ERR_NO_MEM;
    }

    gpio_config_t io = {
        .pin_bit_mask = (1ULL << PIN_DC) | (1ULL << PIN_RST),
        .mode = GPIO_MODE_OUTPUT,
    };
    ESP_ERROR_CHECK(gpio_config(&io));
    gpio_set_level(PIN_RST, 1);
    gpio_set_level(PIN_DC, 0);

    spi_bus_config_t bus = {
        .mosi_io_num = PIN_MOSI,
        .miso_io_num = -1,
        .sclk_io_num = PIN_SCLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = FB_SIZE + 64,
    };
    ESP_ERROR_CHECK(spi_bus_initialize(LCD_HOST, &bus, SPI_DMA_CH_AUTO));

    spi_device_interface_config_t dev = {
        .clock_speed_hz = LCD_SPI_HZ,
        .mode = 0,
        .spics_io_num = PIN_CS,
        .queue_size = 1,
    };
    ESP_ERROR_CHECK(spi_bus_add_device(LCD_HOST, &dev, &s_spi));

    gpio_set_level(PIN_RST, 0);
    vTaskDelay(pdMS_TO_TICKS(10));
    gpio_set_level(PIN_RST, 1);
    vTaskDelay(pdMS_TO_TICKS(120));

    lcd_init_sequence();
    ESP_LOGI(TAG, "panel initialised");

    st7305_clear();
    return st7305_flush();
}

void st7305_clear(void)
{
    memset(s_fb, 0, FB_SIZE);
}

void st7305_set_pixel(int x, int y, bool on)
{
    if (x < 0 || x >= LCD_WIDTH || y < 0 || y >= LCD_HEIGHT) {
        return;
    }
    /* Landscape UI: UI y runs along the panel's 168 columns, UI x along its 384 rows. */
    int col = y;
    int row = x;
    int k = col % 12;
    size_t idx = (size_t)(row / 2) * BYTES_PER_ROW + (col / 12) * 3 + k / 4;
    uint8_t bit = 0x80 >> ((k % 4) * 2 + (row & 1));
    if (on) {
        s_fb[idx] |= bit;
    } else {
        s_fb[idx] &= ~bit;
    }
}

void st7305_fill_rect(int x, int y, int w, int h, bool on)
{
    for (int j = y; j < y + h; j++) {
        for (int i = x; i < x + w; i++) {
            st7305_set_pixel(i, j, on);
        }
    }
}

int st7305_draw_text(int x, int y, const char *s, int scale, bool on)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c < FONT_FIRST || c > FONT_LAST) {
            c = '?';
        }
        const uint8_t *glyph = font8x16[c - FONT_FIRST];
        for (int gy = 0; gy < FONT_H; gy++) {
            for (int gx = 0; gx < FONT_W; gx++) {
                if (glyph[gy] & (0x80 >> gx)) {
                    st7305_fill_rect(x + gx * scale, y + gy * scale, scale, scale, on);
                }
            }
        }
        x += FONT_W * scale;
    }
    return x;
}

esp_err_t st7305_flush(void)
{
    static const uint8_t caset[] = { CASET_START, CASET_END };
    static const uint8_t raset[] = { 0x00, ROW_PAIRS - 1 };
    esp_err_t err = lcd_cmd(0x2A, caset, sizeof(caset));
    if (err == ESP_OK) {
        err = lcd_cmd(0x2B, raset, sizeof(raset));
    }
    if (err == ESP_OK) {
        err = lcd_cmd(0x2C, s_fb, FB_SIZE);
    }
    return err;
}
